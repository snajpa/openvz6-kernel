/*
 *  linux/kernel/bc/beancounter.c
 *
 *  Copyright (C) 1998  Alan Cox
 *                1998-2000  Andrey V. Savochkin <saw@saw.sw.com.sg>
 *  Copyright (C) 2000-2005 SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 * TODO:
 *   - more intelligent limit check in mremap(): currently the new size is
 *     charged and _then_ old size is uncharged
 *     (almost done: !move_vma case is completely done,
 *      move_vma in its current implementation requires too many conditions to
 *      do things right, because it may be not only expansion, but shrinking
 *      also, plus do_munmap will require an additional parameter...)
 *   - problem: bad pmd page handling
 *   - consider /proc redesign
 *   - TCP/UDP ports
 *   + consider whether __charge_beancounter_locked should be inline
 *
 * Changes:
 *   1999/08/17  Marcelo Tosatti <marcelo@conectiva.com.br>
 *	- Set "barrier" and "limit" parts of limits atomically.
 *   1999/10/06  Marcelo Tosatti <marcelo@conectiva.com.br>
 *	- setublimit system call.
 */

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/mmgang.h>
#include <linux/swap.h>
#include <linux/sched.h>
#include <linux/random.h>
#include <linux/cgroup.h>
#include <linux/pid_namespace.h>

#include <bc/beancounter.h>
#include <bc/io_acct.h>
#include <bc/vmpages.h>
#include <bc/dcache.h>
#include <bc/proc.h>

static struct kmem_cache *ub_cachep;

struct user_beancounter ub0 = {
#ifdef CONFIG_BC_RSS_ACCOUNTING
	.gang_set.gangs = init_gang_array,
#endif
};
EXPORT_SYMBOL(ub0);

static struct workqueue_struct *ub_clean_wq;

const char *ub_rnames[] = {
	"kmemsize",	/* 0 */
	"lockedpages",
	"privvmpages",
	"shmpages",
	"dummy",
	"numproc",	/* 5 */
	"physpages",
	"vmguarpages",
	"oomguarpages",
	"numtcpsock",
	"numflock",	/* 10 */
	"numpty",
	"numsiginfo",
	"tcpsndbuf",
	"tcprcvbuf",
	"othersockbuf",	/* 15 */
	"dgramrcvbuf",
	"numothersock",
	"dcachesize",
	"numfile",
	"dummy",	/* 20 */
	"dummy",
	"dummy",
	"numiptent",
	"swappages",
};

unsigned int ub_dcache_thres_ratio __read_mostly = 2; /* percent */
unsigned int ub_dcache_lru_popup __read_mostly = 1;
unsigned int ub_dcache_time_thresh __read_mostly = 5;
unsigned int ub_dcache_no_vzfs_cache __read_mostly = 0;
EXPORT_SYMBOL(ub_dcache_no_vzfs_cache);

static int ubc_ioprio = 1;

static int ubc_pagecache_isolation = 0;

/* default maximum perpcu resources precharge */
int ub_resource_precharge[UB_RESOURCES] = {
	[UB_KMEMSIZE]	= 32 * PAGE_SIZE,
       [UB_PRIVVMPAGES]= 256,
	[UB_NUMPROC]	= 4,
	[UB_PHYSPAGES]	= 512,	/* up to 2Mb, 1 huge page */
	[UB_NUMSIGINFO]	= 4,
	[UB_DCACHESIZE] = 4 * PAGE_SIZE,
	[UB_NUMFILE]	= 8,
	[UB_SWAPPAGES]	= 256,
	[UB_SHADOWPAGES] = 256,
};

/* natural limits for percpu precharge bounds */
static int resource_precharge_min = 0;
static int resource_precharge_max = INT_MAX / NR_CPUS;

void init_beancounter_precharge(struct user_beancounter *ub, int resource)
{
	if (!atomic_read(&ub->ub_refcount))
		return;

	/* limit maximum precharge with one half of current resource excess */
	ub->ub_parms[resource].max_precharge = min_t(long,
			ub_resource_precharge[resource],
			ub_resource_excess(ub, resource, UB_SOFT) /
			(2 * num_possible_cpus()));
}

static void init_beancounter_precharges(struct user_beancounter *ub)
{
	int resource;

	for ( resource = 0 ; resource < UB_RESOURCES ; resource++ )
		init_beancounter_precharge(ub, resource);
}

static void __init init_beancounter_precharges_early(struct user_beancounter *ub)
{
	int resource;

	for ( resource = 0 ; resource < UB_RESOURCES ; resource++ ) {

		/* DEBUG: sanity checks for initial prechage bounds */
		BUG_ON(ub_resource_precharge[resource] < resource_precharge_min);
		BUG_ON(ub_resource_precharge[resource] > resource_precharge_max);

		ub->ub_parms[resource].max_precharge =
			ub_resource_precharge[resource];
	}
}

void ub_precharge_snapshot(struct user_beancounter *ub, int *precharge)
{
	int cpu, resource;

	memset(precharge, 0, sizeof(int) * UB_RESOURCES);
	for_each_possible_cpu(cpu) {
		struct ub_percpu_struct *pcpu = ub_percpu(ub, cpu);
		for ( resource = 0 ; resource < UB_RESOURCES ; resource++ )
			precharge[resource] += pcpu->precharge[resource];
	}
	precharge[UB_PHYSPAGES] += precharge[UB_KMEMSIZE] >> PAGE_SHIFT;
	precharge[UB_OOMGUARPAGES] = precharge[UB_SWAPPAGES];
}

static void forbid_beancounter_precharge(struct user_beancounter *ub, int val)
{
	int resource;

	for ( resource = 0 ; resource < UB_RESOURCES ; resource++ )
		ub->ub_parms[resource].max_precharge = val;
}

static void init_beancounter_struct(struct user_beancounter *ub);
static void init_beancounter_nolimits(struct user_beancounter *ub);

#define UB_HASH_SIZE 256
#define ub_hash_fun(x) ((((x) >> 8) ^ (x)) & (UB_HASH_SIZE - 1))
static struct hlist_head ub_hash[UB_HASH_SIZE];
static DEFINE_SPINLOCK(ub_hash_lock);
LIST_HEAD(ub_top_list); /* protected by ub_hash_lock */
EXPORT_SYMBOL(ub_top_list);
LIST_HEAD(ub_leaked_list);

static struct cgroup *ub_cgroup_root;

int ub_attach(struct user_beancounter *ub)
{
	struct user_beancounter *old_ub;
	int err;

	if (ub->ub_cgroup) {
		err = cgroup_kernel_attach(ub->ub_cgroup, current);
		if (err)
			return err;
	}

	err = ub_mem_cgroup_attach(ub);
	if (err) {
		if (ub->ub_cgroup)
			cgroup_kernel_attach(get_exec_ub()->ub_cgroup, current);
		return err;
	}

	old_ub = set_exec_ub(ub);

	get_beancounter_longterm(ub);
	put_beancounter_longterm(old_ub);

	return 0;
}

int ub_attach_task(struct user_beancounter *ub, struct task_struct *tsk)
{
	if (tsk != current)
		 return -EINVAL;

	return ub_attach(ub);
}
EXPORT_SYMBOL(ub_attach_task);

/*
 *	Per user resource beancounting. Resources are tied to their luid.
 *	The resource structure itself is tagged both to the process and
 *	the charging resources (a socket doesn't want to have to search for
 *	things at irq time for example). Reference counters keep things in
 *	hand.
 *
 *	The case where a user creates resource, kills all his processes and
 *	then starts new ones is correctly handled this way. The refcounters
 *	will mean the old entry is still around with resource tied to it.
 */

static int ub_cgroup_init(struct user_beancounter *ub)
{
	char name[16];
	struct cgroup *cg;

	if (!ubc_ioprio)
		return 0;

	snprintf(name, sizeof(name), "%u", ub->ub_uid);
	cg = cgroup_kernel_open(ub_cgroup_root, CGRP_CREAT|CGRP_WEAK, name);
	if (IS_ERR(cg))
		return PTR_ERR(cg);

	ub->ub_cgroup = cg;
	ub_init_ioprio(ub);
	return 0;
}

static void ub_cgroup_destroy(struct user_beancounter *ub)
{
	if (ub->ub_cgroup) {
		ub_fini_ioprio(ub);
		cgroup_kernel_close(ub->ub_cgroup);
	}
}

static struct user_beancounter *alloc_ub(uid_t uid)
{
	struct user_beancounter *new_ub;

	ub_debug(UBD_ALLOC, "Creating ub %p\n", new_ub);

	new_ub = kmem_cache_zalloc(ub_cachep, GFP_KERNEL);
	if (new_ub == NULL)
		return NULL;

	init_beancounter_nolimits(new_ub);
	init_beancounter_struct(new_ub);

	init_beancounter_precharges(new_ub);

	if (ubc_pagecache_isolation)
		set_bit(UB_PAGECACHE_ISOLATION, &new_ub->ub_flags);

	if (alloc_mem_gangs(get_ub_gs(new_ub)))
		goto fail_gangs;

	if (percpu_counter_init(&new_ub->ub_orphan_count, 0))
		goto fail_pcpu;

	new_ub->ub_percpu = alloc_percpu(struct ub_percpu_struct);
	if (new_ub->ub_percpu == NULL)
		goto fail_free;

	new_ub->ub_uid = uid;
	return new_ub;

fail_free:
	percpu_counter_destroy(&new_ub->ub_orphan_count);
fail_pcpu:
	free_mem_gangs(get_ub_gs(new_ub));
fail_gangs:
	kmem_cache_free(ub_cachep, new_ub);
	return NULL;
}

static inline void __free_ub(struct user_beancounter *ub)
{
	free_percpu(ub->ub_percpu);
	kfree(ub->ub_store);
	free_mem_gangs(get_ub_gs(ub));
	kfree(ub->private_data2);
	kmem_cache_free(ub_cachep, ub);
}

static inline void free_ub(struct user_beancounter *ub)
{
	percpu_counter_destroy(&ub->ub_orphan_count);
	__free_ub(ub);
}

int ub_count;

struct user_beancounter *get_beancounter_byuid(uid_t uid, int create)
{
	struct user_beancounter *new_ub, *ub;
	unsigned long flags;
	struct hlist_head *hash;
	struct hlist_node *ptr;

	hash = &ub_hash[ub_hash_fun(uid)];

	rcu_read_lock();
	hlist_for_each_entry_rcu(ub, ptr, hash, ub_hash) {
		if (ub->ub_uid != uid)
			continue;

		if (get_beancounter_rcu(ub)) {
			rcu_read_unlock();
			return ub;
		}

		spin_lock_irqsave(&ub_hash_lock, flags);
		if (!hlist_unhashed(&ub->ub_hash)) {
			get_beancounter(ub);
			spin_unlock_irqrestore(&ub_hash_lock, flags);
			rcu_read_unlock();
			cancel_work_sync(&ub->work);
			return ub;
		}
		spin_unlock_irqrestore(&ub_hash_lock, flags);
	}
	rcu_read_unlock();

	if (!create)
		return NULL;

	new_ub = alloc_ub(uid);
	if (new_ub == NULL)
		return NULL;

	if (ub_cgroup_init(new_ub)) {
		free_ub(new_ub);
		return NULL;
	}

	spin_lock_irqsave(&ub_hash_lock, flags);

	hlist_for_each_entry(ub, ptr, hash, ub_hash) {
		if (ub->ub_uid != uid)
			continue;

		get_beancounter(ub);
		spin_unlock_irqrestore(&ub_hash_lock, flags);
		ub_cgroup_destroy(new_ub);
		free_ub(new_ub);
		cancel_work_sync(&ub->work);
		return ub;
	}

	ub_count++;
	list_add_rcu(&new_ub->ub_list, &ub_top_list);
	hlist_add_head_rcu(&new_ub->ub_hash, hash);
	add_mem_gangs(get_ub_gs(new_ub));
	spin_unlock_irqrestore(&ub_hash_lock, flags);

	ub_update_threshold();
	set_gang_limits(get_ub_gs(new_ub),
			&new_ub->ub_parms[UB_PHYSPAGES].limit,
			&node_states[N_HIGH_MEMORY]);

	return new_ub;
}
EXPORT_SYMBOL(get_beancounter_byuid);

struct user_beancounter *get_sub_beancounter(struct user_beancounter *parent)
{
	struct user_beancounter *ub;

	ub = alloc_ub(0);
	if (!ub)
		return NULL;

	ub->parent = get_beancounter_longterm(parent);
	ub->top = parent->top;

	spin_lock_irq(&ub_hash_lock);
	list_add_rcu(&ub->ub_list, &parent->children);
	add_mem_gangs(get_ub_gs(ub));
	spin_unlock_irq(&ub_hash_lock);

	return ub;
}

bool ub_is_descendant(struct user_beancounter *ub,
		      struct user_beancounter *root)
{
	if (!root)
		return true;
	while (ub) {
		if (ub == root)
			return true;
		ub = ub->parent;
	}
	return false;
}

struct user_beancounter *beancounter_iter(struct user_beancounter *root,
					  struct user_beancounter *prev)
{
	struct user_beancounter *cur, *tmp;
	struct list_head *list;

	cur = prev;
	if (!cur && root)
		return root;

	rcu_read_lock();

	list = cur ? &cur->children : &ub_top_list;
	list_for_each_entry_rcu(tmp, list, ub_list) {
		if (get_beancounter_rcu(tmp)) {
			cur = tmp;
			goto out;
		}
	}

	while (cur != root) {
		tmp = cur;
		list = cur->parent ? &cur->parent->children : &ub_top_list;
		list_for_each_entry_continue_rcu(tmp, list, ub_list) {
			if (get_beancounter_rcu(tmp)) {
				cur = tmp;
				goto out;
			}
		}
		cur = cur->parent;
	}
	cur = NULL;
out:
	rcu_read_unlock();

	if (prev != root)
		put_beancounter(prev);

	return cur;
}

void beancounter_iter_break(struct user_beancounter *root,
			    struct user_beancounter *prev)
{
	if (prev != root)
		put_beancounter(prev);
}

#ifdef CONFIG_BC_KEEP_UNUSED

void release_beancounter(struct user_beancounter *ub)
{
}

#else

static int verify_res(struct user_beancounter *ub, const char *name,
		unsigned long held)
{
	if (likely(held == 0))
		return 1;

	printk(KERN_WARNING "Ub %u helds %ld in %s on put\n",
			ub->ub_uid, held, name);
	return 0;
}

static inline int bc_verify_held(struct user_beancounter *ub)
{
	int i, clean;

	ub_update_resources_locked(ub);

	clean = 1;
	for (i = 0; i < UB_RESOURCES; i++)
		clean &= verify_res(ub, ub_rnames[i],
				__get_beancounter_usage_percpu(ub, i));

	clean &= verify_res(ub, "dirty_pages",
			__ub_stat_get_exact(ub, dirty_pages));
	clean &= verify_res(ub, "writeback_pages",
			__ub_stat_get_exact(ub, writeback_pages));
	clean &= verify_res(ub, "shadow_pages",
			__get_beancounter_usage_percpu(ub, UB_SHADOWPAGES));
	clean &= verify_res(ub, "swap_entries", ub->ub_swapentries);
	clean &= verify_res(ub, "hugetlb_pages", ub->ub_hugetlb_pages);
	clean &= verify_res(ub, "tmpfs_respages", ub->ub_tmpfs_respages);

	clean &= verify_res(ub, "refcount", atomic_read(&ub->ub_refcount));

	clean &= verify_res(ub, "pincount", __ub_percpu_sum(ub, pincount));

	clean &= verify_res(ub, "dcache", !list_empty(&ub->ub_dentry_lru));

	clean &= verify_res(ub, "underflow",
			test_bit(UB_UNDERFLOW, &ub->ub_flags));

	ub_debug_trace(!clean, 5, 60*HZ);

	return clean;
}

static void bc_free_rcu(struct rcu_head *rcu)
{
	struct user_beancounter *ub;

	ub = container_of(rcu, struct user_beancounter, rcu);
	__free_ub(ub);
}

static void leak_beancounter(struct user_beancounter *ub)
{
	atomic_add(INT_MIN/2, &ub->ub_refcount);

	spin_lock_irq(&ub_hash_lock);
	list_add_tail_rcu(&ub->ub_leaked_list, &ub_leaked_list);
	spin_unlock_irq(&ub_hash_lock);

	printk(KERN_ERR "UB: leaked beancounter %u (%p)\n",
			ub->ub_uid, ub);
	add_taint(TAINT_CRAP);
}

static void ub_synchronize_sched(struct rcu_head *rcu);
static void delayed_cleanup_beancounter(struct work_struct *w);

static void delayed_release_beancounter(struct work_struct *w)
{
	struct user_beancounter *ub;
	unsigned long zero_limit = 0;
	unsigned long flags;
	int refcount;

	ub = container_of(w, struct user_beancounter, work);

	spin_lock_irqsave(&ub_hash_lock, flags);

	refcount = atomic_read(&ub->ub_refcount);
	if (refcount > 0)
		/* raced with get_beancounter_byuid */
		goto out;

	if (WARN_ON((ub == get_ub0()))) {
		printk(KERN_ERR "UB: Trying to put ub0\n");
		goto out;
	}

	if (WARN_ON(!list_empty(&ub->children)))
		goto out;

	/* sub-beancounters are never hashed */
	if (!ub->parent) {
		if (hlist_unhashed(&ub->ub_hash)) {
			printk(KERN_ERR "UB: Trying to put unhashed ub %u (%p)\n",
					ub->ub_uid, ub);
			goto out;
		}
		hlist_del_init_rcu(&ub->ub_hash);
		ub_count--;
	}
	list_del_rcu(&ub->ub_list);
	spin_unlock_irqrestore(&ub_hash_lock, flags);

	if (WARN_ON(refcount < 0))
		printk(KERN_ERR "UB: Bad refcount (%d) on put of %u (%p)\n",
				refcount, ub->ub_uid, ub);

	/* dcache is not accounted to sub-beancounters, so there is no need to
	 * update dcache thresholds */
	if (!ub->parent)
		ub_update_threshold();

	/* reset commitment */
	set_gang_limits(get_ub_gs(ub), &zero_limit, NULL);

	ub_dcache_unuse(ub);

	if (!verify_res(ub, ub_rnames[UB_KMEMSIZE],
		       __get_beancounter_usage_percpu(ub, UB_KMEMSIZE)) ||
	    refcount)
		return leak_beancounter(ub);

	forbid_beancounter_precharge(ub, 0);
	/* synchronize with __try_charge_beancounter_percpu() */
	call_rcu_sched(&ub->rcu, ub_synchronize_sched);
	return;

out:
	spin_unlock_irqrestore(&ub_hash_lock, flags);
}

static void ub_synchronize_sched(struct rcu_head *rcu)
{
	struct user_beancounter *ub = container_of(rcu,
			struct user_beancounter, rcu);

	INIT_DELAYED_WORK(&ub->dwork, delayed_cleanup_beancounter);
	queue_delayed_work(ub_clean_wq, &ub->dwork, 0);
}

static void delayed_cleanup_beancounter(struct work_struct *w)
{
	struct user_beancounter *ub;
	long pages;

	ub = container_of(w, struct user_beancounter, dwork.work);

	junk_mem_gangs(get_ub_gs(ub));

	pages = __get_beancounter_usage_percpu(ub, UB_SHADOWPAGES);
	pages += __get_beancounter_usage_percpu(ub, UB_PHYSPAGES);

	/*
	 * Here we wait for all isolated pages. No new charges at this point
	 * so per-cpu summing abowe is safe. Memory reclaimer cannot peel
	 * pages from semi-dead beancounters, thus we shouldn't block here
	 * because ubcleand is single-threaded. This function queues cleanup
	 * again and again until all pages are moved to the junkyard.
	 */
	if (pages) {
		queue_delayed_work(ub_clean_wq, &ub->dwork, 1);
		return;
	}

	ub_unuse_swap(ub);

	if (!bc_verify_held(ub))
		return leak_beancounter(ub);

	/* DEBUG: to trigger BUG_ON in precharge/charge/uncharge */
	forbid_beancounter_precharge(ub, -1);
	del_mem_gangs(get_ub_gs(ub));
	ub_free_counters(ub);
	percpu_counter_destroy(&ub->ub_orphan_count);
	ub_cgroup_destroy(ub);

	call_rcu(&ub->rcu, bc_free_rcu);
}

static void __release_beancounter(struct user_beancounter *ub)
{
	unsigned long flags;

	spin_lock_irqsave(&ub_hash_lock, flags);
	if (!atomic_read(&ub->ub_refcount))
		queue_work(ub_clean_wq, &ub->work);
	spin_unlock_irqrestore(&ub_hash_lock, flags);
}

void release_beancounter(struct user_beancounter *ub)
{
	/*
	 * Release the beancounter and drop the reference to its parent
	 * (grandparent if parent dies, and so on). It's safe to release the
	 * parent's reference here, because ub_clean_wq is single-threaded,
	 * which guarantees the parent won't pass away before child.
	 */
	do {
		__release_beancounter(ub);
		ub = ub->parent;
	} while (ub && atomic_dec_and_test(&ub->ub_refcount));
}

#endif /* CONFIG_BC_KEEP_UNUSED */

EXPORT_SYMBOL(release_beancounter);

/*
 *	Generic resource charging stuff
 */

int __charge_beancounter_locked(struct user_beancounter *ub,
		int resource, unsigned long val, enum ub_severity strict)
{
	ub_debug_resource(resource, "Charging %lu for %d of %p with %lu\n",
			val, resource, ub, ub->ub_parms[resource].held);
	/*
	 * ub_value <= UB_MAXVALUE, value <= UB_MAXVALUE, and only one addition
	 * at the moment is possible so an overflow is impossible.  
	 */
	ub->ub_parms[resource].held += val;

	switch (strict & ~UB_SEV_FLAGS) {
		case UB_HARD:
			if (ub->ub_parms[resource].held >
					ub->ub_parms[resource].barrier)
				break;
		case UB_SOFT:
			if (ub->ub_parms[resource].held >
					ub->ub_parms[resource].limit)
				break;
		case UB_FORCE:
			ub_adjust_maxheld(ub, resource);
			return 0;
		default:
			BUG();
	}

	if (!(strict & UB_TEST)) {
		if (strict == UB_SOFT && __ratelimit(&ub->ub_ratelimit))
			printk(KERN_INFO "Fatal resource shortage: %s, UB %d.\n",
			       ub_rnames[resource], ub->ub_uid);
		ub->ub_parms[resource].failcnt++;
	}
	ub->ub_parms[resource].held -= val;
	return -ENOMEM;
}

int charge_beancounter(struct user_beancounter *ub,
		int resource, unsigned long val, enum ub_severity strict)
{
	struct user_beancounter *p, *q;
	unsigned long flags;
	int retval = 0;

	if (val > UB_MAXVALUE)
		return -EINVAL;

	local_irq_save(flags);
	for (p = ub; p != NULL; p = p->parent) {
		spin_lock(&p->ub_lock);
		retval = __charge_beancounter_locked(p, resource, val, strict);
		spin_unlock(&p->ub_lock);
		if (unlikely(retval))
			goto unroll;
	}
out:
	local_irq_restore(flags);
	return retval;
unroll:
	for (q = ub; q != p; q = q->parent) {
		spin_lock(&q->ub_lock);
		__uncharge_beancounter_locked(q, resource, val);
		spin_unlock(&q->ub_lock);
	}
	goto out;
}
EXPORT_SYMBOL(charge_beancounter);

void uncharge_warn(struct user_beancounter *ub, const char *resource,
		unsigned long val, unsigned long held)
{
	set_bit(UB_UNDERFLOW, &ub->ub_flags);
	add_taint(TAINT_CRAP);
	printk(KERN_ERR "Uncharging too much %lu h %lu, res %s ub %u\n",
			val, held, resource, ub->ub_uid);
	ub_debug_trace(1, 10, 10*HZ);
}

void __uncharge_beancounter_locked(struct user_beancounter *ub,
		int resource, unsigned long val)
{
	ub_debug_resource(resource, "Uncharging %lu for %d of %p with %lu\n",
			val, resource, ub, ub->ub_parms[resource].held);
	if (ub->ub_parms[resource].held < val) {
		uncharge_warn(ub, ub_rnames[resource],
				val, ub->ub_parms[resource].held);
		val = ub->ub_parms[resource].held;
	}
	ub->ub_parms[resource].held -= val;
}

void uncharge_beancounter(struct user_beancounter *ub,
		int resource, unsigned long val)
{
	struct user_beancounter *p;
	unsigned long flags;

	local_irq_save(flags);
	for (p = ub; p != NULL; p = p->parent) {
		spin_lock(&p->ub_lock);
		__uncharge_beancounter_locked(p, resource, val);
		spin_unlock(&p->ub_lock);
	}
	local_irq_restore(flags);
}
EXPORT_SYMBOL(uncharge_beancounter);

/* called with disabled interrupts */
static int __precharge_beancounter_percpu(struct user_beancounter *ub,
		int resource, unsigned long val)
{
	struct ub_percpu_struct *ub_pcpu = ub_percpu(ub, smp_processor_id());
	int charge, retval;

	BUG_ON(ub->ub_parms[resource].max_precharge < 0);

	if (likely(ub_pcpu->precharge[resource] >= val))
		return 0;

	spin_lock(&ub->ub_lock);
	charge = max((int)val, ub->ub_parms[resource].max_precharge >> 1) -
		ub_pcpu->precharge[resource];
	retval = __charge_beancounter_locked(ub, resource,
			charge, UB_SOFT | UB_TEST);
	if (!retval)
		ub_pcpu->precharge[resource] += charge;
	spin_unlock(&ub->ub_lock);

	return retval;
}

/* called with disabled interrupts */
int __charge_beancounter_percpu(struct user_beancounter *ub,
		struct ub_percpu_struct *ub_pcpu,
		int resource, unsigned long val, enum ub_severity strict)
{
	int retval, precharge;

	spin_lock(&ub->ub_lock);
	precharge = max(0, (ub->ub_parms[resource].max_precharge >> 1) -
			ub_pcpu->precharge[resource]);
	retval = __charge_beancounter_locked(ub, resource,
			val + precharge, UB_SOFT | UB_TEST);
	if (!retval)
		ub_pcpu->precharge[resource] += precharge;
	else {
		init_beancounter_precharge(ub, resource);
		retval = __charge_beancounter_locked(ub, resource,
				val, strict);
	}
	spin_unlock(&ub->ub_lock);

	return retval;
}
EXPORT_SYMBOL(__charge_beancounter_percpu);

/* called with disabled interrupts */
void __uncharge_beancounter_percpu(struct user_beancounter *ub,
		struct ub_percpu_struct *ub_pcpu,
		int resource, unsigned long val)
{
	int uncharge;

	spin_lock(&ub->ub_lock);
	if (ub->ub_parms[resource].max_precharge !=
			ub_resource_precharge[resource])
		init_beancounter_precharge(ub, resource);
	uncharge = max(0, ub_pcpu->precharge[resource] -
			(ub->ub_parms[resource].max_precharge >> 1));
	ub_pcpu->precharge[resource] -= uncharge;
	smp_wmb();
	__uncharge_beancounter_locked(ub, resource, val + uncharge);
	spin_unlock(&ub->ub_lock);
}
EXPORT_SYMBOL(__uncharge_beancounter_percpu);

unsigned long __get_beancounter_usage_percpu(struct user_beancounter *ub,
		int resource)
{
	long held, precharge;

	held = ub->ub_parms[resource].held;
	smp_rmb();
	precharge = __ub_percpu_sum(ub, precharge[resource]);

	switch (resource) {
	case UB_PHYSPAGES:
		/* kmemsize precharge already charged into physpages  */
		precharge += __ub_percpu_sum(ub, precharge[UB_KMEMSIZE]) >> PAGE_SHIFT;
		break;
	case UB_OOMGUARPAGES:
		/* oomguarpages contains swappages and its precharge too */
		precharge = __ub_percpu_sum(ub, precharge[UB_SWAPPAGES]);
		break;
	}

	return held - precharge;
}

unsigned long get_beancounter_usage_percpu(struct user_beancounter *ub, int res)
{
	return max_t(long, 0, __get_beancounter_usage_percpu(ub, res));
}

int precharge_beancounter(struct user_beancounter *ub,
		int resource, unsigned long val)
{
	unsigned long flags;
	int retval;

	retval = -EINVAL;
	if (val > UB_MAXVALUE)
		goto out;

	local_irq_save(flags);
	if (ub)
		retval = __precharge_beancounter_percpu(ub, resource, val);
	local_irq_restore(flags);
out:
	return retval;
}
EXPORT_SYMBOL(precharge_beancounter);

int charge_beancounter_fast(struct user_beancounter *ub,
		int resource, unsigned long val, enum ub_severity strict)
{
	struct user_beancounter *p, *q;
	unsigned long flags;
	int retval = 0;

	if (val > UB_MAXVALUE)
		return -EINVAL;

	local_irq_save(flags);
	for (p = ub; p != NULL; p = p->parent) {
		retval = __charge_beancounter_fast(p, resource, val, strict);
		if (unlikely(retval))
			goto unroll;
	}
out:
	local_irq_restore(flags);
	return retval;
unroll:
	for (q = ub; q != p; q = q->parent)
		__uncharge_beancounter_fast(q, resource, val);
	goto out;
}
EXPORT_SYMBOL(charge_beancounter_fast);

void uncharge_beancounter_fast(struct user_beancounter *ub,
		int resource, unsigned long val)
{
	struct user_beancounter *p;
	unsigned long flags;

	local_irq_save(flags);
	for (p = ub; p != NULL; p = p->parent)
		__uncharge_beancounter_fast(p, resource, val);
	local_irq_restore(flags);
}
EXPORT_SYMBOL(uncharge_beancounter_fast);

void ub_reclaim_rate_limit(struct user_beancounter *ub, int wait, unsigned count)
{
	ktime_t wall;
	u64 step;

	ub = top_beancounter(ub);

	if (!ub->rl_step)
		return;

	spin_lock(&ub->rl_lock);
	step = (u64)ub->rl_step * count;
	wall = ktime_add_ns(ktime_get(), step);
	if (wall.tv64 < ub->rl_wall.tv64)
		wall = ktime_add_ns(ub->rl_wall, step);
	ub->rl_wall = wall;
	spin_unlock(&ub->rl_lock);

	if (wait && get_exec_ub_top() == ub && !test_thread_flag(TIF_MEMDIE)) {
		set_current_state(TASK_KILLABLE | TASK_IOTHROTTLED);
		schedule_hrtimeout(&wall, HRTIMER_MODE_ABS);
	}
}

/*
 *	Initialization
 *
 *	struct user_beancounter contains
 *	 - limits and other configuration settings,
 *	   with a copy stored for accounting purposes,
 *	 - structural fields: lists, spinlocks and so on.
 *
 *	Before these parts are initialized, the structure should be memset
 *	to 0 or copied from a known clean structure.  That takes care of a lot
 *	of fields not initialized explicitly.
 */

static void init_beancounter_struct(struct user_beancounter *ub)
{
	ub->ub_magic = UB_MAGIC;
	atomic_set(&ub->ub_refcount, 1);
	ub->parent = NULL;
	ub->top = ub;
	INIT_LIST_HEAD(&ub->children);
	INIT_HLIST_NODE(&ub->ub_hash);
	spin_lock_init(&ub->ub_lock);
	INIT_LIST_HEAD(&ub->ub_tcp_sk_list);
	INIT_LIST_HEAD(&ub->ub_other_sk_list);
#ifdef CONFIG_BC_DEBUG_KMEM
	INIT_LIST_HEAD(&ub->ub_cclist);
#endif
	INIT_LIST_HEAD(&ub->ub_dentry_lru);
#ifndef CONFIG_BC_KEEP_UNUSED
	INIT_WORK(&ub->work, delayed_release_beancounter);
#endif
	INIT_LIST_HEAD(&ub->ub_dentry_top);
	init_oom_control(&ub->oom_ctrl);
	spin_lock_init(&ub->rl_lock);
	ub->rl_wall.tv64 = LLONG_MIN;
	ub->dc_time = 0;
	ub->dc_shrink_ts = 0;
	rb_init_node(&ub->dc_node);
}

static void init_beancounter_nolimits(struct user_beancounter *ub)
{
	int k;

	for (k = 0; k < UB_RESOURCES; k++) {
		ub->ub_parms[k].limit = UB_MAXVALUE;
		ub->ub_parms[k].barrier = UB_MAXVALUE;
	}

	/*
	 * Unlimited vmguarpages gives immunity against systemwide overcommit
	 * policy. It makes sense in some cases but by default we must obey it.
	 */
	ub->ub_parms[UB_VMGUARPAGES].barrier = 0;

	/*
	 * Unlimited oomguarpages makes container or host mostly immune to
	 * to the OOM-killer while other containers exists. Withal we cannot
	 * set it to zero, otherwise single unconfigured container will be
	 * first target for OOM-killer. 75% of ram looks like sane default.
	 */
	ub->ub_parms[UB_OOMGUARPAGES].barrier = totalram_pages * 3 / 4;

	/* Ratelimit for messages in the kernel log */
	ub->ub_ratelimit.burst = 4;
	ub->ub_ratelimit.interval = 300*HZ;

	/* VSwap ratelimit. Safe for ub0, its physpages are unlimited */
	ub->rl_step = NSEC_PER_SEC / 25600; /* 100 Mb/s */
}

static DEFINE_PER_CPU(struct ub_percpu_struct, ub0_percpu);

void __init ub_init_early(void)
{
	struct user_beancounter *ub;

	init_cache_counters();
	ub = get_ub0();
	ub->ub_uid = 0;
	init_beancounter_nolimits(ub);
	init_beancounter_struct(ub);
	init_beancounter_precharges_early(ub);
	ub->ub_percpu = &per_cpu_var(ub0_percpu);

	memset(&current->task_bc, 0, sizeof(struct task_beancounter));
	(void)set_exec_ub(ub);
	current->task_bc.task_ub = get_beancounter_longterm(ub);
	__charge_beancounter_locked(ub, UB_NUMPROC, 1, UB_FORCE);
	init_mm.mm_ub = get_beancounter_longterm(ub);

	hlist_add_head(&ub->ub_hash, &ub_hash[ub->ub_uid]);
	list_add(&ub->ub_list, &ub_top_list);
	ub_count++;
}

static int proc_resource_precharge(ctl_table *table, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos)
{
	static DEFINE_MUTEX(lock);
	struct user_beancounter *ub;
	int err;

	mutex_lock(&lock);

	err = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (err || !write)
		goto out;

	rcu_read_lock();
	for_each_top_beancounter(ub) {
		spin_lock_irq(&ub->ub_lock);
		init_beancounter_precharges(ub);
		spin_unlock_irq(&ub->ub_lock);
	}
	rcu_read_unlock();

out:
	mutex_unlock(&lock);
	return err;
}

static unsigned int zero = 0;
static unsigned int one = 1;
static unsigned int hundreed = 100;
static int ubc_pagecache_isolation_id;
static DEFINE_MUTEX(pagecache_isolation_lock);

static int proc_pagecache_isolation(ctl_table *table, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos)
{
	struct user_beancounter *ub;
	int err;

	mutex_lock(&pagecache_isolation_lock);
	err = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (err || !write)
		goto out;
	rcu_read_lock();
	for_each_top_beancounter(ub) {
		if (ubc_pagecache_isolation)
			set_bit(UB_PAGECACHE_ISOLATION, &ub->ub_flags);
		else
			clear_bit(UB_PAGECACHE_ISOLATION, &ub->ub_flags);
	}
	rcu_read_unlock();
out:
	mutex_unlock(&pagecache_isolation_lock);
	return err;
}

static int proc_pagecache_isolation_change(ctl_table *table, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos)
{
	struct user_beancounter *ub;
	int err;

	mutex_lock(&pagecache_isolation_lock);
	err = proc_dointvec(table, write, buffer, lenp, ppos);
	if (err || !write)
		goto out;
	ub = get_beancounter_byuid(ubc_pagecache_isolation_id, 0);
	if (ub) {
		if (table->extra1)
			set_bit(UB_PAGECACHE_ISOLATION, &ub->ub_flags);
		else
			clear_bit(UB_PAGECACHE_ISOLATION, &ub->ub_flags);
		put_beancounter(ub);
	} else
		err = -ENOENT;
out:
	mutex_unlock(&pagecache_isolation_lock);
	return err;
}

static ctl_table ub_sysctl_table[] = {
	{
		.procname	= "resource_precharge",
		.ctl_name	= CTL_UNNUMBERED,
		.data		= &ub_resource_precharge,
		.extra1		= &resource_precharge_min,
		.extra2		= &resource_precharge_max,
		.maxlen		= sizeof(ub_resource_precharge),
		.mode		= 0644,
		.proc_handler	= &proc_resource_precharge,
	},
	{
		.procname	= "dcache_threshold_ratio",
		.ctl_name	= CTL_UNNUMBERED,
		.data		= &ub_dcache_thres_ratio,
		.maxlen		= sizeof(ub_dcache_thres_ratio),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &hundreed,
	},
	{
		.procname	= "dcache_shrink_time_threshold",
		.ctl_name	= CTL_UNNUMBERED,
		.data		= &ub_dcache_time_thresh,
		.maxlen		= sizeof(ub_dcache_time_thresh),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "dcache_lru_popup",
		.ctl_name	= CTL_UNNUMBERED,
		.data		= &ub_dcache_lru_popup,
		.maxlen		= sizeof(ub_dcache_lru_popup),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "dcache_no_vzfs_cache",
		.ctl_name	= CTL_UNNUMBERED,
		.data		= &ub_dcache_no_vzfs_cache,
		.maxlen		= sizeof(ub_dcache_no_vzfs_cache),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "ioprio",
		.ctl_name	= CTL_UNNUMBERED,
		.data		= &ubc_ioprio,
		.maxlen		= sizeof(ubc_ioprio),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
#ifdef CONFIG_BC_IO_ACCOUNTING
	{
		.procname	= "dirty_ratio",
		.ctl_name	= CTL_UNNUMBERED,
		.data		= &ub_dirty_radio,
		.maxlen		= sizeof ub_dirty_radio,
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "dirty_background_ratio",
		.ctl_name	= CTL_UNNUMBERED,
		.data		= &ub_dirty_background_ratio,
		.maxlen		= sizeof ub_dirty_background_ratio,
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "pagecache_isolation",
		.ctl_name	= CTL_UNNUMBERED,
		.data		= &ubc_pagecache_isolation,
		.maxlen		= sizeof ubc_pagecache_isolation,
		.mode		= 0644,
		.proc_handler	= proc_pagecache_isolation,
		.extra1		= &zero,
		.extra2		= &one,
	},
	{
		.procname	= "pagecache_isolation_on",
		.ctl_name	= CTL_UNNUMBERED,
		.data		= &ubc_pagecache_isolation_id,
		.maxlen		= sizeof ubc_pagecache_isolation_id,
		.mode		= 0200,
		.proc_handler	= proc_pagecache_isolation_change,
		.extra1		= &one,
	},
	{
		.procname	= "pagecache_isolation_off",
		.ctl_name	= CTL_UNNUMBERED,
		.data		= &ubc_pagecache_isolation_id,
		.maxlen		= sizeof ubc_pagecache_isolation_id,
		.mode		= 0200,
		.proc_handler	= proc_pagecache_isolation_change,
	},
#endif /* CONFIG_BC_IO_ACCOUNTING */
	{ .ctl_name = 0 }
};

static ctl_table ub_sysctl_root[] = {
       {
	       .ctl_name	= CTL_UNNUMBERED,
	       .procname	= "ubc",
	       .mode		= 0555,
	       .child		= ub_sysctl_table,
       },
       { .ctl_name = 0 }
};

void __init ub_init_late(void)
{
	register_sysctl_table(ub_sysctl_root);
	ub_cachep = kmem_cache_create("user_beancounters",
			sizeof(struct user_beancounter),
			0, SLAB_HWCACHE_ALIGN | SLAB_PANIC, NULL);

	init_oom_control(&global_oom_ctrl);

	init_beancounter_nolimits(&ub0);
	set_gang_limits(get_ub_gs(&ub0), &ub0.ub_parms[UB_PHYSPAGES].limit,
					 &node_states[N_HIGH_MEMORY]);
}

static __init int ub_init_wq(void)
{
	ub_clean_wq = create_singlethread_workqueue("ubcleand");
	if (ub_clean_wq == NULL)
		panic("Can't create ubclean wq");
	return 0;
}

late_initcall(ub_init_wq);

int __init ub_init_cgroup(void)
{
	struct vfsmount *mnt;
	struct cgroup_sb_opts opts = {
		.name		= "beancounter",
		.subsys_bits    = 1ul << blkio_subsys_id,
	};
	int err;

	mnt = cgroup_kernel_mount(&opts);
	if (IS_ERR(mnt))
		return PTR_ERR(mnt);
	ub_cgroup_root = cgroup_get_root(mnt);

	err = ub_cgroup_init(&ub0);
	if (ub0.ub_cgroup)
		err = cgroup_kernel_attach(ub0.ub_cgroup,
					   init_pid_ns.child_reaper);
	return err;
}
late_initcall(ub_init_cgroup);

static int __init parse_ubc_ioprio(char *arg)
{
	ubc_ioprio = simple_strtoul(arg, NULL, 0);
	return 0;
}
__setup("ubc.ioprio=", parse_ubc_ioprio);
