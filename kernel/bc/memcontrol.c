#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/mmgang.h>
#include <linux/mutex.h>
#include <linux/task_work.h>
#include <linux/res_counter.h>
#include <linux/cgroup.h>
#include <bc/beancounter.h>

struct mem_cgroup {
	struct cgroup_subsys_state css;
	struct user_beancounter *ub;
	unsigned long long soft_limit;		/* dummy */
};

static struct mem_cgroup *cgroup_to_mem_cgroup(struct cgroup *cg)
{
	return container_of(cgroup_subsys_state(cg, mem_cgroup_subsys_id),
			    struct mem_cgroup, css);
}

static struct cgroup_subsys_state *
mem_cgroup_create(struct cgroup_subsys *ss, struct cgroup *cg)
{
	struct mem_cgroup *memcg, *parent_memcg;
	struct user_beancounter *ub, *parent_ub;

	memcg = kzalloc(sizeof(*memcg), GFP_KERNEL);
	if (!memcg)
		return ERR_PTR(-ENOMEM);

	memcg->soft_limit = RESOURCE_MAX;

	if (!cg->parent) {
		ub = get_beancounter_longterm(get_ub0());
		goto done;
	}

	parent_memcg = cgroup_to_mem_cgroup(cg->parent);
	parent_ub = parent_memcg->ub;

	if (current->in_ub_memcg_attach)
		ub = get_beancounter_longterm(get_exec_ub());
	else
		ub = get_sub_beancounter(parent_ub);
	if (!ub) {
		kfree(memcg);
		return ERR_PTR(-ENOMEM);
	}
done:
	memcg->ub = ub;
	rcu_assign_pointer(ub->mem_cgroup, cg);
	return &memcg->css;
}

static int mem_cgroup_pre_destroy(struct cgroup_subsys *ss, struct cgroup *cg)
{
	struct mem_cgroup *memcg = cgroup_to_mem_cgroup(cg);

	RCU_INIT_POINTER(memcg->ub->mem_cgroup, NULL);
	return 0;
}

static void mem_cgroup_destroy(struct cgroup_subsys *ss, struct cgroup *cg)
{
	struct mem_cgroup *memcg = cgroup_to_mem_cgroup(cg);
	struct user_beancounter *ub = memcg->ub;

	spin_lock_irq(&ub->ub_lock);
	ub->ub_parms[UB_PHYSPAGES].limit = UB_MAXVALUE;
	ub->ub_parms[UB_PHYSPAGES].barrier = UB_MAXVALUE;
	ub->ub_parms[UB_SWAPPAGES].limit = UB_MAXVALUE;
	ub->ub_parms[UB_SWAPPAGES].barrier = UB_MAXVALUE;
	spin_unlock_irq(&ub->ub_lock);

	put_beancounter_longterm(ub);
	kfree(memcg);
}

struct mem_cgroup_attach_work {
	struct task_work task_work;
	struct user_beancounter *ub;
};

static void mem_cgroup_attach_work_fn(struct task_work *tw)
{
	struct mem_cgroup_attach_work *w = container_of(tw,
			struct mem_cgroup_attach_work, task_work);

	put_beancounter_longterm(set_exec_ub(w->ub));
	kfree(w);
}

static void mem_cgroup_attach_work_release(struct task_work *tw)
{
	struct mem_cgroup_attach_work *w = container_of(tw,
			struct mem_cgroup_attach_work, task_work);

	put_beancounter_longterm(w->ub);
	kfree(w);
}

static void mem_cgroup_attach_task(struct cgroup *cg, struct task_struct *p)
{
	struct mem_cgroup *memcg = cgroup_to_mem_cgroup(cg);
	struct mem_cgroup_attach_work *w;
	struct task_work *tw;

	if (current->in_ub_memcg_attach)
		return;

	if (p->flags & PF_KTHREAD)
		return;

	tw = task_work_cancel(p, mem_cgroup_attach_work_fn);
	if (tw)
		mem_cgroup_attach_work_release(tw);

	w = kmalloc(sizeof(*w), GFP_KERNEL | __GFP_NOFAIL);
	init_task_work(&w->task_work, mem_cgroup_attach_work_fn, w);
	w->ub = get_beancounter_longterm(memcg->ub);

	if (task_work_add(p, &w->task_work, true))
		mem_cgroup_attach_work_release(&w->task_work);
}

enum {
	_MEM,
	_MEMSWAP,
};

#define MEMFILE_PRIVATE(x, val)	(((x) << 16) | (val))
#define MEMFILE_TYPE(val)	(((val) >> 16) & 0xffff)
#define MEMFILE_ATTR(val)	((val) & 0xffff)

static u64 mem_cgroup_read(struct cgroup *cg, struct cftype *cft)
{
	struct mem_cgroup *memcg = cgroup_to_mem_cgroup(cg);
	struct user_beancounter *ub = memcg->ub;
	struct ubparm *m, *s;
	int type, name;
	u64 val;

	type = MEMFILE_TYPE(cft->private);
	name = MEMFILE_ATTR(cft->private);

	BUG_ON(type != _MEM && type != _MEMSWAP);

	m = &ub->ub_parms[UB_PHYSPAGES];
	s = &ub->ub_parms[UB_SWAPPAGES];

	switch (name) {
	case RES_USAGE:
		if (type == _MEM)
			val = m->held;
		else
			val = m->held + s->held;
		val <<= PAGE_SHIFT;
		break;
	case RES_MAX_USAGE:
		if (type == _MEM)
			val = m->maxheld;
		else
			val = m->maxheld + s->maxheld;
		val <<= PAGE_SHIFT;
		break;
	case RES_LIMIT:
		if (type == _MEM)
			val = m->limit;
		else
			val = m->limit < UB_MAXVALUE &&
			      s->limit < UB_MAXVALUE ?
			      m->limit + s->limit : UB_MAXVALUE;
		if (val < UB_MAXVALUE)
			val <<= PAGE_SHIFT;
		break;
	case RES_SOFT_LIMIT:
		val = memcg->soft_limit;
		break;
	case RES_FAILCNT:
		if (type == _MEM)
			val = m->failcnt;
		else
			val = s->failcnt;
		break;
	default:
		BUG();
	}

	return val;
}

static int mem_cgroup_write(struct cgroup *cg, struct cftype *cft,
			    const char *buffer)
{
	struct mem_cgroup *memcg = cgroup_to_mem_cgroup(cg);
	struct user_beancounter *ub = memcg->ub;
	struct ubparm *m, *s;
	unsigned long mem_lim, memsw_lim;
	int type, name;
	unsigned long long val;
	int ret;

	type = MEMFILE_TYPE(cft->private);
	name = MEMFILE_ATTR(cft->private);

	BUG_ON(name != RES_LIMIT && name != RES_SOFT_LIMIT);

	ret = res_counter_memparse_write_strategy(buffer, &val);
	if (ret)
		return ret;

	if (name == RES_SOFT_LIMIT) {
		memcg->soft_limit = val;
		return 0;
	}

	if (val == RESOURCE_MAX)
		val = UB_MAXVALUE;
	else
		val >>= PAGE_SHIFT;

	m = &ub->ub_parms[UB_PHYSPAGES];
	s = &ub->ub_parms[UB_SWAPPAGES];

	spin_lock_irq(&ub->ub_lock);
	mem_lim = m->limit;
	memsw_lim = m->limit < UB_MAXVALUE &&
		    s->limit < UB_MAXVALUE ?
		    m->limit + s->limit : UB_MAXVALUE;
	switch (type) {
	case _MEM:
		if (val <= memsw_lim) {
			m->limit = m->barrier = val;
			s->limit = s->barrier = memsw_lim - val;
		} else
			ret = -EINVAL;
		break;
	case _MEMSWAP:
		if (val >= mem_lim)
			s->limit = s->barrier = val - mem_lim;
		else
			ret = -EINVAL;
		break;
	default:
		BUG();
	}
	spin_unlock_irq(&ub->ub_lock);

	return ret;
}

static int mem_cgroup_reset(struct cgroup *cg, unsigned int event)
{
	struct user_beancounter *ub = cgroup_to_mem_cgroup(cg)->ub;
	struct ubparm *r;
	int type, name;

	type = MEMFILE_TYPE(event);
	name = MEMFILE_ATTR(event);

	switch (type) {
	case _MEM:
		r = &ub->ub_parms[UB_PHYSPAGES];
		break;
	case _MEMSWAP:
		r = &ub->ub_parms[UB_SWAPPAGES];
		break;
	default:
		BUG();
	}

	spin_lock_irq(&ub->ub_lock);
	switch (name) {
	case RES_MAX_USAGE:
		r->maxheld = r->held;
		break;
	case RES_FAILCNT:
		r->failcnt = 0;
		break;
	default:
		BUG();
	}
	spin_unlock_irq(&ub->ub_lock);

	return 0;
}

static const char * const mem_cgroup_lru_names[] = {
	"inactive_anon",
	"active_anon",
	"inactive_file",
	"active_file",
	"unevictable",
};

static int mem_cgroup_stat_read(struct cgroup *cg, struct cftype *cft,
				struct cgroup_map_cb *cb)
{
	struct mem_cgroup *memcg = cgroup_to_mem_cgroup(cg);
	unsigned long stats[NR_LRU_LISTS];
	char buf[32];
	enum lru_list l;

	gang_page_stat(get_ub_gs(memcg->ub), false, NULL, stats, NULL);
	for_each_lru(l)
		cb->fill(cb, mem_cgroup_lru_names[l], stats[l]);

	gang_page_stat(get_ub_gs(memcg->ub), true, NULL, stats, NULL);
	for_each_lru(l) {
		snprintf(buf, sizeof(buf), "total_%s", mem_cgroup_lru_names[l]);
		cb->fill(cb, buf, stats[l]);
	}
	return 0;
}
static u64 mem_cgroup_hierarchy_read(struct cgroup *cont, struct cftype *cft)
{
	return 1;
}

static int mem_cgroup_hierarchy_write(struct cgroup *cont, struct cftype *cft,
					u64 val)
{
	return 0;
}

static struct cftype mem_cgroup_files[] = {
	{
		.name = "usage_in_bytes",
		.private = MEMFILE_PRIVATE(_MEM, RES_USAGE),
		.read_u64 = mem_cgroup_read,
	},
	{
		.name = "max_usage_in_bytes",
		.private = MEMFILE_PRIVATE(_MEM, RES_MAX_USAGE),
		.trigger = mem_cgroup_reset,
		.read_u64 = mem_cgroup_read,
	},
	{
		.name = "limit_in_bytes",
		.private = MEMFILE_PRIVATE(_MEM, RES_LIMIT),
		.write_string = mem_cgroup_write,
		.read_u64 = mem_cgroup_read,
	},
	{
		.name = "soft_limit_in_bytes",
		.private = MEMFILE_PRIVATE(_MEM, RES_SOFT_LIMIT),
		.write_string = mem_cgroup_write,
		.read_u64 = mem_cgroup_read,
	},
	{
		.name = "failcnt",
		.private = MEMFILE_PRIVATE(_MEM, RES_FAILCNT),
		.trigger = mem_cgroup_reset,
		.read_u64 = mem_cgroup_read,
	},
	{
		.name = "memsw.usage_in_bytes",
		.private = MEMFILE_PRIVATE(_MEMSWAP, RES_USAGE),
		.read_u64 = mem_cgroup_read,
	},
	{
		.name = "memsw.max_usage_in_bytes",
		.private = MEMFILE_PRIVATE(_MEMSWAP, RES_MAX_USAGE),
		.trigger = mem_cgroup_reset,
		.read_u64 = mem_cgroup_read,
	},
	{
		.name = "memsw.limit_in_bytes",
		.private = MEMFILE_PRIVATE(_MEMSWAP, RES_LIMIT),
		.write_string = mem_cgroup_write,
		.read_u64 = mem_cgroup_read,
	},
	{
		.name = "memsw.failcnt",
		.private = MEMFILE_PRIVATE(_MEMSWAP, RES_FAILCNT),
		.trigger = mem_cgroup_reset,
		.read_u64 = mem_cgroup_read,
	},
	{
		.name = "stat",
		.read_map = mem_cgroup_stat_read,
	},
	{
		.name = "use_hierarchy",
		.write_u64 = mem_cgroup_hierarchy_write,
		.read_u64 = mem_cgroup_hierarchy_read,
	},
};

static int mem_cgroup_populate(struct cgroup_subsys *ss, struct cgroup *cg)
{
	return cgroup_add_files(cg, ss, mem_cgroup_files,
				ARRAY_SIZE(mem_cgroup_files));
}

struct cgroup_subsys mem_cgroup_subsys = {
	.name = "memory",
	.subsys_id = mem_cgroup_subsys_id,
	.create = mem_cgroup_create,
	.pre_destroy = mem_cgroup_pre_destroy,
	.destroy = mem_cgroup_destroy,
	.populate = mem_cgroup_populate,
	.attach_task = mem_cgroup_attach_task,
};

static struct cgroup *mem_cgroup_root;

static int __init mem_cgroup_init(void)
{
	struct vfsmount *mnt;
	struct cgroup_sb_opts opts = {
		.subsys_bits = 1ul << mem_cgroup_subsys_id,
	};

	mnt = cgroup_kernel_mount(&opts);
	if (IS_ERR(mnt))
		return PTR_ERR(mnt);

	mem_cgroup_root = cgroup_get_root(mnt);

	return 0;
}
late_initcall(mem_cgroup_init);

int ub_mem_cgroup_attach(struct user_beancounter *ub)
{
	struct user_beancounter *old_ub;
	struct cgroup *cg;
	char name[16];
	int err;

	if (ub->parent)
		return -EPERM;

	old_ub = set_exec_ub(ub);
	current->in_ub_memcg_attach = 1;

	if (ub != get_ub0()) {
		snprintf(name, sizeof(name), "%u", ub->ub_uid);
		cg = cgroup_kernel_open(mem_cgroup_root,
					CGRP_CREAT|CGRP_WEAK, name);
		err = PTR_ERR(cg);
		if (IS_ERR(cg))
			goto out;
	} else
		cg = mem_cgroup_root;

	err = -EBUSY;
	if (cgroup_to_mem_cgroup(cg)->ub != ub)
		goto out_close_cg;

	err = cgroup_kernel_attach(cg, current);

out_close_cg:
	if (cg != mem_cgroup_root)
		cgroup_kernel_close(cg);
out:
	current->in_ub_memcg_attach = 0;
	ub = set_exec_ub(old_ub);

	return err;
}

void ub_print_mem_cgroup_name(struct user_beancounter *ub)
{
	static char buf[PATH_MAX];
	static DEFINE_SPINLOCK(lock);
	unsigned long flags;

	if (!ub->parent) {
		printk(KERN_CONT "/");
		return;
	}

	if (!ub->mem_cgroup) {
		printk(KERN_CONT "(deleted)");
		return;
	}

	spin_lock_irqsave(&lock, flags);

	rcu_read_lock();
	cgroup_path(rcu_dereference(ub->mem_cgroup), buf, sizeof(buf));
	rcu_read_unlock();

	printk(KERN_CONT "%s", buf);

	spin_unlock_irqrestore(&lock, flags);
}
