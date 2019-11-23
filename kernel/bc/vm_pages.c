/*
 *  kernel/bc/vm_pages.c
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/virtinfo.h>
#include <linux/module.h>
#include <linux/shmem_fs.h>
#include <linux/vmalloc.h>
#include <linux/init.h>
#include <linux/mmgang.h>

#include <asm/pgtable.h>
#include <asm/page.h>

#include <bc/beancounter.h>
#include <bc/vmpages.h>
#include <bc/proc.h>
#include <bc/oom_kill.h>

#ifdef CONFIG_BC_RSS_ACCOUNTING

/**
 * Update oomguarpages.held value, it includes:
 *  charged swap-backed pages:	present anonymous pages, swapcache, tmpfs
 *  unevictable-pages:		mlocked pages, ramfs
 *  swap-entries:		allocated swap-space
 */
void __ub_update_oomguarpages(struct user_beancounter *ub)
{
	unsigned long pages[NR_LRU_LISTS];

	gang_page_stat(get_ub_gs(ub), true, NULL, pages, NULL);

	ub->ub_parms[UB_OOMGUARPAGES].held =
		pages[LRU_ACTIVE_ANON] +
		pages[LRU_INACTIVE_ANON] +
		pages[LRU_UNEVICTABLE] +
		ub->ub_parms[UB_SWAPPAGES].held;

	ub_adjust_maxheld(ub, UB_OOMGUARPAGES);
}

#else

void __ub_update_oomguarpages(struct user_beancounter *ub)
{
	ub->ub_parms[UB_OOMGUARPAGES].held =
		ub->ub_parms[UB_PRIVVMPAGES].held +
		ub->ub_parms[UB_LOCKEDPAGES].held +
		ub->ub_parms[UB_PHYSPAGES].held +
		ub->ub_parms[UB_SWAPPAGES].held;

	ub_adjust_maxheld(ub, UB_OOMGUARPAGES);
}

#endif

long ub_oomguarpages_left(struct user_beancounter *ub)
{
	unsigned long flags;
	long left;
	int precharge[UB_RESOURCES];

	spin_lock_irqsave(&ub->ub_lock, flags);
	__ub_update_oomguarpages(ub);
	left = ub->ub_parms[UB_OOMGUARPAGES].barrier -
		ub->ub_parms[UB_OOMGUARPAGES].held;
	spin_unlock_irqrestore(&ub->ub_lock, flags);

	ub_precharge_snapshot(ub, precharge);
	left += precharge[UB_OOMGUARPAGES];

	return left;
}

void ub_update_resources_locked(struct user_beancounter *ub)
{
	__ub_update_oomguarpages(ub);
}
EXPORT_SYMBOL(ub_update_resources_locked);

void ub_update_resources(struct user_beancounter *ub)
{
	unsigned long flags;

	spin_lock_irqsave(&ub->ub_lock, flags);
	ub_update_resources_locked(ub);
	spin_unlock_irqrestore(&ub->ub_lock, flags);
}
EXPORT_SYMBOL(ub_update_resources);

int ub_memory_charge(struct mm_struct *mm, unsigned long size,
		unsigned vm_flags, struct file *vm_file, int sv)
{
	struct user_beancounter *ub;

	ub = mm_ub_top(mm);
	if (ub == NULL)
		return 0;

	size >>= PAGE_SHIFT;
	if (size > UB_MAXVALUE)
		return -EINVAL;

	BUG_ON(sv != UB_SOFT && sv != UB_HARD);

	if (vm_flags & VM_LOCKED) {
		if (charge_beancounter(ub, UB_LOCKEDPAGES, size, sv))
			goto out_err;
	}
	if (VM_UB_PRIVATE(vm_flags, vm_file)) {
               if (charge_beancounter_fast(ub, UB_PRIVVMPAGES, size, sv))
			goto out_private;
	}
	return 0;

out_private:
	if (vm_flags & VM_LOCKED)
		uncharge_beancounter(ub, UB_LOCKEDPAGES, size);
out_err:
	return -ENOMEM;
}

void ub_memory_uncharge(struct mm_struct *mm, unsigned long size,
		unsigned vm_flags, struct file *vm_file)
{
	struct user_beancounter *ub;

	ub = mm_ub_top(mm);
	if (ub == NULL)
		return;

	size >>= PAGE_SHIFT;

	if (vm_flags & VM_LOCKED)
		uncharge_beancounter(ub, UB_LOCKEDPAGES, size);
       if (VM_UB_PRIVATE(vm_flags, vm_file))
               uncharge_beancounter_fast(ub, UB_PRIVVMPAGES, size);
}

int ub_locked_charge(struct mm_struct *mm, unsigned long size)
{
	struct user_beancounter *ub;

	ub = mm_ub_top(mm);
	if (ub == NULL)
		return 0;

	return charge_beancounter(ub, UB_LOCKEDPAGES,
			size >> PAGE_SHIFT, UB_HARD);
}

void ub_locked_uncharge(struct mm_struct *mm, unsigned long size)
{
	struct user_beancounter *ub;

	ub = mm_ub_top(mm);
	if (ub == NULL)
		return;

	uncharge_beancounter(ub, UB_LOCKEDPAGES, size >> PAGE_SHIFT);
}

int ub_lockedshm_charge(struct shmem_inode_info *shi, unsigned long size)
{
	struct user_beancounter *ub;

	ub = top_beancounter(shi->shmi_ub);
	if (ub == NULL)
		return 0;

	return charge_beancounter(ub, UB_LOCKEDPAGES,
				  size >> PAGE_SHIFT, UB_HARD);
}

void ub_lockedshm_uncharge(struct shmem_inode_info *shi, unsigned long size)
{
	struct user_beancounter *ub;

	ub = top_beancounter(shi->shmi_ub);
	if (ub == NULL)
		return;

	uncharge_beancounter(ub, UB_LOCKEDPAGES, size >> PAGE_SHIFT);
}


static inline void do_ub_tmpfs_respages_inc(struct user_beancounter *ub)
{
	unsigned long flags;

	spin_lock_irqsave(&ub->ub_lock, flags);
	ub->ub_tmpfs_respages++;
	spin_unlock_irqrestore(&ub->ub_lock, flags);
}

void ub_tmpfs_respages_inc(struct shmem_inode_info *shi)
{
	if (shi->shmi_ub)
		do_ub_tmpfs_respages_inc(shi->shmi_ub);
}

static inline void do_ub_tmpfs_respages_sub(struct user_beancounter *ub,
		unsigned long size)
{
	unsigned long flags;

	spin_lock_irqsave(&ub->ub_lock, flags);
	/* catch possible overflow */
	if (ub->ub_tmpfs_respages < size) {
		uncharge_warn(ub, "tmpfs_respages",
				size, ub->ub_tmpfs_respages);
		size = ub->ub_tmpfs_respages;
	}
	ub->ub_tmpfs_respages -= size;
	spin_unlock_irqrestore(&ub->ub_lock, flags);
}

void ub_tmpfs_respages_sub(struct shmem_inode_info *shi,
		unsigned long size)
{
	if (shi->shmi_ub)
		do_ub_tmpfs_respages_sub(shi->shmi_ub, size);
}

#ifdef CONFIG_BC_RSS_ACCOUNTING
int ub_try_to_free_pages(struct user_beancounter *ub, gfp_t gfp_mask)
{
	unsigned long progress, flags;

	if (!(gfp_mask & __GFP_WAIT))
		goto nowait;

	progress = try_to_free_gang_pages(get_ub_gs(ub),
			gfp_mask | __GFP_HIGHMEM);
	if (progress)
		return 0;

nowait:
	if (gfp_mask & __GFP_NOWARN)
		goto nowarn;

	spin_lock_irqsave(&ub->ub_lock, flags);
	ub->ub_parms[UB_PHYSPAGES].failcnt++;
	if (!ub_resource_excess(ub, UB_SWAPPAGES, UB_SOFT))
		ub->ub_parms[UB_SWAPPAGES].failcnt++;
	spin_unlock_irqrestore(&ub->ub_lock, flags);

nowarn:
	if ((gfp_mask & __GFP_NORETRY) || !(gfp_mask & __GFP_WAIT) ||
			out_of_memory_in_ub(ub, gfp_mask))
		return -ENOMEM;

	return 0;
}

static int __ub_phys_charge(struct user_beancounter *ub,
		unsigned long pages, gfp_t gfp_mask)
{
	int strict = UB_SOFT | UB_TEST;
	unsigned long flags;

	if (gfp_mask & __GFP_NOFAIL)
		strict = UB_FORCE;

	ub_oom_start(&ub->oom_ctrl);

	local_irq_save(flags);
	while (__charge_beancounter_fast(ub, UB_PHYSPAGES, pages, strict)) {
		local_irq_restore(flags);
		if (test_thread_flag(TIF_MEMDIE) ||
		    fatal_signal_pending(current))
			strict = UB_FORCE;
		else if (ub_try_to_free_pages(ub, gfp_mask))
			return -ENOMEM;
		local_irq_save(flags);
	}
	local_irq_restore(flags);

	return 0;
}

int ub_phys_charge(struct user_beancounter *ub,
		unsigned long pages, gfp_t gfp_mask)
{
	struct user_beancounter *p, *q, *exec_ub;
	unsigned long flags;
	bool force = false;
	int retval;

	exec_ub = get_exec_ub();
	if (ub_is_descendant(ub, exec_ub))
		force = true;

	for (p = ub; p != NULL; p = p->parent) {
		if (p == exec_ub)
			force = false;

		retval = __try_charge_beancounter_percpu(p,
				ub_percpu(p, get_cpu()), UB_PHYSPAGES, pages);
		put_cpu();
		if (retval)
			retval = __ub_phys_charge(p, pages,
				force ? gfp_mask | __GFP_NOFAIL : gfp_mask);
		if (retval)
			goto unroll;
	}
	return 0;
unroll:
	local_irq_save(flags);
	for (q = ub; q != p; q = q->parent)
		__uncharge_beancounter_fast(q, UB_PHYSPAGES, pages);
	local_irq_restore(flags);
	return retval;
}
EXPORT_SYMBOL(ub_phys_charge);

static int __ub_check_ram_limits_size(struct user_beancounter *ub,
				      gfp_t gfp_mask, int size)
{
	if (gfp_mask & __GFP_NOFAIL)
		return 0;

	ub_oom_start(&ub->oom_ctrl);

	do {
		if (test_thread_flag(TIF_MEMDIE) ||
		    fatal_signal_pending(current))
			return 0;
		if (ub_try_to_free_pages(ub, gfp_mask))
			return -ENOMEM;
	} while (precharge_beancounter(ub, UB_PHYSPAGES, size));

	return 0;
}

int ub_check_ram_limits_size(struct user_beancounter *ub,
			     gfp_t gfp_mask, int size)
{
	struct user_beancounter *p, *exec_ub;
	bool force = false;
	int retval;

	exec_ub = get_exec_ub();
	if (ub_is_descendant(ub, exec_ub))
		force = true;

	for (p = ub; p != NULL; p = p->parent) {
		if (p == exec_ub)
			force = false;

		if (likely(p->ub_parms[UB_PHYSPAGES].limit == UB_MAXVALUE ||
		    !precharge_beancounter(p, UB_PHYSPAGES, size) || force))
			continue;

		retval = __ub_check_ram_limits_size(p, gfp_mask, size);
		if (retval)
			return retval;
	}
	return 0;
}
EXPORT_SYMBOL(ub_check_ram_limits_size);

#endif

#ifdef CONFIG_HUGETLBFS

int ub_hugetlb_charge(struct user_beancounter *ub, struct page *page)
{
	struct user_beancounter *top_ub = top_beancounter(ub);
	int numpages = 1 << compound_order(page);

	if (ub_phys_charge(ub, numpages, GFP_KERNEL))
		return -ENOMEM;

	spin_lock_irq(&top_ub->ub_lock);
	if (__charge_beancounter_locked(top_ub, UB_LOCKEDPAGES, numpages, UB_SOFT)) {
		spin_unlock_irq(&top_ub->ub_lock);
		ub_phys_uncharge(ub, numpages);
		return -ENOMEM;
	}
	ub->ub_hugetlb_pages += numpages;
	spin_unlock_irq(&top_ub->ub_lock);

	BUG_ON(page->kmem_ub);
	page->kmem_ub = ub;
	get_beancounter(ub);
	return 0;
}

void ub_hugetlb_uncharge(struct page *page)
{
	struct user_beancounter *ub = page->kmem_ub;
	struct user_beancounter *top_ub = top_beancounter(ub);
	int numpages = 1 << compound_order(page);

	if (!ub)
		return;

	ub_phys_uncharge(ub, numpages);

	spin_lock_irq(&top_ub->ub_lock);
	__uncharge_beancounter_locked(top_ub, UB_LOCKEDPAGES, numpages);
	ub->ub_hugetlb_pages -= numpages;
	spin_unlock_irq(&top_ub->ub_lock);

	page->kmem_ub = NULL;
	put_beancounter(ub);
}

#endif /* CONFIG_HUGETLBFS */

#ifdef CONFIG_BC_SWAP_ACCOUNTING

/*
 * All this stuff is protected with swap_lock
 */

void ub_swapentry_get(struct swap_info_struct *si, pgoff_t num,
		      struct user_beancounter *ub)
{
	rcu_assign_pointer(si->swap_ubs[num], ub);
	ub->ub_swapentries++;
}

void ub_swapentry_put(struct swap_info_struct *si, pgoff_t num)
{
	struct user_beancounter *ub = si->swap_ubs[num];

	rcu_assign_pointer(si->swap_ubs[num], NULL);
	ub->ub_swapentries--;
}

void ub_swapentry_charge(struct swap_info_struct *si, pgoff_t num)
{
	charge_beancounter_fast(si->swap_ubs[num], UB_SWAPPAGES, 1, UB_FORCE);
}

void ub_swapentry_uncharge(struct swap_info_struct *si, pgoff_t num)
{
	uncharge_beancounter_fast(si->swap_ubs[num], UB_SWAPPAGES, 1);
}

void ub_swapentry_recharge(struct swap_info_struct *si, pgoff_t num,
			   struct user_beancounter *new_ub)
{
	struct user_beancounter *ub;

	ub = si->swap_ubs[num];
	rcu_assign_pointer(si->swap_ubs[num], new_ub);
	ub->ub_swapentries--;
	new_ub->ub_swapentries++;
	if (!(si->swap_map[num] & SWAP_HAS_CACHE)) {
		uncharge_beancounter_fast(ub, UB_SWAPPAGES, 1);
		charge_beancounter_fast(new_ub, UB_SWAPPAGES, 1, UB_FORCE);
	}
}

int ub_swap_init(struct swap_info_struct *si, pgoff_t num)
{
	struct user_beancounter **ubs;

	ubs = vmalloc(num * sizeof(struct user_beancounter *));
	if (ubs == NULL)
		return -ENOMEM;

	memset(ubs, 0, num * sizeof(struct user_beancounter *));
	si->swap_ubs = ubs;
	return 0;
}

void ub_swap_fini(struct swap_info_struct *si)
{
	if (si->swap_ubs) {
		vfree(si->swap_ubs);
		si->swap_ubs = NULL;
	}
}
#endif

static int bc_fill_sysinfo(struct user_beancounter *ub,
		unsigned long meminfo_val, struct sysinfo *si)
{
	unsigned long used, total;
	unsigned long totalram, totalswap;

	/* No virtualization */
	if (meminfo_val == VE_MEMINFO_SYSTEM)
		return NOTIFY_DONE | NOTIFY_STOP_MASK;

	totalram = si->totalram;
	totalswap = si->totalswap;

	memset(si, 0, sizeof(*si));

	total = ub->ub_parms[UB_PHYSPAGES].limit;
	used = get_beancounter_usage_percpu(ub, UB_PHYSPAGES) + ub->ub_parms[UB_SHMPAGES].held;

	if (total == UB_MAXVALUE) {
		if (meminfo_val < VE_MEMINFO_NR_SPECIAL)
			total = totalram;
		else {
			total = min(meminfo_val, totalram);
			used = get_beancounter_usage_percpu(ub, UB_PRIVVMPAGES);
			if (glob_ve_meminfo) {
				ub_update_resources(ub);
				used = ub->ub_parms[UB_OOMGUARPAGES].held;
			}
		}
	}

	si->totalram = total;
	si->freeram = (total > used ? total - used : 0);

	total = ub->ub_parms[UB_SWAPPAGES].limit;
	used = get_beancounter_usage_percpu(ub, UB_SWAPPAGES);

	if (total == UB_MAXVALUE) {
		if (meminfo_val < VE_MEMINFO_NR_SPECIAL)
			total = totalswap;
		else
			total = 0;
	}

	si->totalswap = total;
	si->freeswap = (total > used ? total - used : 0);

	si->mem_unit = PAGE_SIZE;

	return NOTIFY_OK;
}

static int bc_fill_meminfo(struct user_beancounter *ub,
		unsigned long meminfo_val, struct meminfo *mi)
{
	int cpu, ret;
	long dcache, kmem;

	ret = bc_fill_sysinfo(ub, meminfo_val, mi->si);
	if (ret & NOTIFY_STOP_MASK)
		goto out;

	gang_page_stat(get_ub_gs(ub), true, NULL, mi->pages, mi->shadow);

	mi->locked = ub->ub_parms[UB_LOCKEDPAGES].held;
	mi->shmem = ub->ub_parms[UB_SHMPAGES].held;
	dcache = ub->ub_parms[UB_DCACHESIZE].held;
	kmem = ub->ub_parms[UB_KMEMSIZE].held;

	mi->dirty_pages = __ub_stat_get(ub, dirty_pages);
	mi->writeback_pages = __ub_stat_get(ub, writeback_pages);
	for_each_possible_cpu(cpu) {
		struct ub_percpu_struct *pcpu = ub_percpu(ub, cpu);

		mi->dirty_pages	+= pcpu->dirty_pages;
		mi->writeback_pages	+= pcpu->writeback_pages;
		dcache		-= pcpu->precharge[UB_DCACHESIZE];
		kmem		-= pcpu->precharge[UB_KMEMSIZE];
	}

	mi->dirty_pages = max_t(long, 0, mi->dirty_pages);
	mi->writeback_pages = max_t(long, 0, mi->writeback_pages);

	mi->slab_reclaimable = DIV_ROUND_UP(max(0L, dcache), PAGE_SIZE);
	mi->slab_unreclaimable =
		DIV_ROUND_UP(max(0L, kmem - dcache), PAGE_SIZE);

	mi->cached = min(mi->si->totalram - mi->si->freeram -
			mi->slab_reclaimable - mi->slab_unreclaimable,
			mi->pages[LRU_INACTIVE_FILE] +
			mi->pages[LRU_ACTIVE_FILE]);
out:
	return ret;
}

static int bc_fill_vmstat(struct user_beancounter *ub, unsigned long *stat)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		struct ub_percpu_struct *pcpu = ub_percpu(ub, cpu);

		stat[NR_VM_ZONE_STAT_ITEMS + PSWPIN]	+= pcpu->swapin;
		stat[NR_VM_ZONE_STAT_ITEMS + PSWPOUT]	+= pcpu->swapout;

		stat[NR_VM_ZONE_STAT_ITEMS + PSWPIN]	+= pcpu->vswapin;
		stat[NR_VM_ZONE_STAT_ITEMS + PSWPOUT]	+= pcpu->vswapout;
	}

	return NOTIFY_OK;
}

static int bc_mem_notify(struct vnotifier_block *self,
		unsigned long event, void *arg, int old_ret)
{
	switch (event) {
	case VIRTINFO_MEMINFO: {
		struct meminfo *mi = arg;
		return bc_fill_meminfo(mi->ub, mi->meminfo_val, mi);
	}
	case VIRTINFO_SYSINFO:
		return bc_fill_sysinfo(get_exec_ub_top(),
				get_exec_env()->meminfo_val, arg);
	case VIRTINFO_VMSTAT:
		return bc_fill_vmstat(get_exec_ub_top(), arg);
	};

	return old_ret;
}

static struct vnotifier_block bc_mem_notifier_block = {
	.notifier_call = bc_mem_notify,
};

static int __init init_vmguar_notifier(void)
{
	virtinfo_notifier_register(VITYPE_GENERAL, &bc_mem_notifier_block);
	return 0;
}

static void __exit fini_vmguar_notifier(void)
{
	virtinfo_notifier_unregister(VITYPE_GENERAL, &bc_mem_notifier_block);
}

module_init(init_vmguar_notifier);
module_exit(fini_vmguar_notifier);

static void __show_one_resource(const char *name, struct ubparm *parm)
{
	if (parm->limit == UB_MAXVALUE)
		printk("%s: %lu / inf [%lu] ", name,
				parm->held, parm->failcnt);
	else
		printk("%s: %lu / %lu [%lu] ", name,
				parm->held, parm->limit, parm->failcnt);
}

void __show_ub_mem(struct user_beancounter *ub)
{
	__show_one_resource("RAM", ub->ub_parms + UB_PHYSPAGES);
	__show_one_resource("SWAP", ub->ub_parms + UB_SWAPPAGES);
	__show_one_resource("KMEM", ub->ub_parms + UB_KMEMSIZE);
	__show_one_resource("DCSZ", ub->ub_parms + UB_DCACHESIZE);
	__show_one_resource("OOMG", ub->ub_parms + UB_OOMGUARPAGES);

	printk("Dirty %lu Wback %lu Dche %u Prnd %lu\n",
			ub_stat_get(ub, dirty_pages),
			ub_stat_get(ub, writeback_pages),
			ub->ub_dentry_unused, ub->ub_dentry_pruned);
}

void show_ub_mem(struct user_beancounter *ub)
{
	printk(KERN_INFO "UB-%d-Mem-Info:\n", ub->ub_uid);
	gang_show_state(get_ub_gs(ub));
	__show_ub_mem(ub);
}

#ifdef CONFIG_PROC_FS
static int bc_vmaux_show(struct seq_file *f, void *v)
{
	struct user_beancounter *ub, *iter;
	struct ub_percpu_struct *ub_pcpu;
	unsigned long swapin, swapout, vswapin, vswapout, phys_pages;
	unsigned long swapentries, tmpfs_respages, hugetlb_pages;
	unsigned long shadow_pages;
	int i;

	ub = seq_beancounter(f);

	swapin = swapout = vswapin = vswapout = 0;
	phys_pages = ub->ub_parms[UB_PHYSPAGES].held;
	shadow_pages = ub->ub_parms[UB_SHADOWPAGES].held;
	for_each_possible_cpu(i) {
		ub_pcpu = ub_percpu(ub, i);
		swapin += ub_pcpu->swapin;
		swapout += ub_pcpu->swapout;
		vswapin += ub_pcpu->vswapin;
		vswapout += ub_pcpu->vswapout;
		phys_pages -= ub_pcpu->precharge[UB_PHYSPAGES];
		shadow_pages -= ub_pcpu->precharge[UB_SHADOWPAGES];
	}

	swapentries = tmpfs_respages = hugetlb_pages = 0;
	for_each_beancounter_tree(iter, ub) {
		swapentries += iter->ub_swapentries;
		tmpfs_respages += iter->ub_tmpfs_respages;
		hugetlb_pages += iter->ub_hugetlb_pages;
	}

	phys_pages = max_t(long, 0, phys_pages);
	shadow_pages = max_t(long, 0, shadow_pages);

	seq_printf(f, bc_proc_lu_fmt, "tmpfs_respages", tmpfs_respages);

	seq_printf(f, bc_proc_lu_fmt, "swapin", swapin);
	seq_printf(f, bc_proc_lu_fmt, "swapout", swapout);

	seq_printf(f, bc_proc_lu_fmt, "vswapin", vswapin);
	seq_printf(f, bc_proc_lu_fmt, "vswapout", vswapout);

	seq_printf(f, bc_proc_lu_fmt, "ram", phys_pages);
	seq_printf(f, bc_proc_lu_fmt, "shadow", shadow_pages);
	seq_printf(f, bc_proc_lu_fmt, "swap_entries", swapentries);

	seq_printf(f, bc_proc_lu_fmt, "hugetlb", hugetlb_pages);

	return 0;
}
static struct bc_proc_entry bc_vmaux_entry = {
	.name = "vmaux",
	.u.show = bc_vmaux_show,
};

static int __init bc_vmaux_init(void)
{
	bc_register_proc_entry(&bc_vmaux_entry);
	return 0;
}

late_initcall(bc_vmaux_init);
#endif
