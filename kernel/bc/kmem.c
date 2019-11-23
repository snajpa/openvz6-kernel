/*
 *  kernel/bc/kmem.c
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/swap.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/init.h>

#include <bc/beancounter.h>
#include <bc/oom_kill.h>
#include <bc/vmpages.h>
#include <bc/dcache.h>
#include <bc/kmem.h>
#include <bc/proc.h>

int __ub_kmem_charge(struct user_beancounter *ub,
		unsigned long size, gfp_t gfp_mask)
{
	unsigned long pages, charge, flags;
	int kmem_strict, phys_strict;
	int do_precharge = 1;
	int failres;

	charge = size + (ub->ub_parms[UB_KMEMSIZE].max_precharge >> 1);
	pages = PAGE_ALIGN(charge) >> PAGE_SHIFT;

	phys_strict = UB_SOFT | UB_TEST;
	kmem_strict = ub_gfp_sev(gfp_mask) | UB_TEST;

	if (unlikely(gfp_mask & __GFP_NOFAIL)) {
		kmem_strict = phys_strict = UB_FORCE | UB_TEST;
		goto no_precharge;
	}

	if (unlikely(irqs_disabled() || !(gfp_mask & __GFP_WAIT))) {
		phys_strict = UB_FORCE | UB_TEST;
		goto no_precharge;
	}

	ub_oom_start(&ub->oom_ctrl);

try_again:
	failres = UB_PHYSPAGES;
	while (charge_beancounter_fast(ub, UB_PHYSPAGES, pages, phys_strict)) {
		if (test_thread_flag(TIF_MEMDIE) ||
		    fatal_signal_pending(current)) {
			do_precharge = 0;
			goto no_precharge;
		} else if (!ub_try_to_free_pages(ub, gfp_mask))
			continue;
		goto no_precharge;
	}

	failres = UB_KMEMSIZE;
	charge = pages << PAGE_SHIFT;
	spin_lock_irqsave(&ub->ub_lock, flags);
	while (__charge_beancounter_locked(ub, UB_KMEMSIZE, charge, kmem_strict)) {
		init_beancounter_precharge(ub, UB_KMEMSIZE);
		spin_unlock_irqrestore(&ub->ub_lock, flags);
		if (ub_dcache_shrink(ub, charge, gfp_mask)) {
			uncharge_beancounter(ub, UB_PHYSPAGES, pages);
			goto no_precharge;
		}
		spin_lock_irqsave(&ub->ub_lock, flags);
	}
	ub_percpu(ub, smp_processor_id())->
		precharge[UB_KMEMSIZE] += charge - size;
	spin_unlock_irqrestore(&ub->ub_lock, flags);

	return 0;

no_precharge:
	if (do_precharge) {
		do_precharge = 0;
		pages = PAGE_ALIGN(size) >> PAGE_SHIFT;
		goto try_again;
	}

	spin_lock_irqsave(&ub->ub_lock, flags);
	ub->ub_parms[failres].failcnt++;
	spin_unlock_irqrestore(&ub->ub_lock, flags);

	if (__ratelimit(&ub->ub_ratelimit))
		printk(KERN_INFO "Fatal resource shortage: %s, UB %d.\n",
				ub_rnames[failres], ub->ub_uid);

	return -ENOMEM;
}
EXPORT_SYMBOL(__ub_kmem_charge);

void __ub_kmem_uncharge(struct user_beancounter *ub,
		struct ub_percpu_struct *ub_pcpu,
		unsigned long size)
{
	unsigned long uncharge;

	spin_lock(&ub->ub_lock);

	if (ub->ub_parms[UB_KMEMSIZE].max_precharge !=
			ub_resource_precharge[UB_KMEMSIZE])
		init_beancounter_precharge(ub, UB_KMEMSIZE);

	if (!__try_uncharge_beancounter_percpu(ub, ub_pcpu, UB_KMEMSIZE, size))
		goto out;

	uncharge = (size + ub_pcpu->precharge[UB_KMEMSIZE]
			- (ub->ub_parms[UB_KMEMSIZE].max_precharge >> 1)
		   ) & PAGE_MASK;
	ub_pcpu->precharge[UB_KMEMSIZE] += size - uncharge;
	__uncharge_beancounter_locked(ub, UB_KMEMSIZE, uncharge);
	__uncharge_beancounter_locked(ub, UB_PHYSPAGES, uncharge >> PAGE_SHIFT);

out:
	spin_unlock(&ub->ub_lock);
}
EXPORT_SYMBOL(__ub_kmem_uncharge);

int ub_slab_charge(struct kmem_cache *cachep, void *objp, gfp_t flags)
{
	unsigned int size;
	struct user_beancounter *ub;

	ub = get_beancounter(get_exec_ub_top());
	if (ub == NULL)
		return 0;

	size = CHARGE_SIZE(kmem_cache_objuse(cachep));
	if (ub_kmem_charge(ub, size, flags))
		goto out_err;

	*ub_slab_ptr(cachep, objp) = ub;
	return 0;

out_err:
	put_beancounter(ub);
	return -ENOMEM;
}

void ub_slab_uncharge(struct kmem_cache *cachep, void *objp)
{
	unsigned int size;
	struct user_beancounter **ub_ref;

	ub_ref = ub_slab_ptr(cachep, objp);
	if (*ub_ref == NULL)
		return;

	size = CHARGE_SIZE(kmem_cache_objuse(cachep));
	ub_kmem_uncharge(*ub_ref, size);
	put_beancounter(*ub_ref);
	*ub_ref = NULL;
}

/* 
 * takes init_mm.page_table_lock 
 * some outer lock to protect pages from vmalloced area must be held
 */
struct user_beancounter *vmalloc_ub(void *obj)
{
	struct page *pg;

	pg = vmalloc_to_page(obj);
	if (pg == NULL)
		return NULL;

	return page_kmem_ub(pg);
}

EXPORT_SYMBOL(vmalloc_ub);

struct user_beancounter *mem_ub(void *obj)
{
	struct user_beancounter *ub;

	if ((unsigned long)obj >= VMALLOC_START &&
	    (unsigned long)obj  < VMALLOC_END)
		ub = vmalloc_ub(obj);
	else
		ub = slab_ub(obj);

	return ub;
}

EXPORT_SYMBOL(mem_ub);
