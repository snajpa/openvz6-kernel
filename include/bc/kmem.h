/*
 *  include/bc/kmem.h
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#ifndef __UB_SLAB_H_
#define __UB_SLAB_H_

#include <bc/beancounter.h>
#include <bc/decl.h>

/*
 * UB_KMEMSIZE accounting
 */

#ifdef CONFIG_BC_DEBUG_ITEMS
#define CHARGE_ORDER(__o)		(1 << (__o))
#define CHARGE_SIZE(__s)		1
#else
#define CHARGE_ORDER(__o)		(PAGE_SIZE << (__o))
#define CHARGE_SIZE(__s)		(__s)
#endif

struct mm_struct;
struct page;
struct kmem_cache;

UB_DECLARE_FUNC(struct user_beancounter *, vmalloc_ub(void *obj))
UB_DECLARE_FUNC(struct user_beancounter *, mem_ub(void *obj))

UB_DECLARE_FUNC(int, ub_slab_charge(struct kmem_cache *cachep,
			void *objp, gfp_t flags))
UB_DECLARE_VOID_FUNC(ub_slab_uncharge(struct kmem_cache *cachep, void *obj))

static inline struct user_beancounter* page_kmem_ub(struct page *page)
{
	return page->kmem_ub;
}

static inline enum ub_severity ub_gfp_sev(gfp_t gfp_mask)
{
	return (gfp_mask & __GFP_SOFT_UBC) ? UB_SOFT : UB_HARD;
}

extern int __ub_kmem_charge(struct user_beancounter *ub,
		unsigned long size, gfp_t gfp_mask);
extern void __ub_kmem_uncharge(struct user_beancounter *ub,
		struct ub_percpu_struct *ub_pcpu,
		unsigned long size);

static inline int ub_kmem_charge(struct user_beancounter *ub,
		unsigned long size, gfp_t gfp_mask)
{
	struct ub_percpu_struct *ub_pcpu;
	unsigned long flags;

	local_irq_save(flags);
	ub_pcpu = ub_percpu(ub, smp_processor_id());
	if (__try_charge_beancounter_percpu(ub, ub_pcpu, UB_KMEMSIZE, size)) {
		local_irq_restore(flags);
		return __ub_kmem_charge(ub, size, gfp_mask);
	}
	local_irq_restore(flags);
	return 0;
}

static inline void ub_kmem_uncharge(struct user_beancounter *ub,
		unsigned long size)
{
	struct ub_percpu_struct *ub_pcpu;
	unsigned long flags;

	local_irq_save(flags);
	ub_pcpu = ub_percpu(ub, smp_processor_id());
	if (__try_uncharge_beancounter_percpu(ub, ub_pcpu, UB_KMEMSIZE, size))
		__ub_kmem_uncharge(ub, ub_pcpu, size);
	local_irq_restore(flags);
}

static inline int ub_page_charge(struct page *page, int order,
		struct user_beancounter *ub, gfp_t gfp_mask)
{
	if (ub_kmem_charge(ub, CHARGE_ORDER(order), gfp_mask))
		return -ENOMEM;

	BUG_ON(page->kmem_ub != NULL);
	page->kmem_ub = get_beancounter(ub);
	return 0;
}

static inline void ub_page_uncharge(struct page *page, int order)
{
	struct user_beancounter *ub = page->kmem_ub;

	if (likely(ub == NULL))
		return;

	page->kmem_ub = NULL;
	BUG_ON(ub->ub_magic != UB_MAGIC);
	ub_kmem_uncharge(ub, CHARGE_ORDER(order));
	put_beancounter(ub);
}

static inline int ub_page_table_get_one(struct mm_struct *mm)
{
	if (mm->page_table_precharge)
		return 0;
	if (ub_kmem_charge(mm_ub_top(mm), PAGE_SIZE,
				GFP_KERNEL | __GFP_SOFT_UBC))
		return -ENOMEM;
	return 1;
}

static inline void ub_page_table_put_one(struct mm_struct *mm, int one)
{
	if (one)
		ub_kmem_uncharge(mm_ub_top(mm), PAGE_SIZE);
}

static inline int ub_page_table_charge(struct mm_struct *mm, int one)
{
	if (one)
		return 0;
	if (unlikely(mm->page_table_precharge == 0))
		return ub_kmem_charge(mm_ub_top(mm), PAGE_SIZE,
				GFP_ATOMIC | __GFP_SOFT_UBC);
	mm->page_table_precharge--;
	return 0;
}

static inline void ub_page_table_uncharge(struct mm_struct *mm)
{
	mm->page_table_precharge++;
}

static inline int ub_page_table_precharge(struct mm_struct *mm, long precharge)
{
	if (ub_kmem_charge(mm_ub_top(mm), precharge << PAGE_SHIFT,
				GFP_KERNEL | __GFP_SOFT_UBC))
		return -ENOMEM;
	mm->page_table_precharge += precharge;
	return 0;
}

static inline void ub_page_table_commit(struct mm_struct *mm)
{
	if (unlikely(mm->page_table_precharge)) {
		ub_kmem_uncharge(mm_ub_top(mm),
				mm->page_table_precharge << PAGE_SHIFT);
		mm->page_table_precharge = 0;
	}
}

static inline void *ub_kmem_alloc(struct user_beancounter *ub,
		struct kmem_cache *cachep, gfp_t gfp_flags)
{
	void *objp;

	if (ub_kmem_charge(ub, cachep->objuse, gfp_flags))
		return NULL;

	objp = kmem_cache_alloc(cachep, gfp_flags);

	if (unlikely(objp == NULL))
		ub_kmem_uncharge(ub, cachep->objuse);

	return objp;
}

static inline void ub_kmem_free(struct user_beancounter *ub,
		struct kmem_cache *cachep, void *objp)
{
	kmem_cache_free(cachep, objp);
	ub_kmem_uncharge(ub, cachep->objuse);
}

#ifdef CONFIG_BEANCOUNTERS
static inline int should_charge(unsigned long cflags, gfp_t flags)
{
	if (!(cflags & SLAB_UBC))
		return 0;
	if ((cflags & SLAB_NO_CHARGE) && !(flags & __GFP_UBC))
		return 0;
	return 1;
}

#define should_uncharge(cflags)	should_charge(cflags, __GFP_UBC)
#else
#define should_charge(cflags, f)	0
#define should_uncharge(cflags)		0
#endif

#endif /* __UB_SLAB_H_ */
