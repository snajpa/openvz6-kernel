/*
 *  include/bc/vmpages.h
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#ifndef __UB_PAGES_H_
#define __UB_PAGES_H_

#include <linux/linkage.h>
#include <linux/sched.h>	/* for get_exec_ub() */
#include <linux/mm.h>
#include <bc/beancounter.h>
#include <bc/decl.h>

extern int glob_ve_meminfo;

/*
 * Check whether vma has private or copy-on-write mapping.
 */
#define VM_UB_PRIVATE(__flags, __file)					\
		( ((__flags) & VM_WRITE) ?				\
			(__file) == NULL || !((__flags) & VM_SHARED) :	\
			0						\
		)

UB_DECLARE_FUNC(int, ub_memory_charge(struct mm_struct *mm,
			unsigned long size,
			unsigned vm_flags,
			struct file *vm_file,
			int strict))
UB_DECLARE_VOID_FUNC(ub_memory_uncharge(struct mm_struct *mm,
			unsigned long size,
			unsigned vm_flags,
			struct file *vm_file))

struct shmem_inode_info;
UB_DECLARE_VOID_FUNC(ub_tmpfs_respages_inc(struct shmem_inode_info *shi))
UB_DECLARE_VOID_FUNC(ub_tmpfs_respages_sub(struct shmem_inode_info *shi,
			unsigned long size))
#define ub_tmpfs_respages_dec(shi)	ub_tmpfs_respages_sub(shi, 1)

UB_DECLARE_FUNC(int, ub_locked_charge(struct mm_struct *mm,
			unsigned long size))
UB_DECLARE_VOID_FUNC(ub_locked_uncharge(struct mm_struct *mm,
			unsigned long size))
UB_DECLARE_FUNC(int, ub_lockedshm_charge(struct shmem_inode_info *shi,
			unsigned long size))
UB_DECLARE_VOID_FUNC(ub_lockedshm_uncharge(struct shmem_inode_info *shi,
			unsigned long size))

extern void __ub_update_oomguarpages(struct user_beancounter *ub);

static inline int ub_swap_full(struct user_beancounter *ub)
{
	return (ub->ub_parms[UB_SWAPPAGES].held * 2 >
			ub->ub_parms[UB_SWAPPAGES].limit);
}


struct swap_info_struct;

#ifdef CONFIG_BC_SWAP_ACCOUNTING

extern int ub_swap_init(struct swap_info_struct *si, pgoff_t num);
extern void ub_swap_fini(struct swap_info_struct *si);
extern void ub_swapentry_get(struct swap_info_struct *si, pgoff_t offset,
			     struct user_beancounter *ub);
extern void ub_swapentry_put(struct swap_info_struct *si, pgoff_t offset);
extern void ub_swapentry_charge(struct swap_info_struct *si, pgoff_t offset);
extern void ub_swapentry_uncharge(struct swap_info_struct *si, pgoff_t offset);
extern void ub_swapentry_recharge(struct swap_info_struct *si, pgoff_t offset,
				  struct user_beancounter *new_ub);

#else /* CONFIG_BC_SWAP_ACCOUNTING */

static inline int ub_swap_init(struct swap_info_struct *si, pgoff_t num)
{
	return 0;
}
static inline void ub_swap_fini(struct swap_info_struct *si) { }
static inline void ub_swapentry_get(struct swap_info_struct *si, pgoff_t offset,
			     struct user_beancounter *ub) { }
static inline void ub_swapentry_put(struct swap_info_struct *si, pgoff_t offset) { }
static inline void ub_swapentry_charge(struct swap_info_struct *si, pgoff_t offset) { }
static inline void ub_swapentry_uncharge(struct swap_info_struct *si, pgoff_t offset) { }
static inline void ub_swapentry_recharge(struct swap_info_struct *si, pgoff_t offset,
					 struct user_beancounter *new_ub) { }

#endif /* CONFIG_BC_SWAP_ACCOUNTING */


#ifdef CONFIG_BC_RSS_ACCOUNTING

int ub_hugetlb_charge(struct user_beancounter *ub, struct page *page);
void ub_hugetlb_uncharge(struct page *page);

int ub_try_to_free_pages(struct user_beancounter *ub, gfp_t gfp_mask);

extern int ub_phys_charge(struct user_beancounter *ub,
		unsigned long pages, gfp_t gfp_mask);

static inline void ub_phys_uncharge(struct user_beancounter *ub,
		unsigned long pages)
{
	uncharge_beancounter_fast(ub, UB_PHYSPAGES, pages);
}

int ub_check_ram_limits_size(struct user_beancounter *ub,
			     gfp_t gfp_mask, int size);

static inline int ub_check_ram_limits(struct user_beancounter *ub, gfp_t gfp_mask)
{
	return ub_check_ram_limits_size(ub, gfp_mask, 1);
}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
static inline int ub_precharge_hpage(struct mm_struct *mm)
{
	return ub_check_ram_limits_size(mm_ub(mm), GFP_TRANSHUGE, HPAGE_PMD_NR);
}
#endif

#else /* CONFIG_BC_RSS_ACCOUNTING */

static inline int ub_try_to_free_pages(struct user_beancounter *ub, gfp_t gfp_mask)
{
	return -ENOSYS;
}

static inline int ub_phys_charge(struct user_beancounter *ub,
		unsigned long pages, gfp_t gfp_mask)
{
	return charge_beancounter_fast(ub, UB_PHYSPAGES, pages, UB_FORCE);
}

static inline void ub_phys_uncharge(struct user_beancounter *ub,
		unsigned long pages)
{
	uncharge_beancounter_fast(ub, UB_PHYSPAGES, pages);
}

static inline int ub_check_ram_limits(struct user_beancounter *ub, gfp_t gfp_mask)
{
	return 0;
}

static inline int ub_precharge_hpage(struct mm_struct *mm)
{
	return 0;
}
#endif /* CONFIG_BC_RSS_ACCOUNTING */

void __show_ub_mem(struct user_beancounter *ub);
void show_ub_mem(struct user_beancounter *ub);

#endif /* __UB_PAGES_H_ */
