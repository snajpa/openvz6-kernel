/*
 *  linux/mm/swap_state.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *  Swap reorganised 29.12.95, Stephen Tweedie
 *
 *  Rewritten to use page cache, (C) 1998 Stephen Tweedie
 */
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/rmap.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/init.h>
#include <linux/pagemap.h>
#include <linux/buffer_head.h>
#include <linux/backing-dev.h>
#include <linux/pagevec.h>
#include <linux/migrate.h>
#include <linux/page_cgroup.h>
#include <linux/mmgang.h>

#include <asm/pgtable.h>

#include <bc/vmpages.h>
#include <bc/io_acct.h>
#include <bc/kmem.h>

/*
 * swapper_space is a fiction, retained to simplify the path through
 * vmscan's shrink_page_list, to make sync_page look nicer, and to allow
 * future use of radix_tree tags in the swap cache.
 */
static const struct address_space_operations swap_aops = {
	.writepage	= swap_writepage,
	.sync_page	= block_sync_page,
	.set_page_dirty	= __set_page_dirty_nobuffers,
	.migratepage	= migrate_page,
};

static struct backing_dev_info swap_backing_dev_info = {
	.name		= "swap",
	.capabilities	= BDI_CAP_NO_ACCT_AND_WRITEBACK | BDI_CAP_SWAP_BACKED,
	.unplug_io_fn	= swap_unplug_io_fn,
};

struct address_space swapper_space = {
	.page_tree	= RADIX_TREE_INIT(GFP_ATOMIC|__GFP_NOWARN),
	.tree_lock	= __SPIN_LOCK_UNLOCKED(swapper_space.tree_lock),
	.a_ops		= &swap_aops,
	.i_mmap_nonlinear = LIST_HEAD_INIT(swapper_space.i_mmap_nonlinear),
	.backing_dev_info = &swap_backing_dev_info,
};
EXPORT_SYMBOL(swapper_space);

#define INC_CACHE_INFO(x)	do { swap_cache_info.x++; } while (0)

struct {
	unsigned long add_total;
	unsigned long del_total;
	unsigned long find_success;
	unsigned long find_total;
} swap_cache_info;
EXPORT_SYMBOL(swap_cache_info);

void show_swap_cache_info(void)
{
	printk("%lu pages in swap cache\n", total_swapcache_pages);
	printk("Swap cache stats: add %lu, delete %lu, find %lu/%lu\n",
		swap_cache_info.add_total, swap_cache_info.del_total,
		swap_cache_info.find_success, swap_cache_info.find_total);
	printk("Free swap  = %ldkB\n",
	       get_nr_swap_pages() << (PAGE_SHIFT - 10));
	printk("Total swap = %lukB\n", total_swap_pages << (PAGE_SHIFT - 10));
}

/*
 * __add_to_swap_cache resembles add_to_page_cache_locked on swapper_space,
 * but sets SwapCache flag and private instead of mapping and index.
 */
int __add_to_swap_cache(struct page *page, swp_entry_t entry)
{
	int error;

	VM_BUG_ON(!PageLocked(page));
	VM_BUG_ON(PageSwapCache(page));
	VM_BUG_ON(!PageSwapBacked(page));

	page_cache_get(page);
	SetPageSwapCache(page);
	set_page_private(page, entry.val);

	spin_lock_irq(&swapper_space.tree_lock);
	error = radix_tree_insert(&swapper_space.page_tree, entry.val, page);
	if (likely(!error)) {
		total_swapcache_pages++;
		__inc_zone_page_state(page, NR_FILE_PAGES);
		INC_CACHE_INFO(add_total);
	}
	spin_unlock_irq(&swapper_space.tree_lock);

	if (unlikely(error)) {
		/*
		 * Only the context which have set SWAP_HAS_CACHE flag
		 * would call add_to_swap_cache().
		 * So add_to_swap_cache() doesn't returns -EEXIST.
		 */
		VM_BUG_ON(error == -EEXIST);
		set_page_private(page, 0UL);
		ClearPageSwapCache(page);
		page_cache_release(page);
	}

	return error;
}
EXPORT_SYMBOL(__add_to_swap_cache);

int add_to_swap_cache(struct page *page, swp_entry_t entry, gfp_t gfp_mask)
{
	int error;

	error = radix_tree_maybe_preload(gfp_mask);
	if (!error) {
		error = __add_to_swap_cache(page, entry);
		radix_tree_preload_end();
	}
	return error;
}
EXPORT_SYMBOL(add_to_swap_cache);

/*
 * This must be called only on pages that have
 * been verified to be in the swap cache.
 */
void __delete_from_swap_cache(struct page *page)
{
	VM_BUG_ON(!PageLocked(page));
	VM_BUG_ON(!PageSwapCache(page));
	VM_BUG_ON(PageWriteback(page));

	radix_tree_delete(&swapper_space.page_tree, page_private(page));
	set_page_private(page, 0);
	ClearPageSwapCache(page);
	total_swapcache_pages--;
	__dec_zone_page_state(page, NR_FILE_PAGES);
	INC_CACHE_INFO(del_total);
}

/**
 * add_to_swap - allocate swap space for a page
 * @page: page we want to move to swap
 * @ub: user_beancounter to charge swap-entry
 *
 * Allocate swap space for the page and add the page to the
 * swap cache.  Caller needs to hold the page lock. 
 */
int add_to_swap(struct page *page, struct user_beancounter *ub)
{
	swp_entry_t entry;
	int err;

	VM_BUG_ON(!PageLocked(page));
	VM_BUG_ON(!PageUptodate(page));

	entry = get_swap_page(ub);
	if (!entry.val)
		return 0;

	if (unlikely(PageTransHuge(page)))
		if (unlikely(split_huge_page(page))) {
			swapcache_free(entry, NULL);
			return 0;
		}

	if (PageVSwap(page) && remove_from_vswap(page)) {
		swapcache_free(entry, NULL);
		return 0;
	}

	/*
	 * Radix-tree node allocations from PF_MEMALLOC contexts could
	 * completely exhaust the page allocator. __GFP_NOMEMALLOC
	 * stops emergency reserves from being allocated.
	 *
	 * TODO: this could cause a theoretical memory reclaim
	 * deadlock in the swap out path.
	 */
	/*
	 * Add it to the swap cache and mark it dirty
	 */
	err = add_to_swap_cache(page, entry,
			__GFP_HIGH|__GFP_NOMEMALLOC|__GFP_NOWARN);

	if (!err) {	/* Success */
		SetPageDirty(page);
		return 1;
	} else {	/* -ENOMEM radix-tree allocation failure */
		/*
		 * add_to_swap_cache() doesn't return -EEXIST, so we can safely
		 * clear SWAP_HAS_CACHE flag.
		 */
		swapcache_free(entry, NULL);
		return 0;
	}
}
EXPORT_SYMBOL(add_to_swap);

/*
 * This must be called only on pages that have
 * been verified to be in the swap cache and locked.
 * It will never put the page into the free list,
 * the caller has a reference on the page.
 */
void delete_from_swap_cache(struct page *page)
{
	swp_entry_t entry;

	entry.val = page_private(page);

	spin_lock_irq(&swapper_space.tree_lock);
	__delete_from_swap_cache(page);
	spin_unlock_irq(&swapper_space.tree_lock);

	swapcache_free(entry, page);
	page_cache_release(page);
}
EXPORT_SYMBOL(delete_from_swap_cache);

/* 
 * If we are the only user, then try to free up the swap cache. 
 * 
 * Its ok to check for PageSwapCache without the page lock
 * here because we are going to recheck again inside
 * try_to_free_swap() _with_ the lock.
 * 					- Marcelo
 */
static inline void free_swap_cache(struct page *page)
{
	if (PageSwapCache(page) && !page_mapped(page) && trylock_page(page)) {
		try_to_free_swap(page);
		unlock_page(page);
	}
}

/* 
 * Perform a free_page(), also freeing any swap cache associated with
 * this page if it is the last user of the page.
 */
void free_page_and_swap_cache(struct page *page)
{
	free_swap_cache(page);
	page_cache_release(page);
}

/*
 * Passed an array of pages, drop them all from swapcache and then release
 * them.  They are removed from the LRU and freed if this is their last use.
 */
void free_pages_and_swap_cache(struct page **pages, int nr)
{
	struct page **pagep = pages;

	lru_add_drain();
	while (nr) {
		int todo = min(nr, PAGEVEC_SIZE);
		int i;

		for (i = 0; i < todo; i++)
			free_swap_cache(pagep[i]);
		release_pages(pagep, todo, 0);
		pagep += todo;
		nr -= todo;
	}
}

/*
 * Lookup a swap entry in the swap cache. A found page will be returned
 * unlocked and with its refcount incremented - we rely on the kernel
 * lock getting page table operations atomic even if we drop the page
 * lock before returning.
 */
struct page * lookup_swap_cache(swp_entry_t entry)
{
	struct page *page;

	page = find_get_page(&swapper_space, entry.val);

	if (page)
		INC_CACHE_INFO(find_success);

	INC_CACHE_INFO(find_total);
	return page;
}

static struct user_beancounter *get_swapin_ub(struct page *page,
					      swp_entry_t entry,
					      struct vm_area_struct *vma)
{
	struct user_beancounter *ub;

#ifdef CONFIG_BC_SWAP_ACCOUNTING
	rcu_read_lock();
	ub = get_swap_ub(entry);
	if (!ub || !get_beancounter_rcu(ub)) {
		/* speedup unuse pass */
		if (ub)
			ub_unuse_swap_page(page);
		ub = get_beancounter(get_exec_ub());
	}
	rcu_read_unlock();
#else
	/* can be NULL for shmem, see shmem_swapin() */
	if (vma && vma->vm_mm)
		ub = mm_ub(vma->vm_mm);
	else
		ub = get_exec_ub();
	get_beancounter(ub);
#endif

	return ub;
}

/* 
 * Locate a page of swap in physical memory, reserving swap cache space
 * and reading the disk if it is not already cached.
 * A failure return means that either the page allocation failed or that
 * the swap entry is no longer in use.
 */
struct page *read_swap_cache_async(swp_entry_t entry, gfp_t gfp_mask,
			struct vm_area_struct *vma, unsigned long addr)
{
	struct page *found_page, *new_page = NULL;
	int err;
	struct user_beancounter *ub;
	gfp_t charge_gfp = gfp_mask;

	/*
	 * A process performing swapin readahead can try to charge a page to a
	 * ub different from mm_ub. Generally, it is OK, but if the process is
	 * responsible for cleaning ub memory (e.g. pstorage) it might get
	 * stuck in reclaimer waiting for a page to be written back. To avoid
	 * that, we force charge readahead pages if the current process is in
	 * ub0.
	 */
	if (get_exec_ub() == get_ub0())
		charge_gfp |= __GFP_NOFAIL;

	do {
		/*
		 * First check the swap cache.  Since this is normally
		 * called after lookup_swap_cache() failed, re-calling
		 * that would confuse statistics.
		 */
		found_page = find_get_page(&swapper_space, entry.val);
		if (found_page)
			break;

		/*
		 * Get a new page to read into from swap.
		 */
		if (!new_page) {
			new_page = alloc_page_vma(gfp_mask, vma, addr);
			if (!new_page)
				break;		/* Out of memory */

			ub = get_swapin_ub(new_page, entry, vma);
			err = gang_add_user_page(new_page, get_ub_gs(ub),
						 charge_gfp);
			put_beancounter(ub);
			if (err)
				break;
		}

		/*
		 * call radix_tree_preload() while we can wait.
		 */
		err = radix_tree_maybe_preload(gfp_mask & GFP_KERNEL);
		if (err)
			break;

		/*
		 * Swap entry may have been freed since our caller observed it.
		 */
		err = swapcache_prepare(entry);
		if (err == -EEXIST) {
			radix_tree_preload_end();
			/*
			 * We might race against get_swap_page() and stumble
			 * across a SWAP_HAS_CACHE swap_map entry whose page
			 * has not been brought into the swapcache yet, while
			 * the other end is scheduled away waiting on discard
			 * I/O completion at scan_swap_map().
			 *
			 * In order to avoid turning this transitory state
			 * into a permanent loop around this -EEXIST case
			 * if !CONFIG_PREEMPT and the I/O completion happens
			 * to be waiting on the CPU waitqueue where we are now
			 * busy looping, we just conditionally invoke the
			 * scheduler here, if there are some more important
			 * tasks to run.
			 */
			cond_resched();
			continue;
		}
		if (err) {		/* swp entry is obsolete ? */
			radix_tree_preload_end();
			break;
		}

		/* May fail (-ENOMEM) if radix-tree node allocation failed. */
		__set_page_locked(new_page);
		SetPageSwapBacked(new_page);
		err = __add_to_swap_cache(new_page, entry);
		if (likely(!err)) {
			radix_tree_preload_end();
			/*
			 * Initiate read into locked page and return.
			 */
			lru_cache_add_anon(new_page);
			swap_readpage(new_page);
			return new_page;
		}
		radix_tree_preload_end();
		ClearPageSwapBacked(new_page);
		__clear_page_locked(new_page);
		/*
		 * add_to_swap_cache() doesn't return -EEXIST, so we can safely
		 * clear SWAP_HAS_CACHE flag.
		 */
		swapcache_free(entry, NULL);
	} while (err != -ENOMEM);

	if (new_page) {
		if (page_gang(new_page))
			gang_del_user_page(new_page);
		page_cache_release(new_page);
	}
	return found_page;
}
EXPORT_SYMBOL(read_swap_cache_async);

/**
 * swapin_readahead - swap in pages in hope we need them soon
 * @entry: swap entry of this memory
 * @gfp_mask: memory allocation flags
 * @vma: user vma this address belongs to
 * @addr: target address for mempolicy
 *
 * Returns the struct page for entry and addr, after queueing swapin.
 *
 * Primitive swap readahead code. We simply read an aligned block of
 * (1 << page_cluster) entries in the swap area. This method is chosen
 * because it doesn't cost us any seek time.  We also make sure to queue
 * the 'original' request together with the readahead ones...
 *
 * This has been extended to use the NUMA policies from the mm triggering
 * the readahead.
 *
 * Caller must hold down_read on the vma->vm_mm if vma is not NULL.
 */
struct page *swapin_readahead(swp_entry_t entry, gfp_t gfp_mask,
			struct vm_area_struct *vma, unsigned long addr)
{
	int nr_pages;
	struct page *page;
	unsigned long offset;
	unsigned long end_offset;

	/*
	 * Get starting offset for readaround, and number of pages to read.
	 * Adjust starting address by readbehind (for NUMA interleave case)?
	 * No, it's very unlikely that swap layout would follow vma layout,
	 * more likely that neighbouring swap pages came from the same node:
	 * so use the same "addr" to choose the same node for each swap read.
	 */
	nr_pages = valid_swaphandles(entry, &offset);
	for (end_offset = offset + nr_pages; offset < end_offset; offset++) {
		/* Ok, do the async read-ahead now */
		page = read_swap_cache_async(swp_entry(swp_type(entry), offset),
						gfp_mask, vma, addr);
		if (!page)
			break;
		page_cache_release(page);
	}
	lru_add_drain();	/* Push any new pages onto the LRU now */
	return read_swap_cache_async(entry, gfp_mask, vma, addr);
}

#ifdef CONFIG_MEMORY_VSWAP

static int __add_to_vswap(struct page *page)
{
	VM_BUG_ON(!PageLocked(page));
	VM_BUG_ON(PageSwapCache(page));

	if (PageVSwap(page)) {
		if (atomic_inc_not_zero(&page->vswap_count))
			return 1;
		/*
		 * wait for put_vswap_page() completion,
		 * see note in __remove_from_vswap()
		 */
		while (PageVSwap(page))
			cpu_relax();
	}

	if (unlikely(PageTransHuge(page)) && split_huge_page(page))
		return 0;

	atomic_set(&page->vswap_count, 1);
	SetPageVSwap(page);
	inc_zone_page_state(page, NR_VSWAP);
	return 1;
}

int add_to_vswap(struct page *page)
{
	int ret = SWAP_FAIL;

	if (__add_to_vswap(page)) {
		ret = try_to_unmap(page, TTU_VSWAP);
		put_vswap_page(page);
	}
	return ret;
}

void __remove_from_vswap(struct page *page)
{
	/*
	 * Either in atomic -- under pte-lock
	 * or in add_to_vswap() under page-lock.
	 */
	VM_BUG_ON(!in_atomic() && !PageLocked(page));
	__dec_zone_page_state(page, NR_VSWAP);
	ClearPageVSwap(page);
}

static int remove_vswap_pte(struct page *page, struct vm_area_struct *vma,
			    unsigned long addr, void *data)
{
	struct mm_struct *mm = vma->vm_mm;
	int ret = SWAP_AGAIN;
	swp_entry_t entry;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep, pte;
	spinlock_t *ptl;

	pgd = pgd_offset(mm, addr);
	if (!pgd_present(*pgd))
		goto out;

	pud = pud_offset(pgd, addr);
	if (!pud_present(*pud))
		goto out;

	pmd = pmd_offset(pud, addr);
	if (!pmd_present(*pmd) || pmd_trans_huge(*pmd))
		goto out;

	ptep = pte_offset_map_lock(mm, pmd, addr, &ptl);
	pte = *ptep;

	if (!is_swap_pte(pte))
		goto out_unlock;

	entry = pte_to_swp_entry(pte);
	if (!is_vswap_entry(entry) || vswap_entry_to_page(entry) != page)
		goto out_unlock;

	pte = mk_pte(page, vma->vm_page_prot);
	if (is_write_vswap_entry(entry)) {
		pte = pte_mkwrite(pte);
		ClearPageCheckpointed(page);
	}
	inc_mm_counter(mm, anon_rss);
	dec_mm_counter(mm, swap_usage);

	flush_icache_page(vma, page);
	set_pte_at(mm, addr, ptep, pte);
	page_add_anon_rmap(page, vma, addr);
	/* No need to invalidate - it was non-present before */
	update_mmu_cache(vma, addr, pte);
	put_vswap_page(page);
out_unlock:
	pte_unmap_unlock(ptep, ptl);
out:
	return ret;
}

int remove_from_vswap(struct page *page)
{
	struct rmap_walk_control rwc = {
		.rmap_one = remove_vswap_pte,
		.arg = NULL,
	};

	VM_BUG_ON(!PageLocked(page));
	if (rmap_walk(page, &rwc) != SWAP_AGAIN || PageVSwap(page))
		return -EBUSY;
	return 0;
}

#endif /* CONFIG_MEMORY_VSWAP */
