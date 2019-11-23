#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/errno.h>
#include <linux/ve.h>
#include <linux/ve_proto.h>
#include <linux/pagemap.h>
#include <linux/rmap.h>
#include <linux/uio.h>
#ifndef __ia64__
#include <asm/ldt.h>
#endif
#include <asm/mmu.h>
#include <asm/tlb.h>
#include <linux/swapops.h>
#include <linux/swap.h>
#include <linux/shmem_fs.h>
#include <linux/vmalloc.h>
#include <linux/cpt_image.h>
#include <linux/rbtree.h>
#include <linux/mmgang.h>

#include <linux/cpt_obj.h>
#include <linux/cpt_context.h>
#include "cpt_mm.h"
#include "cpt_pagein.h"

/* TODO:
 * 1. Error handling and recovery
 */

struct swp_node
{
	swp_entry_t		ent;
	struct anon_vma		*anon;
	u64			pfn;
	struct rb_node		rb_hash;
	/*
	 * This value signal not to clean swap entry
	 * when rst_drop_iter_rbtree is executed.
	 * It is faster than check every swap entry
	 * for belongings to shared memory
	 */
	int			keep;
};

static inline struct swp_node * rb_lookup_pfn(u64 pfn, cpt_context_t *ctx)
{
	struct rb_node *n = ctx->iter_rb_root.rb_node;
	struct swp_node *pd;

	while (n)
	{
		pd = rb_entry(n, struct swp_node, rb_hash);

		if (pfn < pd->pfn)
			n = n->rb_left;
		else if (pfn > pd->pfn)
			n = n->rb_right;
		else
			return pd->ent.val ? pd : NULL;
	}
	return NULL;
}

static inline int rb_insert_pfn(u64 pfn, swp_entry_t ent, cpt_context_t *ctx)
{
	struct rb_node **p = &ctx->iter_rb_root.rb_node;
	struct rb_node *parent = NULL;
	struct swp_node *pd;

	while (*p)
	{
		parent = *p;
		pd = rb_entry(parent, struct swp_node, rb_hash);

		if (pfn < pd->pfn)
			p = &(*p)->rb_left;
		else if (pfn > pd->pfn)
			p = &(*p)->rb_right;
		else
			goto out;
	}

	pd = kmalloc(sizeof(struct swp_node), GFP_KERNEL);
	if (pd == NULL)
		return -ENOMEM;
	memset(pd, 0, sizeof(struct swp_node));
	rb_link_node(&pd->rb_hash, parent, p);
	rb_insert_color(&pd->rb_hash, &ctx->iter_rb_root);
out:
	pd->pfn = pfn;
	pd->ent = ent;
	pd->anon = NULL;
	return 0;
}

static int iter_clone(struct mm_struct * mm,
		      unsigned long addr,
		      struct page *src_page,
		      cpt_context_t * ctx)
{
	int err;
	struct page *page;
	void *dst, *src;

	err = get_user_pages(current, mm, addr,
			     1, 1, 1, &page, NULL);
	if (err == 0)
		err = -EFAULT;
	if (err < 0) {
		eprintk_ctx("iter_clone: get_user_pages: %d\n", err);
		return err;
	}

	dst = kmap(page);
	src = kmap(src_page);
	memcpy(dst, src, PAGE_SIZE);
	kunmap(src_page);
	kunmap(page);

	page_cache_release(page);
	return 0;
}

/* See handle_mm_fault */
int rst_iter(struct vm_area_struct *vma, u64 pfn,
	     unsigned long addr, cpt_context_t * ctx)
{
	int err = -EFAULT;
	struct mm_struct *mm = vma->vm_mm;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	spinlock_t *ptl;
	struct swp_node *swn;

	swn = rb_lookup_pfn(pfn, ctx);
	if (swn == NULL) {
		eprintk_ctx("rst_iter: missing pfn %lx\n", (unsigned long)pfn);
		return -EINVAL;
	}

	if (swn->anon && swn->anon != vma->anon_vma) {
		struct page * page;
		err = -ENOMEM;
		page = read_swap_cache_async(swn->ent, GFP_HIGHUSER, vma, addr);
		if (page) {
			err = -EIO;
			wait_on_page_locked(page);
			if (PageUptodate(page))
				err = iter_clone(mm, addr, page, ctx);
			page_cache_release(page);
		}
		wprintk("cloning iter page due to anon vma mismatch %d\n", err);
		return err;
	}

	pgd = pgd_offset(mm, addr);
	pud = pud_alloc(mm, pgd, addr);
	if (unlikely(!pud))
		return -ENOMEM;

	pmd = pmd_alloc(mm, pud, addr);
	if (unlikely(!pmd))
		return -ENOMEM;

	pte = pte_alloc_map_lock(mm, pmd, addr, &ptl);
	if (unlikely(!pte))
		return -ENOMEM;

	if (pte_none(*pte)) {
		if (swap_duplicate(swn->ent) < 0)
			BUG();
		set_pte(pte, swp_entry_to_pte(swn->ent));
		inc_mm_counter(mm, swap_usage);
		if (list_empty(&mm->mmlist)) {
			spin_lock(&mmlist_lock);
			if (list_empty(&mm->mmlist))
				list_add(&mm->mmlist, &init_mm.mmlist);
			spin_unlock(&mmlist_lock);
		}
		swn->anon = vma->anon_vma;
		err = 0;
	} else {
		eprintk_ctx("rst_iter for populated pte: 0x%lx %lx\n",
			    addr, (unsigned long)pfn);
	}
	pte_unmap_unlock(pte, ptl);

	return err;
}

int
rst_iter_chunk(struct file *file, loff_t pos,
	       struct cpt_page_block * pgb,
	       cpt_context_t *ctx)
{
	unsigned long ptr = pgb->cpt_start;
	u64 page_pos[16];
	int err;

	err = ctx->pread(&page_pos,
			 8*(pgb->cpt_end-ptr)/PAGE_SIZE,
			 ctx,
			 pos + pgb->cpt_hdrlen);
	if (err) {
		eprintk_ctx("Oops\n");
		return -EINVAL;
	}

	while (ptr < pgb->cpt_end) {
		unsigned long pfn = page_pos[(ptr-pgb->cpt_start)/PAGE_SIZE];
		struct swp_node *swn;

		swn = rb_lookup_pfn(pfn, ctx);
		if (swn == NULL) {
			eprintk_ctx("rst_iter_shmem: missing pfn %lx\n", pfn);
			return -EINVAL;
		}
		if (swn->anon) {
			eprintk_ctx("rst_iter_shmem: creepy anon?\n");
			return -EINVAL;
		}
		err = shmem_insertpage(file->f_dentry->d_inode,
				       ptr/PAGE_SIZE, swn->ent);
		if (err) {
			eprintk_ctx("rst_iter_shmem: failed to insert?\n");
			return err;
		}
		swn->keep = 1;
		ptr += PAGE_SIZE;
	}
	if (i_size_read(file->f_dentry->d_inode) < ptr)
		i_size_write(file->f_dentry->d_inode, ptr);
	return 0;
}

static int nread(struct file *file, char *buf, int len)
{
	int offset = 0;

	while (offset < len) {
		int res;
		mm_segment_t oldfs;
		oldfs = get_fs(); set_fs(KERNEL_DS);
		res = vfs_read(file, buf+offset, len-offset, &file->f_pos);
		set_fs(oldfs);
		if (res < 0)
			return res;
		if (res == 0)
			return -EIO;
		offset += res;
	}
	return 0;
}

/*
 * This one is close to read_swap_cache_async() in ideas, so look comments there.
 */
static struct page *dontread_swap_cache(swp_entry_t entry, struct file *file,
					struct user_beancounter *ub)
{
	struct page *found_page, *new_page = NULL;
	int err = 0;
	void *dst;

	do {
		found_page = find_get_page(&swapper_space, entry.val);
		if (found_page)
			break;

		/*
		 * Get a new page to read into from swap.
		 */
		if (!new_page) {
			new_page = alloc_page(GFP_HIGHUSER);
			if (!new_page)
				break;		/* Out of memory */
			if (gang_add_user_page(new_page, get_ub_gs(ub), GFP_KERNEL))
				break;
		}

		err = radix_tree_preload(GFP_KERNEL);
		if (err)
			break;

		err = swapcache_prepare(entry);
		if (err == -EEXIST) {
			radix_tree_preload_end();
			cond_resched();
			continue;
		}
		BUG_ON(err);

		__set_page_locked(new_page);
		SetPageSwapBacked(new_page);
		err = __add_to_swap_cache(new_page, entry);
		if (!err) {
			radix_tree_preload_end();
			lru_cache_add_anon(new_page);
			goto dirty_page;
		}
		radix_tree_preload_end();
		ClearPageSwapBacked(new_page);
		__clear_page_locked(new_page);
		swapcache_free(entry, NULL);
	} while (err != -ENOMEM);

	if (new_page) {
		if (page_gang(new_page))
			gang_del_user_page(new_page);
		page_cache_release(new_page);
	}
	if (found_page) {
		lock_page(found_page);
		new_page = found_page;
		goto dirty_page;
	}
	return NULL;

dirty_page:
	dst = kmap(new_page);
	err = nread(file, dst, PAGE_SIZE);
	kunmap(new_page);
	SetPageDirty(new_page);
	SetPageUptodate(new_page);
	unlock_page(new_page);
	if (err) {
		page_cache_release(new_page);
		return NULL;
	}
	return new_page;
}

int rst_iteration(cpt_context_t *ctx)
{
	int err = 0;
	struct file * file = ctx->pagein_file_in;
	mm_segment_t oldfs;
	struct user_beancounter *ub;

#ifdef ITER_DEBUG
	if (!file) {
		file = filp_open("/var/tmp/dmp_", O_RDONLY, 0);
		if (IS_ERR(file))
			file = NULL;
		ctx->pagein_file_in = file;
	}
#endif
	if (file == NULL)
		return -EBADF;
#ifndef ITER_DEBUG
	if (ctx->pagein_file_out == NULL)
		return -EBADF;
#endif

	ub = ctx->iter_ub;
	if (ub == NULL) {
		if (ctx->ve_id == 0) {
			ub = get_beancounter_longterm(mm_ub_top(&init_mm));
		} else {
			ub = get_beancounter_byuid(ctx->ve_id, 1);
			err = -ENOMEM;
			if (ub == NULL)
				goto out;
		}
		ctx->iter_ub = ub;
	}
	get_beancounter(ub);

	for (;;) {
		struct swp_node * swn;
		swp_entry_t ent;
		void *dst;
		struct page * page;
		struct pgin_reply rep;

		err = nread(file, (void*)&rep, sizeof(rep));
		if (err) {
#ifdef ITER_DEBUG
			err = 0;
#endif
			break;
		}

		if (rep.rmid != PGIN_RMID) {
			err = -EINVAL;
			eprintk_ctx("iter stream corrupt\n");
			break;
		}

		if (rep.handle == 0) {
			switch (rep.error) {
			case ITER_PASS:
				continue;
			case ITER_STOP:
				break;
			default:
				eprintk_ctx("iter stream corrupt: unknown control code %d\n", rep.error);
				err = -EINVAL;
			}
			break;
		}

		err = -ENOMEM;

		swn = rb_lookup_pfn(rep.handle, ctx);
		if (swn) {
			page = dontread_swap_cache(swn->ent, file, ub);
			if (page == NULL) {
				eprintk_ctx("Found swap entry without page\n");
				break;
			}
			page_cache_release(page);
			continue;
		}
		
		if (get_nr_swap_pages() < total_swap_pages * swap_percent / 100) {
			eprintk_ctx("Swap pages barrier\n");
			eprintk_ctx("swap_percent = %d\n", swap_percent);
			break;
		}

		page = alloc_page(GFP_HIGHUSER);
		if (page == NULL) {
			eprintk_ctx("Failed to alloc page\n");
			break;
		}

		err = gang_add_user_page(page, get_ub_gs(ub), GFP_KERNEL);
		if (err) {
			eprintk_ctx("Failed to charge page\n");
			page_cache_release(page);
			break;
		}

		dst = kmap(page);
		err = nread(file, dst, PAGE_SIZE);
		kunmap(page);

		if (err) {
			eprintk_ctx("Failed to read page\n");
			gang_del_user_page(page);
			page_cache_release(page);
			break;
		}

		lock_page(page);
		SetPageUptodate(page);
		SetPageSwapBacked(page);
		if (add_to_swap(page, ub)) {
			lru_cache_add_anon(page);
			ent.val = page->private;
			err = swap_duplicate(ent);
		} else {
			gang_del_user_page(page);
			err = -ENOMEM;
		}
		unlock_page(page);
		page_cache_release(page);

		if (err) {
			eprintk_ctx("Failed to add page to swap\n");
			break;
		}

		err = rb_insert_pfn(rep.handle, ent, ctx);
		if (err) {
			eprintk_ctx("Failed to add swap enry to tree\n");
			free_swap_and_cache(ent);
			break;
		}
	}
	put_beancounter(ub);

out:
#ifndef ITER_DEBUG
	if (!err) {
		struct pgin_request req;
		req.rmid = PGIN_RMID;
		req.size = PGIN_STOP;
		req.index = 0;
		req.handle = 0;
		oldfs = get_fs(); set_fs(KERNEL_DS);
		err = vfs_write(ctx->pagein_file_out, (void*)&req, sizeof(req),
				&ctx->pagein_file_out->f_pos);
		set_fs(oldfs);
		if (err != sizeof(req)) {
			if (err >= 0)
				err = -EIO;
		} else {
			err = 0;
		}
	}
#endif
	if (err) {
		fput(ctx->pagein_file_out);
		ctx->pagein_file_out = NULL;
		fput(ctx->pagein_file_in);
		ctx->pagein_file_in = NULL;
		rst_drop_iter_rbtree(ctx);
	}
	return err;
}

void rst_drop_iter_rbtree(cpt_context_t *ctx)
{
	struct swp_node *pd;
	struct rb_node *node;

	if (ctx->iter_rb_root.rb_node == NULL)
		goto free_ub;

	while ((node = ctx->iter_rb_root.rb_node) != NULL) {
		pd = rb_entry(node, struct swp_node, rb_hash);
		if (pd->ent.val && !pd->keep)
			free_swap_and_cache(pd->ent);
		rb_erase(node, &ctx->iter_rb_root);
		kfree(pd);
	}

free_ub:
	if (ctx->iter_ub) {
		put_beancounter_longterm(ctx->iter_ub);
		ctx->iter_ub = NULL;
	}
}
