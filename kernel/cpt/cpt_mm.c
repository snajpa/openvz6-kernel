/*
 *
 *  kernel/cpt/cpt_mm.c
 *
 *  Copyright (C) 2000-2005  SWsoft
 *  All rights reserved.
 *
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

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
#include <linux/pagemap.h>
#include <linux/rmap.h>
#ifdef CONFIG_X86
#include <asm/ldt.h>
#endif
#include <asm/mmu.h>
#include <linux/cpt_image.h>
#include <linux/shm.h>
#include <linux/swap.h>
#include <linux/swapops.h>

#include <linux/cpt_obj.h>
#include <linux/cpt_context.h>
#include "cpt_mm.h"
#include "cpt_kernel.h"
#include "cpt_fsmagic.h"
#include "cpt_ubc.h"

static int is_packet_sock_vma(struct vm_area_struct *vma)
{
	extern const struct vm_operations_struct packet_mmap_ops;
	return vma->vm_ops == &packet_mmap_ops;
}

/*
 * Locking order between mmap_sem and i_mutex
 *
 * vfs_write() -> get_user_pages()	: i_mutex    -> mmap_sem
 * dup_mmap()				: mmap_sem   -> mmap_sem/1
 * cpt_dump_vm() -> file_write()	: mmap_sem/2 -> i_mutex
 */
#define MMAP_SEM_CPT_DUMP	2

static int collect_one_aio_ctx(struct mm_struct *mm, struct kioctx *aio_ctx,
			       cpt_context_t *ctx)
{
	if (!list_empty(&aio_ctx->run_list)) {
		/* This is impossible at least with kernel 2.6.8.1 or 2.6.16 */
		eprintk_ctx("run list is not empty, cannot suspend AIO\n");
		return -EBUSY;
	}

	/* Wait for pending IOCBs. Linux AIO is mostly _fake_.
	 * It is actually synchronous, except for direct IO and
	 * some funny raw USB things, which cannot happen inside VE.
	 * However, we do this for future.
	 *
	 * Later note: in 2.6.16 we may allow O_DIRECT, so that
	 * it is not meaningless code.
	 */
	wait_for_all_aios(aio_ctx);

	if (!list_empty(&aio_ctx->run_list) ||
	    !list_empty(&aio_ctx->active_reqs) ||
	    aio_ctx->reqs_active) {
		eprintk_ctx("were not able to suspend AIO\n");
		return -EBUSY;
	}

	return 0;
}

static int collect_one_mm(struct mm_struct *mm, cpt_context_t * ctx)
{
	struct vm_area_struct *vma;
	struct hlist_node *n;
	struct kioctx *aio_ctx;

	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (vma->vm_file) {
			if (cpt_object_add(CPT_OBJ_FILE, vma->vm_file, ctx) == NULL)
				return -ENOMEM;
		}
	}

	if (mm->exe_file &&
	    cpt_object_add(CPT_OBJ_FILE, mm->exe_file, ctx) == NULL)
		return -ENOMEM;

#ifdef CONFIG_BEANCOUNTERS
	if (cpt_add_ubc(mm_ub_top(mm), ctx) == NULL)
		return -ENOMEM;
#endif

	hlist_for_each_entry(aio_ctx, n, &mm->ioctx_list, list) {
		int err;

		if ((err = collect_one_aio_ctx(mm, aio_ctx, ctx)) != 0)
			return err;
	}

	return 0;
}

int cpt_collect_mm(cpt_context_t * ctx)
{
	cpt_object_t *obj;
	int err;
	int index;

	for_each_object(obj, CPT_OBJ_TASK) {
		struct task_struct *tsk = obj->o_obj;
		if (tsk->mm && cpt_object_add(CPT_OBJ_MM, tsk->mm, ctx) == NULL)
			return -ENOMEM;
	}

	index = 1;
	for_each_object(obj, CPT_OBJ_MM) {
		struct mm_struct *mm = obj->o_obj;
		struct task_struct *g, *p;
		int mm_users = 0;

		rcu_read_lock();
		do_each_thread_all(g, p) {
			if (p->mm == mm)
				mm_users++;
		} while_each_thread_all(g, p);
		rcu_read_unlock();

		if (obj->o_count != mm_users) {
			eprintk_ctx("mm_struct is referenced outside %d %d\n", obj->o_count, mm_users);
			return -EAGAIN;
		}
		cpt_obj_setindex(obj, index++, ctx);

		if ((err = collect_one_mm(mm, ctx)) != 0)
			return err;
	}

	return 0;
}

static int zcnt, scnt, scnt0, ucnt;

/* Function where_is_anon_page() returns address of a anonymous page in mm
 * of already dumped process. This happens f.e. after fork(). We do not use
 * this right now, just keep statistics, it is diffucult to restore such state,
 * but the most direct use is to save space in dumped image. */


static inline unsigned long
vma_address0(struct page *page, struct vm_area_struct *vma)
{
	pgoff_t pgoff = page->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);
	unsigned long address;

	address = vma->vm_start + ((pgoff - vma->vm_pgoff) << PAGE_SHIFT);
	if (unlikely(address < vma->vm_start || address >= vma->vm_end))
		address |= 1;
	return address;
}

int cpt_check_page(struct vm_area_struct *vma, unsigned long address,
		   struct page *page, int wrprot)
{
	struct mm_struct *mm = vma->vm_mm;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	spinlock_t *ptl;
	int result;

	pgd = pgd_offset(mm, address);
	if (unlikely(!pgd_present(*pgd)))
		return 0;

	pud = pud_offset(pgd, address);
	if (!pud_present(*pud))
		return 0;

	pmd = pmd_offset(pud, address);
	if (unlikely(!pmd_present(*pmd)))
		return 0;

	result = 0;
	pte = pte_offset_map(pmd, address);
	if (!pte_present(*pte)) {
		pte_unmap(pte);
		return 0;
	}

	ptl = pte_lockptr(mm, pmd);
	spin_lock(ptl);
	if (pte_present(*pte) && page_to_pfn(page) == pte_pfn(*pte)) {
		result = 1;
		if (wrprot < 0)
			result = pte_write(*pte);
		else if (wrprot)
			ptep_set_wrprotect(mm, address, pte);
	}
	pte_unmap_unlock(pte, ptl);
	return result;
}

static loff_t where_is_anon_page(cpt_object_t *mmobj, unsigned long mapaddr,
				 struct page *page, cpt_context_t * ctx)
{
	loff_t mmptr = CPT_NULL;
	struct anon_vma *anon_vma;
	struct anon_vma_chain *avc;
	int idx = mmobj->o_index;

	if (!PageAnon(page))
		return CPT_NULL;

	anon_vma = page_lock_anon_vma(page);
	if (!anon_vma)
		return CPT_NULL;

	list_for_each_entry(avc, &anon_vma->head, same_anon_vma) {
		struct vm_area_struct *vma = avc->vma;
		unsigned long addr = vma_address0(page, vma);
		cpt_object_t *obj;

		/* We do not try to support mremapped regions (addr != mapaddr),
		 * only mmaps directly inherited via fork().
		 * With this limitation we may check self-consistency of
		 * vmas (vm_start, vm_pgoff, anon_vma) before
		 * doing __copy_page_range() in rst_mm.
		 */
		if (mmobj->o_obj != vma->vm_mm && addr == mapaddr) {
			obj = lookup_cpt_object(CPT_OBJ_MM, vma->vm_mm, ctx);
			if (obj && obj->o_pos != CPT_NULL && obj->o_index < idx) {
				if (cpt_check_page(vma, addr, page, 0)) {
					mmptr = obj->o_pos;
					idx = obj->o_index;
				}
			}
		}
	}
	page_unlock_anon_vma(anon_vma);

	return mmptr;
}

struct page_area
{
	int type;
	unsigned long start;
	unsigned long end;
	pgoff_t pgoff;
	loff_t mm;
	__u64 list[16];

#define MAX_PAGE_BATCH 16
	struct page *pages[MAX_PAGE_BATCH];
};

struct page_desc
{
	int	type;
	pgoff_t	index;
	loff_t	mm;
	int	shared;
};

enum {
	PD_ABSENT,
	PD_COPY,
	PD_ZERO,
	PD_CLONE,
	PD_FUNKEY,
	PD_ITER,
	PD_ITERYOUNG,
};

/* 0: page can be obtained from backstore, or still not mapped anonymous  page,
      or something else, which does not requre copy.
   1: page requires copy
   2: page requres copy but its content is zero. Quite useless.
   3: wp page is shared after fork(). It is to be COWed when modified.
   4: page is something unsupported... We copy it right now.
 */



static void page_get_desc(cpt_object_t *mmobj,
			  struct vm_area_struct *vma, unsigned long addr,
			  struct page_desc *pdesc, cpt_context_t * ctx)
{
	struct mm_struct *mm = vma->vm_mm;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep, pte;
	spinlock_t *ptl;
	struct page *pg = NULL;
	pgoff_t linear_index = (addr - vma->vm_start)/PAGE_SIZE + vma->vm_pgoff;

	pdesc->index = linear_index;
	pdesc->shared = 0;
	pdesc->mm = CPT_NULL;

	if (vma->vm_flags & VM_IO) {
		pdesc->type = PD_ABSENT;
		return;
	}

	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
		goto out_absent;
	pud = pud_offset(pgd, addr);
	if (pud_none(*pud) || unlikely(pud_bad(*pud)))
		goto out_absent;
	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd))
		goto out_absent;
#ifdef CONFIG_X86
	if (pmd_trans_huge(*pmd))
		split_huge_page_pmd(mm, pmd);
#endif

	if (unlikely(pmd_bad(*pmd)))
		goto out_absent;

#ifdef CONFIG_VZ_CHECKPOINT_ITER
retry:
#endif
	ptep = pte_offset_map_lock(mm, pmd, addr, &ptl);
	pte = *ptep;
	pte_unmap(ptep);

	if (pte_none(pte))
		goto out_absent_unlock;

	if (!pte_present(pte)) {
#ifdef CONFIG_VZ_CHECKPOINT_ITER
		int err;
#endif
		if (pte_file(pte)) {
			pdesc->index = pte_to_pgoff(pte);
			goto out_absent_unlock;
		}
		if (vma->vm_flags & VM_SHARED) {
			/* It is impossible: shared mappings cannot be in swap */
			eprintk_ctx("shared mapping is not present: %08lx@%Ld\n", addr, mmobj->o_pos);
			goto out_unsupported_unlock;
		}
#ifdef CONFIG_PSWAP
		if (ctx->pram_stream &&
		    is_swap_pte(pte) && !non_swap_entry(pte_to_swp_entry(pte))) {
			pdesc->type = PD_COPY;
			goto out_unlock;
		}
#endif
#if defined(CONFIG_VZ_CHECKPOINT_ITER) || defined(CONFIG_PSWAP)
		/* 
		 * raise it from swap now, so that we save at least when the
		 * page is shared. 
		 */
		spin_unlock(ptl);
		err = handle_mm_fault(mm, vma, addr, 0);
		if (err == VM_FAULT_SIGBUS)
			goto out_absent;
		if (err == VM_FAULT_OOM)
			goto out_absent;
		goto retry;
#else
		pdesc->type = PD_COPY;
		goto out_unlock;
#endif
	}

	if ((pg = vm_normal_page(vma, addr, pte)) == NULL) {
		pdesc->type = PD_COPY;
		goto out_unlock;
	}

	get_page(pg);

	if (pg->mapping && !PageAnon(pg)) {
		if (vma->vm_file == NULL) {
			eprintk_ctx("pg->mapping!=NULL for fileless vma: %08lx\n", addr);
			goto out_unsupported_unlock;
		}
		/*
		 * vma and page mappings can differ if inode has peers.
		 * actually vma-mapping must be in page-mapping peer list,
		 * but checking this here is overkill.
		 *
		 * list checks are protected with ptl: close_inode_peer() will
		 * lock it to unmap this page and remove inode from peers list.
		 */
		if (vma->vm_file->f_mapping != pg->mapping &&
		    (list_empty(&vma->vm_file->f_mapping->i_peer_list) ||
		     list_empty(&pg->mapping->i_peer_list))) {
			eprintk_ctx("pg->mapping!=f_mapping: %08lx %p %p %Ld\n",
				    addr, vma->vm_file->f_mapping, pg->mapping,
				    mmobj->o_pos);
			goto out_unsupported_unlock;
		}
		pdesc->index = (pg->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT));
		/* Page is in backstore. For us it is like
		 * it is not present.
		 */
		goto out_absent_unlock;
	}

	spin_unlock(ptl);

	if (PageReserved(pg)) {
		/* Special case: ZERO_PAGE is used, when an
		 * anonymous page is accessed but not written. */
		if (pg == ZERO_PAGE(addr)) {
			if (pte_write(pte)) {
				eprintk_ctx("not funny already, writable ZERO_PAGE\n");
				goto out_unsupported;
			}
			zcnt++;
			goto out_absent;
		}
		eprintk_ctx("reserved page %lu at %08lx@%Ld\n", pg->index,
			    addr, mmobj->o_pos);
		goto out_unsupported;
	}

	if (pg == ZERO_PAGE(addr)) {
		wprintk_ctx("that's how it works now\n");
	}

	if (!pg->mapping && !is_packet_sock_vma(vma)) {
		print_bad_pte(vma, addr, pte, pg);
		goto out_unsupported;
	}

	if (pg->mapping && page_mapcount(pg) > 1) {
		pdesc->shared = 1;
		pdesc->mm = where_is_anon_page(mmobj, addr, pg, ctx);
		if (pdesc->mm != CPT_NULL) {
			scnt0++;
			pdesc->type = PD_CLONE;
			goto out_put;
		} else {
			scnt++;
		}
	}
#ifdef CONFIG_VZ_CHECKPOINT_ITER
	if (ctx->iter_done && PageCheckpointed(pg)) {
		if (pte_write(pte)) {
			wprintk_ctx("writable PG_checkpointed page\n");
		}
		pdesc->index = page_to_pfn(pg);
		pdesc->type = pte_young(pte) ? PD_ITERYOUNG : PD_ITER;
		goto out_put;
	}
#endif
	pdesc->type = PD_COPY;

out_put:
	if (pg)
		put_page(pg);
	return;

out_unlock:
	spin_unlock(ptl);
	goto out_put;

out_absent_unlock:
	spin_unlock(ptl);
out_absent:
	pdesc->type = PD_ABSENT;
	goto out_put;

out_unsupported_unlock:
	spin_unlock(ptl);
out_unsupported:
	ucnt++;
	pdesc->type = PD_FUNKEY;
	goto out_put;
}

static inline void dump_page(struct page *page, struct cpt_context *ctx)
{
	char *maddr;

	maddr = kmap(page);
	ctx->write(maddr, PAGE_SIZE, ctx);
	kunmap(page);
}

/* ATTN: We give "current" to get_user_pages(). This is wrong, but get_user_pages()
 * does not really need this thing. It just stores some page fault stats there.
 *
 * BUG: some archs (f.e. sparc64, but not Intel*) require flush cache pages
 * before accessing vma.
 */
void dump_pages(struct vm_area_struct *vma, struct page_area *pa,
	       	struct cpt_context *ctx)
{
	unsigned long start = pa->start;
	int npages = (pa->end - pa->start) / PAGE_SIZE;
	int count = 0;

	while (count < npages) {
		int copy = npages - count;
		int n;

		if (copy > MAX_PAGE_BATCH)
			copy = MAX_PAGE_BATCH;
		n = get_user_pages(current, vma->vm_mm, start, copy,
				   0, 1, pa->pages, NULL);
		if (n == copy) {
			int i;
			for (i=0; i<n; i++)
				dump_page(pa->pages[i], ctx);
		} else {
			eprintk_ctx("get_user_pages fault\n");
			for ( ; n > 0; n--)
				page_cache_release(pa->pages[n-1]);
			return;
		}
		start += n*PAGE_SIZE;
		count += n;
		for ( ; n > 0; n--)
			page_cache_release(pa->pages[n-1]);
	}
	return;
}

int dump_page_block(struct vm_area_struct *vma, struct page_area *pa,
		    struct cpt_context *ctx)
{
	loff_t saved_object;
	struct cpt_page_block pgb;

	cpt_push_object(&saved_object, ctx);

	pgb.cpt_object = CPT_OBJ_PAGES;
	pgb.cpt_hdrlen = sizeof(pgb);
	pgb.cpt_content = (pa->type == PD_COPY) ?
			CPT_CONTENT_DATA : CPT_CONTENT_VOID;
#ifdef CONFIG_PRAM
	if (pa->type == PD_COPY && ctx->pram_stream &&
	    !is_packet_sock_vma(vma))
		pgb.cpt_content = CPT_CONTENT_PRAM;
#endif
	pgb.cpt_start = pa->start;
	pgb.cpt_end = pa->end;

	ctx->write(&pgb, sizeof(pgb), ctx);
	if (pa->type == PD_COPY) {
		if (pgb.cpt_content == CPT_CONTENT_PRAM)
			cpt_dump_pram(vma, pa->start, pa->end, ctx);
		else
			dump_pages(vma, pa, ctx);
	}
	cpt_close_object(ctx);
	cpt_pop_object(&saved_object, ctx);
	return 0;
}

int dump_remappage_block(struct vm_area_struct *vma, struct page_area *pa,
			 struct cpt_context *ctx)
{
	struct cpt_remappage_block pgb;
	loff_t saved_object;

	cpt_push_object(&saved_object, ctx);

	pgb.cpt_object = CPT_OBJ_REMAPPAGES;
	pgb.cpt_hdrlen = sizeof(pgb);
	pgb.cpt_content = CPT_CONTENT_VOID;
	pgb.cpt_start = pa->start;
	pgb.cpt_end = pa->end;
	pgb.cpt_pgoff = pa->pgoff - (pa->end-pa->start)/PAGE_SIZE + 1;

	ctx->write(&pgb, sizeof(pgb), ctx);
	cpt_close_object(ctx);
	cpt_pop_object(&saved_object, ctx);
	return 0;
}

int dump_copypage_block(struct vm_area_struct *vma, struct page_area *pa,
			struct cpt_context *ctx)
{
	struct cpt_copypage_block pgb;
	loff_t saved_object;

	cpt_push_object(&saved_object, ctx);

	pgb.cpt_object = CPT_OBJ_COPYPAGES;
	pgb.cpt_hdrlen = sizeof(pgb);
	pgb.cpt_content = CPT_CONTENT_VOID;
	pgb.cpt_start = pa->start;
	pgb.cpt_end = pa->end;
	pgb.cpt_source = pa->mm;

	ctx->write(&pgb, sizeof(pgb), ctx);
	cpt_close_object(ctx);
	cpt_pop_object(&saved_object, ctx);
	return 0;
}

int dump_iterpage_block(struct vm_area_struct *vma, struct page_area *pa,
			cpt_context_t *ctx)
{
	struct cpt_iterpage_block pgb;
	loff_t saved_object;

	cpt_push_object(&saved_object, ctx);

	pgb.cpt_object = pa->type == PD_ITER ? CPT_OBJ_ITERPAGES :
		CPT_OBJ_ITERYOUNGPAGES;
	pgb.cpt_hdrlen = sizeof(pgb);
	pgb.cpt_content = CPT_CONTENT_VOID;
	pgb.cpt_start = pa->start;
	pgb.cpt_end = pa->end;
	ctx->write(&pgb, sizeof(pgb), ctx);

	ctx->write(pa->list, 8*((pa->end-pa->start)/PAGE_SIZE), ctx);

	cpt_close_object(ctx);
	cpt_pop_object(&saved_object, ctx);
	return 0;
}


static int can_expand(struct page_area *pa, struct page_desc *pd)
{
	if (pa->start == pa->end)
		return 1;
	if (pa->type != pd->type)
		return 0;
	if (pa->type == PD_ITER || pa->type == PD_ITERYOUNG) {
		if (pa->end - pa->start >= PAGE_SIZE*16)
			return 0;
		pa->list[(pa->end - pa->start)/PAGE_SIZE] = pd->index;
	}
	if (pa->type == PD_ABSENT)
		return pd->index == pa->pgoff + 1;
	if (pa->type == PD_CLONE)
		return pd->mm == pa->mm;
	return 1;
}

#ifdef CONFIG_X86_64
extern int vdso_is_rhel5(struct page *page);
static int vdso_is_old(struct vm_area_struct *vma)
{
	int n, ret;
	struct page *p;

	n = get_user_pages(current, vma->vm_mm, vma->vm_start, 1,
			   0, 0, &p, NULL);
	if (n < 1)
		return -EINVAL;

	ret = vdso_is_rhel5(p);

	page_cache_release(p);

	return ret;
}
#else
#define vdso_is_old(page) 0
#endif

static int dump_one_vma(cpt_object_t *mmobj,
			struct vm_area_struct *vma, struct cpt_context *ctx)
{
	struct cpt_vma_image *v = cpt_get_buf(ctx);
	unsigned long addr;
	loff_t saved_object;
	struct page_area *pa;
	int cloned_pages = 0;

	cpt_push_object(&saved_object, ctx);

	v->cpt_object = CPT_OBJ_VMA;
	v->cpt_hdrlen = sizeof(*v);
	v->cpt_content = CPT_CONTENT_ARRAY;

	v->cpt_start = vma->vm_start;
	v->cpt_end = vma->vm_end;
	v->cpt_flags = vma->vm_flags;
	if (vma->vm_flags&VM_HUGETLB) {
		eprintk_ctx("huge TLB VMAs are still not supported\n");
		cpt_release_buf(ctx);
		return -EINVAL;
	}
	v->cpt_pgprot = vma->vm_page_prot.pgprot;
	v->cpt_pgoff = vma->vm_pgoff;
	v->cpt_file = CPT_NULL;
#ifndef CONFIG_IA64
	if ((void *)vma->vm_start == vma->vm_mm->context.vdso &&
			vma->vm_ops == &special_mapping_vmops) {
		int old = vdso_is_old(vma);

		if (old < 0) {
			eprintk_ctx("can't get vdso page\n");
			cpt_release_buf(ctx);
			return old;
		}

		if (old)
			v->cpt_type = CPT_VMA_VDSO_OLD;
		else
			v->cpt_type = CPT_VMA_VDSO;
	} else
#endif
		v->cpt_type = CPT_VMA_TYPE_0;
	v->cpt_anonvma = 0;

	/*
	 * Dump anon_vma->root instead of current anon_vma.
	 * This allows us to make restore process easier and share one vma
	 * structure between all processes after restore.
	 * It is handy to use absolute address of anon_vma as this identifier.
	 * FIXME: Implement dumping the whole anon_vma tree
	 */
	if (vma->anon_vma)
		v->cpt_anonvmaid = (unsigned long)vma->anon_vma->root;
	else
		v->cpt_anonvmaid = 0;

	if (vma->vm_file) {
		struct file *filp;
		cpt_object_t *obj = lookup_cpt_object(CPT_OBJ_FILE, vma->vm_file, ctx);
		if (obj == NULL) BUG();
		filp = obj->o_obj;
		if (filp->f_op == &shm_file_operations) {
			struct shm_file_data *sfd = filp->private_data;

			v->cpt_type = CPT_VMA_TYPE_SHM;
			obj = lookup_cpt_object(CPT_OBJ_FILE, sfd->file, ctx);
		}
		v->cpt_file = obj->o_pos;
	}

	ctx->write(v, sizeof(*v), ctx);
	cpt_release_buf(ctx);
	if (v->cpt_type == CPT_VMA_VDSO || v->cpt_type == CPT_VMA_VDSO_OLD)
		goto out;

	pa = cpt_get_buf(ctx);

	pa->type = PD_ABSENT;
	pa->pgoff = vma->vm_pgoff;
	pa->mm = CPT_NULL;
	pa->start = vma->vm_start;
	pa->end = vma->vm_start;

	for (addr = vma->vm_start; addr < vma->vm_end; addr += PAGE_SIZE) {
		struct page_desc pd;

		page_get_desc(mmobj, vma, addr, &pd, ctx);
		cloned_pages += pd.shared;

		if (pd.type == PD_FUNKEY) {
			eprintk_ctx("dump_one_vma: funkey page\n");
			cpt_release_buf(ctx);
			return -EINVAL;
		}

		if (!can_expand(pa, &pd)) {
			if (pa->type == PD_COPY ||
			    pa->type == PD_ZERO) {
				dump_page_block(vma, pa, ctx);
			} else if (pa->type == PD_CLONE) {
				dump_copypage_block(vma, pa, ctx);
				cloned_pages++;
			} else if (pa->type == PD_ITER || pa->type == PD_ITERYOUNG) {
				dump_iterpage_block(vma, pa, ctx);
				cloned_pages++;
			} else if (pa->type == PD_ABSENT &&
				   pa->pgoff != (pa->end - vma->vm_start)/PAGE_SIZE + vma->vm_pgoff - 1) {
				dump_remappage_block(vma, pa, ctx);
			}
			pa->start = addr;
		}
		pa->type = pd.type;
		pa->end = addr + PAGE_SIZE;
		pa->pgoff = pd.index;
		if (addr == pa->start)
			pa->list[0] = pd.index;
		pa->mm = pd.mm;
	}

	if (pa->end > pa->start) {
		if (pa->type == PD_COPY ||
		    pa->type == PD_ZERO) {
			dump_page_block(vma, pa, ctx);
		} else if (pa->type == PD_CLONE) {
			dump_copypage_block(vma, pa, ctx);
			cloned_pages++;
		} else if (pa->type == PD_ITER || pa->type == PD_ITERYOUNG) {
			dump_iterpage_block(vma, pa, ctx);
			cloned_pages++;
		} else if (pa->type == PD_ABSENT &&
			   pa->pgoff != (pa->end - vma->vm_start)/PAGE_SIZE + vma->vm_pgoff - 1) {
			dump_remappage_block(vma, pa, ctx);
		}
	}

	if (cloned_pages) {
		__u32 anonvma = 1;
		loff_t anonpos = ctx->current_object + offsetof(struct cpt_vma_image, cpt_anonvma);
		ctx->pwrite(&anonvma, 4, ctx, anonpos);
	}

	cpt_release_buf(ctx);
out:
	cpt_close_object(ctx);

	cpt_pop_object(&saved_object, ctx);

	return 0;
}

static int dump_one_aio_ctx(struct mm_struct *mm, struct kioctx *aio_ctx,
			    cpt_context_t *ctx)
{
	loff_t saved_object;
	struct cpt_aio_ctx_image aimg;

	if (!list_empty(&aio_ctx->run_list) ||
	    !list_empty(&aio_ctx->active_reqs) ||
	    aio_ctx->reqs_active) {
		eprintk_ctx("AIO is active after suspend\n");
		return -EBUSY;
	}

	cpt_push_object(&saved_object, ctx);

	aimg.cpt_next = CPT_ALIGN(sizeof(aimg));
	aimg.cpt_object = CPT_OBJ_AIO_CONTEXT;
	aimg.cpt_hdrlen = sizeof(aimg);
	aimg.cpt_content = CPT_CONTENT_ARRAY;

	aimg.cpt_max_reqs = aio_ctx->max_reqs;
	aimg.cpt_ring_pages = aio_ctx->ring_info.nr_pages;
	aimg.cpt_nr = aio_ctx->ring_info.nr;
	aimg.cpt_tail = aio_ctx->ring_info.tail;
	aimg.cpt_mmap_base = aio_ctx->ring_info.mmap_base;

	ctx->write(&aimg, sizeof(aimg), ctx);

	cpt_pop_object(&saved_object, ctx);
	return 0;
}

static void dump_mm_auxv(struct mm_struct *mm, cpt_context_t *ctx)
{
	loff_t saved_object;
	struct cpt_object_hdr hdr;
	unsigned nwords = 0;
	__u64 *auxv = cpt_get_buf(ctx);

	while (mm->saved_auxv[nwords]) {
		auxv[nwords] = mm->saved_auxv[nwords];
		nwords++;
		auxv[nwords] = mm->saved_auxv[nwords];
		nwords++;
	}

	if (nwords) {
		hdr.cpt_next = CPT_NULL;
		hdr.cpt_object = CPT_OBJ_MM_AUXV;
		hdr.cpt_hdrlen = sizeof(hdr);
		hdr.cpt_content = CPT_CONTENT_DATA;

		cpt_push_object(&saved_object, ctx);
		cpt_open_object(NULL, ctx);
		ctx->write(&hdr, sizeof(hdr), ctx);
		ctx->write(auxv, nwords * sizeof(auxv[0]), ctx);
		cpt_close_object(ctx);
		cpt_pop_object(&saved_object, ctx);
	}

	cpt_release_buf(ctx);
}

static int dump_one_mm(cpt_object_t *obj, struct cpt_context *ctx)
{
	struct mm_struct *mm = obj->o_obj;
	struct vm_area_struct *vma;
	struct cpt_mm_image *v = cpt_get_buf(ctx);
	struct kioctx *aio_ctx;
	struct hlist_node *n;
	int err;

	down_write_nested(&mm->mmap_sem, MMAP_SEM_CPT_DUMP);

	cpt_open_object(obj, ctx);

	v->cpt_next = -1;
	v->cpt_object = CPT_OBJ_MM;
	v->cpt_hdrlen = sizeof(*v);
	v->cpt_content = CPT_CONTENT_ARRAY;

	v->cpt_start_code = mm->start_code;
	v->cpt_end_code = mm->end_code;
	v->cpt_start_data = mm->start_data;
	v->cpt_end_data = mm->end_data;
	v->cpt_start_brk = mm->start_brk;
	v->cpt_brk = mm->brk;
	v->cpt_start_stack = mm->start_stack;
	v->cpt_start_arg = mm->arg_start;
	v->cpt_end_arg = mm->arg_end;
	v->cpt_start_env = mm->env_start;
	v->cpt_end_env = mm->env_end;
	v->cpt_def_flags = mm->def_flags;
#ifdef CONFIG_BEANCOUNTERS
	v->cpt_mmub = cpt_lookup_ubc(mm_ub_top(mm), ctx);
#endif
	v->cpt_mm_flags = mm->flags;
	v->cpt_vps_dumpable = mm->vps_dumpable;
	v->cpt_used_hugetlb = 0; /* not used */
#ifndef CONFIG_IA64
	v->cpt_vdso = (__u32)(unsigned long)mm->context.vdso;
#endif

	ctx->write(v, sizeof(*v), ctx);
	cpt_release_buf(ctx);

#ifdef CONFIG_X86
	if (mm->context.size) {
		loff_t saved_object;
		struct cpt_obj_bits b;
		int size;

		dprintk_ctx("nontrivial LDT\n");

		cpt_push_object(&saved_object, ctx);

		cpt_open_object(NULL, ctx);
		b.cpt_next = CPT_NULL;
		b.cpt_object = CPT_OBJ_BITS;
		b.cpt_hdrlen = sizeof(b);
		b.cpt_content = CPT_CONTENT_MM_CONTEXT;
		b.cpt_size = mm->context.size*LDT_ENTRY_SIZE;

		ctx->write(&b, sizeof(b), ctx);

		size = mm->context.size*LDT_ENTRY_SIZE;

#if defined(CONFIG_X86_64) || defined(CONFIG_XEN) || \
			LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
		ctx->write(mm->context.ldt, size, ctx);
#else
		for (i = 0; i < size; i += PAGE_SIZE) {
			int nr = i / PAGE_SIZE, bytes;
			char *kaddr = kmap(mm->context.ldt_pages[nr]);

			bytes = size - i;
			if (bytes > PAGE_SIZE)
				bytes = PAGE_SIZE;
			ctx->write(kaddr, bytes, ctx);
			kunmap(mm->context.ldt_pages[nr]);
		}
#endif

		cpt_close_object(ctx);
		cpt_pop_object(&saved_object, ctx);
	}
#endif

	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if ((err = dump_one_vma(obj, vma, ctx)) != 0)
			goto out;
	}

	hlist_for_each_entry(aio_ctx, n, &mm->ioctx_list, list) {
		if ((err = dump_one_aio_ctx(mm, aio_ctx, ctx)) != 0)
			goto out;
	}

	dump_mm_auxv(mm, ctx);

	cpt_close_object(ctx);

	up_write(&mm->mmap_sem);

	return 0;

out:
	up_write(&mm->mmap_sem);

	return err;
}

int cpt_dump_vm(struct cpt_context *ctx)
{
	cpt_object_t *obj;

	scnt = scnt0 = zcnt = 0;

	cpt_open_section(ctx, CPT_SECT_MM);

	for_each_object(obj, CPT_OBJ_MM) {
		int err;

		if ((err = dump_one_mm(obj, ctx)) != 0)
			return err;
	}

	cpt_close_section(ctx);

	if (scnt)
		dprintk_ctx("cpt_dump_vm: %d shared private anon pages\n", scnt);
	if (scnt0)
		dprintk_ctx("cpt_dump_vm: %d anon pages are cloned\n", scnt0);
	if (zcnt)
		dprintk_ctx("cpt_dump_vm: %d silly pages canceled\n", zcnt);
	return 0;
}
