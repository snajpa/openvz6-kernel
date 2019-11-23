#include <linux/autoconf.h>
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
#include <linux/mount.h>
#include <linux/splice.h>
#ifndef __ia64__
#include <asm/ldt.h>
#endif
#include <asm/mmu.h>
#include <asm/tlb.h>
#include <linux/cpt_image.h>

#include <linux/cpt_obj.h>
#include <linux/cpt_context.h>
#include "cpt_mm.h"
#include "cpt_files.h"
#include "cpt_pagein.h"

struct iter_data
{
#define CPT_XFER_BATCH	64
	int		xfer_nr;
	struct page	*xfer_batch[CPT_XFER_BATCH];
	int		iter_new;
	int		iter_young;
	int		iter_shm;
	int		iter;
	cpt_context_t	*ctx;
};

/* Algo is the following:
 * 
 * 1. At the first iteration all appropriate pte's are maked COW,
 *    pages are marked PG_checkpointed and transferred (indexed
 *    by pfn).
 * 2. do_wp_page(), if it wants to pte_mkwrite(), clears PG_checkpointed.
 *    Also, PG_checkpointed is cleared, when a page is unmapped.
 * 3. At the next iterations we check PG_checkpoint. If it is set,
 *    we are lucky. If it is not, page is new or it was changed, so that
 *    we send new copy.
 * 4. Iterations stop when amount of new pages is < thresh_1 or it is
 *    more than pages found at the first iteration / 2^N. So, we never
 *    transfer more than 2*memsize.
 * 5. Then we freeze VE.
 * 6. cpt_mm, if sees a page, marked PG_checkpoint, sends its pfn.
 *    (well, and panics, if pte is writable).
 */

static int add_to_xfer_list(struct page *pg, struct iter_data *iter,
			    cpt_context_t *ctx)
{
	int slot = iter->xfer_nr;

	BUG_ON(slot >= CPT_XFER_BATCH);
	iter->xfer_batch[slot] = pg;
	return ((iter->xfer_nr = slot + 1) == CPT_XFER_BATCH);
}

static int submit_page(struct page *pg, cpt_context_t *ctx)
{
	int err;
	struct iovec iov[2];
	struct file *file = ctx->pagein_file_out;
	mm_segment_t oldfs;
	struct pgin_reply rep;

	if (!file)
		return -EBADF;

	rep.rmid = PGIN_RMID;
	rep.error = 0;
	rep.handle = page_to_pfn(pg);

	iov[0].iov_base = &rep;
	iov[0].iov_len = sizeof(rep);
	iov[1].iov_base = kmap(pg);
	iov[1].iov_len = PAGE_SIZE;

	oldfs = get_fs(); set_fs(KERNEL_DS);
	err = vfs_writev(file, iov, 2, &file->f_pos);
	set_fs(oldfs);
	kunmap(pg);
	if (err < 0)
		return err;
	if (err != sizeof(rep) + PAGE_SIZE)
		return -EIO;
	return 0;
}

static int flush_transfer(struct iter_data *iter, cpt_context_t *ctx)
{
	int err = 0;
	int slot;

	for (slot = 0; slot < iter->xfer_nr; slot++) {
		struct page *pg = iter->xfer_batch[slot];
		if (!err)
			err = submit_page(pg, ctx);
		page_cache_release(pg);
	}
	iter->xfer_nr = 0;
	return err;
}

static inline int iter_one_pmd(struct vm_area_struct *vma, pmd_t *pmd,
			       unsigned long addr, unsigned long end,
			       struct iter_data *iter, cpt_context_t *ctx)
{
	int err = 0;
	pte_t *pte;
	struct mm_struct *mm = vma->vm_mm;
	spinlock_t *ptl;

	pte = pte_offset_map_lock(vma->vm_mm, pmd, addr, &ptl);
	do {
		pte_t ptent = *pte;
		struct page *pg;
		int retr = 0;

retry:
		if (pte_none(ptent))
			continue;
		if (!pte_present(*pte)) {
			if (pte_file(ptent))
				continue;

			pte_unmap_unlock(pte, ptl);
			err = handle_mm_fault(mm, vma, addr, 0);
			if (err & VM_FAULT_OOM)
				return -ENOMEM;
			if (err & VM_FAULT_ERROR)
				return -EFAULT;
			err = 0;
			pte = pte_offset_map_lock(vma->vm_mm, pmd, addr, &ptl);
			ptent = *pte;
			retr = 1;
			goto retry;
		}

		pg = vm_normal_page(vma, addr, ptent);

                if (pg == NULL ||
		    !pg->mapping ||
		    !PageAnon(pg) ||
		    PageReserved(pg) ||
		    pg == ZERO_PAGE(addr))
			continue;

		if (iter->iter >= 0) {
			if (ptep_test_and_clear_young(vma, addr, pte) && !retr)
				iter->iter_young++;
		}

		if (iter->iter == 0) {
			/* Just clear the state */
			ClearPageCheckpointed(pg);
			iter->iter_new++;
			continue;
		}

		if (PageCheckpointed(pg)) {
			if (pte_write(ptent)) {
				pte_unmap_unlock(pte, ptl);
				eprintk("COW lost %lu %lu!\n", addr, page_to_pfn(pg));
				return -EFAULT;
			}
			continue;
		}

		iter->iter_new++;
		get_page(pg);
		SetPageCheckpointed(pg);
		ptep_set_wrprotect(vma->vm_mm, addr, pte);
		if (add_to_xfer_list(pg, iter, ctx)) {
			pte_unmap_unlock(pte, ptl);
			flush_tlb_range(vma, vma->vm_start, vma->vm_end);
			err = flush_transfer(iter, ctx);
			if (err)
				return err;
			pte = pte_offset_map_lock(vma->vm_mm, pmd, addr, &ptl);
		}
	} while (pte++, addr += PAGE_SIZE, addr != end);

	pte_unmap_unlock(pte - 1, ptl);

	return err;
}

static inline int
iter_one_pud(struct vm_area_struct * vma, pud_t *pud,
		unsigned long addr, unsigned long end, struct iter_data *iter,
		cpt_context_t *ctx)
{
	pmd_t *pmd;
	unsigned long next;

	pmd = pmd_offset(pud, addr);
	do {
		int err;
		next = pmd_addr_end(addr, end);
		split_huge_page_pmd(vma->vm_mm, pmd);
		if (pmd_none_or_clear_bad(pmd))
			continue;
		err = iter_one_pmd(vma, pmd, addr, next, iter, ctx);
		if (err)
			return err;
	} while (pmd++, addr = next, addr != end);
	return 0;
}

static inline int
iter_one_pgd(struct vm_area_struct * vma, pgd_t *pgd,
	     unsigned long addr, unsigned long end, struct iter_data *iter,
	     cpt_context_t *ctx)
{
	pud_t *pud;
	unsigned long next;

	pud = pud_offset(pgd, addr);
	do {
		int err;
		next = pud_addr_end(addr, end);
		if (pud_none_or_clear_bad(pud))
			continue;
		err = iter_one_pud(vma, pud, addr, next, iter, ctx);
		if (err)
			return err;
	} while (pud++, addr = next, addr != end);
	return 0;
}

static int iter_one_vma(struct iter_data *iter, struct vm_area_struct *vma,
			struct task_struct *tsk, cpt_context_t *ctx)
{
	pgd_t *pgd;
	unsigned long addr, end, next;

	addr = vma->vm_start;
	end = vma->vm_end;

	pgd = pgd_offset(vma->vm_mm, addr);
	do {
		int err;
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
			continue;
		err = iter_one_pgd(vma, pgd, addr, next, iter, ctx);
		if (err)
			return err;
	} while (pgd++, addr = next, addr != end);
	return 0;
}

static int iter_one_mm(struct task_struct *tsk, struct mm_struct *mm,
		       void *data, cpt_context_t *ctx)
{
	int err = 0, err2 = 0;
	struct iter_data *iter = data;
	struct vm_area_struct *vma;

	/* OK, now we are going to scan VM */
	down_read(&mm->mmap_sem);
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		/* We have to mangle page protection bits on share memory
		 * vmas to enforce write ptotection. 
		 */
		if (ctx->iter_shm_start &&
		    (vma->vm_flags & VM_SHARED) &&
		    vma->vm_file &&
		    vma->vm_file->f_vfsmnt == VE_TASK_INFO(tsk)->owner_env->shmem_mnt) {
			int vm_flags = vma->vm_flags & (VM_READ|VM_WRITE|VM_EXEC);
			pgprot_t nprot = vm_get_page_prot(vm_flags);
			pgprot_t oprot = vm_get_page_prot(vm_flags|VM_SHARED);

			if (iter->iter == 0) {
				if (pgprot_val(oprot) != pgprot_val(vma->vm_page_prot)) {
					iprintk_ctx("Unusual page protection %llx %llx " CPT_FID " %lx\n",
						    (unsigned long long)pgprot_val(oprot),
						    (unsigned long long)pgprot_val(vma->vm_page_prot),
						    CPT_TID(tsk), vma->vm_start);
					ctx->iter_shm_start = 0;
				} else {
					vma->vm_page_prot = nprot;
				}
			} else {
				/* Old vma's were updated at 0th iteration.
				 * New ones must have correct protection because
				 * we set AS_CHECKPOINT on shmem mapping.
				 * If pgprot is wrong, something is wrong.
				 */
				if (pgprot_val(nprot) != pgprot_val(vma->vm_page_prot)) {
					iprintk_ctx("Page protection lost\n");
					ctx->iter_shm_start = 0;
				}
			}
		}

		/* Do only true simple anonymous VMAs. */
		if (!vma->anon_vma)
			continue;
		if (is_vm_hugetlb_page(vma))
			continue;
		if ((vma->vm_flags & (VM_SHARED | VM_MAYWRITE)) != VM_MAYWRITE)
			continue;
		err = iter_one_vma(iter, vma, tsk, ctx);
		if (iter->xfer_nr) {
			flush_tlb_range(vma, vma->vm_start, vma->vm_end);
			if (iter->iter)
				err2 = flush_transfer(iter, ctx);
		}
		if (err || err2)
			break;
	}
	up_read(&mm->mmap_sem);
	return err ? : err2;
}

int cpt_walk_mm(int (*doit)(struct task_struct *tsk, struct mm_struct *mm,
			  void *data, cpt_context_t *ctx),
		void *data,
		cpt_context_t *ctx)
{
	int err = 0;
	struct task_struct *p;
	struct ve_struct *env;

	env = get_ve_by_id(ctx->ve_id);
	if (env == NULL)
		return -ESRCH;

	tasklist_write_lock_irq();

	do {
		struct mm_struct *mm;

		/* VE is empty, stop scanning. */
		if (list_empty(&env->vetask_auxlist))
			break;

		p = list_entry(env->vetask_auxlist.next, struct task_struct, ve_task_info.aux_list);
		list_move_tail(&VE_TASK_INFO(p)->aux_list, &env->vetask_auxlist);

		get_task_struct(p);
		write_unlock_irq(&tasklist_lock);

		mm = get_task_mm(p);
		if (mm) {
			err = doit(p, mm, data, ctx);
			mmput(mm);
		}

		put_task_struct(p);

		cond_resched();

		tasklist_write_lock_irq();
		if (err)
			break;
	} while (p != __first_task_ve(env));

	write_unlock_irq(&tasklist_lock);

	put_ve(env);

	return err;
}

/* Just clear the state */

static int iter_one_shm_zero(struct inode * inode,
			     void *data, cpt_context_t *ctx)
{
	struct iter_data *iter = data;
	unsigned long idx;

	if (!S_ISREG(inode->i_mode))
		return 0;

	for (idx = 0;
	     idx < (i_size_read(inode)+PAGE_CACHE_SIZE-1)/PAGE_CACHE_SIZE;
	     idx++) {
		struct page * pg;

		pg = find_lock_page(inode->i_mapping, idx);
		if (pg && !radix_tree_exceptional_entry(pg)) {
			ClearPageCheckpointed(pg);
			iter->iter_new++;
			iter->iter_shm++;
			unlock_page(pg);
			page_cache_release(pg);
		}
	}
	if (iter->iter_shm) {
		set_bit(AS_CHECKPOINT, &inode->i_mapping->flags);
		ctx->iter_shm_start = 1;
	}
	return 0;
}

static int write_protect(struct page * page)
{
	struct address_space *mapping = page->mapping;
	pgoff_t pgoff = page->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);
	struct vm_area_struct *vma;
	struct prio_tree_iter iter;
	int mapcnt = 0;

	SetPageCheckpointed(page);

	if (!page_mapcount(page))
		return 0;

	/* Lazy... */
	if (!list_empty(&mapping->i_mmap_nonlinear)) {
		ClearPageCheckpointed(page);
		return -EBUSY;
	}

	spin_lock(&mapping->i_mmap_lock);
	vma_prio_tree_foreach(vma, &iter, &page->mapping->i_mmap,
			      pgoff, pgoff) {
		unsigned long addr = vma_address(page, vma);
		BUG_ON(IS_ERR_VALUE(addr));
		if (cpt_check_page(vma, addr, page, 1)) {
			flush_tlb_page(vma, addr);
			mapcnt++;
		}
	}
	spin_unlock(&mapping->i_mmap_lock);
	return mapcnt;
}

int cpt_verify_wrprot(struct page * page, cpt_context_t * ctx)
{
	struct address_space *mapping = page->mapping;
	pgoff_t pgoff = page->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);
	struct vm_area_struct *vma;
	struct prio_tree_iter iter;
	int mapcnt = 0;

	if (!list_empty(&mapping->i_mmap_nonlinear)) {
		iprintk_ctx("Unexpected nonlinear mapping %Ld\n", ctx->file->f_pos);
		return -EBUSY;
	}

	spin_lock(&mapping->i_mmap_lock);
	vma_prio_tree_foreach(vma, &iter, &page->mapping->i_mmap,
			      pgoff, pgoff) {
		unsigned long addr = vma_address(page, vma);
		BUG_ON(IS_ERR_VALUE(addr));
		if (cpt_check_page(vma, addr, page, -1)) {
			mapcnt++;
		}
	}
	spin_unlock(&mapping->i_mmap_lock);
	if (mapcnt)
		iprintk("WRPROT broken, %Ld\n", ctx->file->f_pos);
	return mapcnt;
}

static int
iter_actor(struct pipe_inode_info *pipe, struct pipe_buffer *buf,
		struct splice_desc *sd)
{
	struct iter_data * iter = sd->u.data;
	struct page *page = buf->page;
	cpt_context_t * ctx = iter->ctx;
	int err = 0, ret;

	ret = buf->ops->confirm(pipe, buf);
	if (unlikely(ret))
		return ret;

	if (page != ZERO_PAGE(0) && !cpt_page_is_zero(page)) {
		lock_page(page);
		if (!PageCheckpointed(page)) {
			if (write_protect(page) >= 0) {
				iter->iter_new++;
				iter->iter_shm++;
				get_page(page);
				if (add_to_xfer_list(page, iter, ctx))
					err = flush_transfer(iter, ctx);
			}
		}
		unlock_page(page);
	}

	return (err) ? : sd->len;
}

static int
iter_splice_actor(struct pipe_inode_info *pipe, struct splice_desc *sd)
{
	return __splice_from_pipe(pipe, sd, iter_actor);
}

static int iter_one_shm(struct inode * inode,
			void *data, cpt_context_t *ctx)
{
	struct iter_data *iter = data;
	struct file dummyf;
	struct dentry dummyd;
	struct splice_desc sd;
	ssize_t retval;
	int err;

	if (!S_ISREG(inode->i_mode))
		return 0;

	dummyf.f_op = fops_get(inode->i_fop);
	dummyf.f_mapping = inode->i_mapping;
	dummyf.f_dentry = &dummyd;
	dummyf.f_flags = O_NOATIME;
	dummyf.f_mode = FMODE_READ;
	dummyd.d_inode = inode;

	sd.len = 0;
	sd.total_len = 0x40000000UL;
	sd.flags = 0;
	sd.pos = 0;
	sd.u.data = iter;

	retval = splice_direct_to_actor(&dummyf, &sd, iter_splice_actor);

	fops_put(dummyf.f_op);

	err = flush_transfer(iter, ctx);

	return retval < 0 ? retval : err;
}

extern spinlock_t inode_lock;

int cpt_walk_shm(int (*doit)(struct inode * inode,
			     void *data, cpt_context_t *ctx),
		void *data,
		cpt_context_t *ctx)
{
	int err = 0;
	struct ve_struct *env;
	struct super_block *sb;
	struct inode *inode, *old;

	env = get_ve_by_id(ctx->ve_id);
	if (env == NULL)
		return -ESRCH;

	down_read(&env->op_sem);
	err = -ESRCH;
	if (!env->is_running)
		goto out;

	err = 0;
	if (env->shmem_mnt == NULL || (sb = env->shmem_mnt->mnt_sb) == NULL)
		goto out;

	old = NULL;
	spin_lock(&inode_lock);
	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		if (inode->i_state & (I_FREEING|I_WILL_FREE))
			continue;
		__iget(inode);
		spin_unlock(&inode_lock);

		err = doit(inode, data, ctx);

		if (old != NULL)
			iput(old);
		old = inode;
		spin_lock(&inode_lock);

		if (err)
			break;
	}
	spin_unlock(&inode_lock);
	if (old != NULL)
		iput(old);

out:
	up_read(&env->op_sem);

	put_ve(env);

	return err;
}

static int nread(struct file *file, void *buf, int len)
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

int cpt_iteration(cpt_context_t *ctx)
{
	int err;
	int prev_iter, first_iter, prev_young;
	struct iter_data *iter;
	int tmo;

#ifdef ITER_DEBUG
	ctx->pagein_file_out = filp_open("/var/tmp/dmp_", O_WRONLY|O_TRUNC|O_CREAT, 0666);
	if (IS_ERR(ctx->pagein_file_out))
		ctx->pagein_file_out = NULL;
#endif

	if (ctx->pagein_file_out == NULL)
		return -EBADF;

	iter = kmalloc(sizeof(struct iter_data), GFP_KERNEL);
	if (iter == NULL)
		return -ENOMEM;
	memset(iter, 0, sizeof(struct iter_data));

	iter->ctx = ctx;

	/* Clear the state */ 
	cpt_walk_shm(iter_one_shm_zero, iter, ctx);
	cpt_walk_mm(iter_one_mm, iter, ctx);

	iter->iter_new = iter->iter_young = iter->iter_shm = 0;
	iter->iter = 1;
	err = cpt_walk_mm(iter_one_mm, iter, ctx);
	if (!err && ctx->iter_shm_start)
		err = cpt_walk_shm(iter_one_shm, iter, ctx);
	prev_iter = first_iter = iter->iter_new;
	prev_young = iter->iter_young;
	dprintk_ctx("%d: Found %d pages, %d young, %d shm\n",
		    iter->iter, prev_iter, iter->iter_young, iter->iter_shm);
	iter->iter_new = iter->iter_young = iter->iter_shm = 0;
	if (err)
		goto out;

	tmo = HZ/20;

	for (;;) {
		iter->iter++;
		current->state = TASK_UNINTERRUPTIBLE;
		schedule_timeout(tmo);
		err = cpt_walk_mm(iter_one_mm, iter, ctx);
		if (err)
			break;
		if (ctx->iter_shm_start) {
			err = cpt_walk_shm(iter_one_shm, iter, ctx);
			if (err)
				break;
		}
		dprintk_ctx("%d: Found %d pages, %d young, %d shm, %d tmo\n",
			    iter->iter, iter->iter_new, iter->iter_young,
			    iter->iter_shm, tmo);
		if (iter->iter_new > prev_iter/2 ||
		    iter->iter_young > prev_young/2) {
			tmo /= 2;
			if (tmo < 2)
				tmo = 2;
		}
		if (iter->iter_new > first_iter/2 ||
		    iter->iter_new < 10 ||
		    iter->iter > 10) {
			current->state = TASK_UNINTERRUPTIBLE;
			schedule_timeout(tmo/2);
			iter->iter = -1;
			prev_iter = iter->iter_new;
			iter->iter_new = iter->iter_shm = 0;
			cpt_walk_mm(iter_one_mm, iter, ctx);
			if (ctx->iter_shm_start)
				cpt_walk_shm(iter_one_shm, iter, ctx);
			dprintk_ctx("%d: Found %d pages, shm %d, tmo %d\n",
				    iter->iter, iter->iter_new,
				    iter->iter_shm, tmo);
			ctx->iter_done = 1;
#ifndef ITER_DEBUG
			do {
				union {
					struct pgin_reply rep;
					struct pgin_request req;
				} u;
				mm_segment_t oldfs;
				struct file * file = ctx->pagein_file_out;

				u.rep.rmid = PGIN_RMID;
				u.rep.error = ITER_STOP;
				u.rep.handle = 0;

				oldfs = get_fs(); set_fs(KERNEL_DS);
				vfs_write(file, (void*)&u.rep, sizeof(u.rep), &file->f_pos);
				err = nread(ctx->pagein_file_in, &u.req, sizeof(u.req));
				set_fs(oldfs);
				if (!err) {
					if (u.req.rmid != PGIN_RMID ||
					    u.req.size != PGIN_STOP)
						err = -EIO;
				}
			} while (0);
#endif
			break;
		}
		prev_iter = iter->iter_new;
		prev_young = iter->iter_young;
		first_iter /= 2;
		iter->iter_new = iter->iter_young = iter->iter_shm = 0;
	}

out:
	if (err) {
		if (ctx->pagein_file_out) {
			fput(ctx->pagein_file_out);
			ctx->pagein_file_out = NULL;
		}
		if (ctx->pagein_file_in) {
			fput(ctx->pagein_file_in);
			ctx->pagein_file_in = NULL;
		}
	}
	kfree(iter);
	return err;
}
