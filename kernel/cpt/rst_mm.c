/*
 *
 *  kernel/cpt/rst_mm.c
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
#include <linux/mmgang.h>
#include <linux/hugetlb.h>
#include <linux/errno.h>
#include <linux/pagemap.h>
#include <linux/mman.h>
#include <linux/vmalloc.h>
#include <linux/rmap.h>
#include <linux/hash.h>
#include <linux/binfmts.h>
#include <asm/pgalloc.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>
#include <asm/mmu.h>
#ifdef CONFIG_X86
#include <asm/ldt.h>
#include <asm/desc.h>
#endif
#include <asm/mmu_context.h>
#include <asm/vsyscall.h>
#include <linux/cpt_image.h>

#ifdef CONFIG_VE
#include <bc/beancounter.h>
#include <bc/vmpages.h>
#endif

#include <linux/cpt_obj.h>
#include <linux/cpt_context.h>
#include "cpt_files.h"
#include "cpt_ubc.h"
#include "cpt_mm.h"
#include "cpt_kernel.h"

#include "cpt_syscalls.h"

#define __PAGE_NX (1ULL<<63)

#ifdef CONFIG_IA32_EMULATION
extern struct linux_binfmt compat_elf_format;
#else
extern struct linux_binfmt elf_format;
#endif

static unsigned long make_prot(struct cpt_vma_image *vmai)
{
	unsigned long prot = 0;

	if (vmai->cpt_flags&VM_READ)
		prot |= PROT_READ;
	if (vmai->cpt_flags&VM_WRITE)
		prot |= PROT_WRITE;
	if (vmai->cpt_flags&VM_EXEC)
		prot |= PROT_EXEC;
	if (vmai->cpt_flags&VM_GROWSDOWN)
		prot |= PROT_GROWSDOWN;
	if (vmai->cpt_flags&VM_GROWSUP)
		prot |= PROT_GROWSUP;
	return prot;
}

static unsigned long make_flags(struct cpt_vma_image *vmai)
{
	unsigned long flags = MAP_FIXED | MAP_CPT;

	if (vmai->cpt_flags&(VM_SHARED|VM_MAYSHARE))
		flags |= MAP_SHARED;
	else
		flags |= MAP_PRIVATE;

	if (vmai->cpt_file == CPT_NULL)
		flags |= MAP_ANONYMOUS;
	if (vmai->cpt_flags&VM_GROWSDOWN)
		flags |= MAP_GROWSDOWN;
#ifdef MAP_GROWSUP
	if (vmai->cpt_flags&VM_GROWSUP)
		flags |= MAP_GROWSUP;
#endif
	if (vmai->cpt_flags&VM_DENYWRITE)
		flags |= MAP_DENYWRITE;
	if (vmai->cpt_flags&VM_EXECUTABLE)
		flags |= MAP_EXECUTABLE;
	if (!(vmai->cpt_flags&VM_ACCOUNT))
		flags |= MAP_NORESERVE;
	return flags;
}

#ifdef CONFIG_X86
#if !defined(CONFIG_X86_64) && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19) \
				&& !defined(CONFIG_XEN)
static int __alloc_ldt(mm_context_t *pc, int mincount)
{
	int oldsize, newsize, nr;

	if (mincount <= pc->size)
		return 0;
	/*
	 * LDT got larger - reallocate if necessary.
	 */
	oldsize = pc->size;
	mincount = (mincount+511)&(~511);
	newsize = mincount*LDT_ENTRY_SIZE;
	for (nr = 0; nr * PAGE_SIZE < newsize; nr++) {
		BUG_ON(nr * PAGE_SIZE >= 64*1024);
		if (!pc->ldt_pages[nr]) {
			pc->ldt_pages[nr] = alloc_page(GFP_HIGHUSER|__GFP_UBC);
			if (!pc->ldt_pages[nr])
				goto nomem;
			clear_highpage(pc->ldt_pages[nr]);
		}
	}
	pc->size = mincount;
	return 0;

nomem:
	while (--nr >= 0)
		__free_page(pc->ldt_pages[nr]);
	pc->size = 0;
	return -ENOMEM;
}

static int do_rst_ldt(struct cpt_obj_bits *li, loff_t pos, struct cpt_context *ctx)
{
	struct mm_struct *mm = current->mm;
	int i;
	int err;
	int size;

	err = __alloc_ldt(&mm->context, li->cpt_size/LDT_ENTRY_SIZE);
	if (err)
		return err;

	size = mm->context.size*LDT_ENTRY_SIZE;

	for (i = 0; i < size; i += PAGE_SIZE) {
		int nr = i / PAGE_SIZE, bytes;
		char *kaddr = kmap(mm->context.ldt_pages[nr]);

		bytes = size - i;
		if (bytes > PAGE_SIZE)
			bytes = PAGE_SIZE;
		err = ctx->pread(kaddr, bytes, ctx, pos + li->cpt_hdrlen + i);
		kunmap(mm->context.ldt_pages[nr]);
		if (err)
			return err;
	}

	load_LDT(&mm->context);
	return 0;
}

#else

static int do_rst_ldt(struct cpt_obj_bits *li, loff_t pos, struct cpt_context *ctx)
{
	struct mm_struct *mm = current->mm;
	int oldsize = mm->context.size;
	void *oldldt;
	void *newldt;
	int err;

	if (li->cpt_size > PAGE_SIZE)
		newldt = ub_vmalloc(li->cpt_size);
	else
		newldt = (void *)__get_free_page(GFP_KERNEL_UBC);

	if (!newldt)
		return -ENOMEM;

	err = ctx->pread(newldt, li->cpt_size, ctx, pos + li->cpt_hdrlen);
	if (err) {
		if (li->cpt_size > PAGE_SIZE)
			vfree(newldt);
		else
			put_page(virt_to_page(newldt));
		return err;
	}

	oldldt = mm->context.ldt;
	mm->context.ldt = newldt;
	mm->context.size = li->cpt_size/LDT_ENTRY_SIZE;

	load_LDT(&mm->context);

	if (oldsize) {
		if (oldsize*LDT_ENTRY_SIZE > PAGE_SIZE)
			vfree(oldldt);
		else
			put_page(virt_to_page(oldldt));
	}
	return 0;
}
#endif
#endif

static int
restore_aio_ring(struct kioctx *aio_ctx, struct cpt_aio_ctx_image *aimg)
{
	struct aio_ring_info *info = &aio_ctx->ring_info;
	unsigned nr_events = aio_ctx->max_reqs;
	unsigned long size;
	int nr_pages;

	/* We recalculate parameters of the ring exactly like
	 * fs/aio.c does and then compare calculated values
	 * with ones, stored in dump. They must be the same. */

	nr_events += 2;

	size = sizeof(struct aio_ring);
	size += sizeof(struct io_event) * nr_events;
	nr_pages = (size + PAGE_SIZE-1) >> PAGE_SHIFT;

	if (nr_pages != aimg->cpt_ring_pages)
		return -EINVAL;

	info->nr_pages = nr_pages;

	nr_events = (PAGE_SIZE * nr_pages - sizeof(struct aio_ring)) / sizeof(struct io_event);

	if (nr_events != aimg->cpt_nr)
		return -EINVAL;

	info->nr = 0;
	info->ring_pages = info->internal_pages;
	if (nr_pages > AIO_RING_PAGES) {
		info->ring_pages = kmalloc(sizeof(struct page *) * nr_pages, GFP_KERNEL);
		if (!info->ring_pages)
			return -ENOMEM;
		memset(info->ring_pages, 0, sizeof(struct page *) * nr_pages);
	}

	info->mmap_size = nr_pages * PAGE_SIZE;

	/* This piece of shit is not entirely my fault. Kernel aio.c makes
	 * something odd mmap()ping some pages and then pinning them.
	 * I guess it is just some mud remained of failed attempt to show ring
	 * to user space. The result is odd. :-) Immediately after
	 * creation of AIO context, kernel shares those pages with user
	 * and user can read and even write there. But after the first
	 * fork, pages are marked COW with evident consequences.
	 * I remember, I did the same mistake in the first version
	 * of mmapped packet socket, luckily that crap never reached
	 * mainstream.
	 *
	 * So, what are we going to do? I can simulate this odd behaviour
	 * exactly, but I am not insane yet. For now just take the pages
	 * from user space. Alternatively, we could keep kernel copy
	 * in AIO context image, which would be more correct.
	 *
	 * What is wrong now? If the pages are COWed, ring is transferred
	 * incorrectly.
	 */
	down_read(&current->mm->mmap_sem);
	info->mmap_base = aimg->cpt_mmap_base;
	info->nr_pages = get_user_pages(current, current->mm,
					info->mmap_base, nr_pages, 
					1, 0, info->ring_pages, NULL);
	up_read(&current->mm->mmap_sem);

	if (unlikely(info->nr_pages != nr_pages)) {
		int i;

		for (i=0; i<info->nr_pages; i++)
			put_page(info->ring_pages[i]);
		if (info->ring_pages && info->ring_pages != info->internal_pages)
			kfree(info->ring_pages);
		return -EFAULT;
	}

	aio_ctx->user_id = info->mmap_base;

	info->nr = nr_events;
	info->tail = aimg->cpt_tail;

	return 0;
}

static int do_rst_aio(struct cpt_aio_ctx_image *aimg, loff_t pos, cpt_context_t *ctx)
{
	int err;
	struct kioctx *aio_ctx;
	struct ve_struct *ve;

	aio_ctx = kmem_cache_alloc(kioctx_cachep, GFP_KERNEL);
	if (!aio_ctx)
		return -ENOMEM;

	memset(aio_ctx, 0, sizeof(*aio_ctx));
	aio_ctx->max_reqs = aimg->cpt_max_reqs;

	if ((err = restore_aio_ring(aio_ctx, aimg)) < 0) {
		kmem_cache_free(kioctx_cachep, aio_ctx);
		eprintk_ctx("AIO %Ld restore_aio_ring: %d\n", pos, err);
		return err;
	}

	ve = get_exec_env();
	aio_ctx->ve = get_ve(ve);
	spin_lock(&ve->aio_nr_lock);
	ve->aio_nr += aio_ctx->max_reqs;
	spin_unlock(&ve->aio_nr_lock);

	aio_ctx->mm = current->mm;
	atomic_inc(&aio_ctx->mm->mm_count);
	atomic_set(&aio_ctx->users, 1);
	spin_lock_init(&aio_ctx->ctx_lock);
	spin_lock_init(&aio_ctx->ring_info.ring_lock);
	init_waitqueue_head(&aio_ctx->wait);
	INIT_LIST_HEAD(&aio_ctx->active_reqs);
	INIT_LIST_HEAD(&aio_ctx->run_list);
	INIT_DELAYED_WORK(&aio_ctx->wq, aio_kick_handler);

	spin_lock(&aio_ctx->mm->ioctx_lock);
	hlist_add_head(&aio_ctx->list, &aio_ctx->mm->ioctx_list);
	spin_unlock(&aio_ctx->mm->ioctx_lock);

	return 0;
}

struct anonvma_map
{
	struct hlist_node	list;
	struct anon_vma		*avma;
	__u64			id;
};

static int verify_create_anonvma(struct mm_struct *mm,
				 struct cpt_vma_image *vmai,
				 cpt_context_t *ctx)
{
	struct anon_vma *avma = NULL;
	struct anon_vma *new_avma;
	struct vm_area_struct *vma;
	int h;

	if (!ctx->anonvmas) {
		if (CPT_ANONVMA_HSIZE*sizeof(struct hlist_head) > PAGE_SIZE)
			return -EINVAL;
		if ((ctx->anonvmas = (void*)__get_free_page(GFP_KERNEL)) == NULL)
			return -ENOMEM;
		for (h = 0; h < CPT_ANONVMA_HSIZE; h++)
			INIT_HLIST_HEAD(&ctx->anonvmas[h]);
	} else {
		struct anonvma_map *map;
		struct hlist_node *elem;

		h = hash_long((unsigned long)vmai->cpt_anonvmaid, CPT_ANONVMA_HBITS);
		hlist_for_each_entry(map, elem, &ctx->anonvmas[h], list) {
			if (map->id == vmai->cpt_anonvmaid) {
				avma = map->avma;
				break;
			}
		}
	}

	down_read(&mm->mmap_sem);
	if ((vma = find_vma(mm, vmai->cpt_start)) == NULL) {
		up_read(&mm->mmap_sem);
		return -ESRCH;
	}
	if (vma->vm_start != vmai->cpt_start) {
		up_read(&mm->mmap_sem);
		eprintk_ctx("vma start mismatch\n");
		return -EINVAL;
	}
	if (vma->vm_pgoff != vmai->cpt_pgoff) {
		dprintk_ctx("vma pgoff mismatch, fixing\n");
		if (vma->vm_file || (vma->vm_flags&(VM_SHARED|VM_MAYSHARE))) {
			eprintk_ctx("cannot fixup vma pgoff\n");
			up_read(&mm->mmap_sem);
			return -EINVAL;
		}
		vma->vm_pgoff = vmai->cpt_pgoff;
	}

	if (!vma->anon_vma) {
		if (avma) {
			vma->anon_vma = avma;
			if (anon_vma_link(vma)) {
				vma->anon_vma = NULL;
				up_read(&mm->mmap_sem);
				return -ENOMEM;
			}
		} else {
			int err;

			err = anon_vma_prepare(vma);

			if (err) {
				up_read(&mm->mmap_sem);
				return err;
			}
		}
	} else {
		/* Note, we _can_ arrive to the situation, when two
		 * different anonvmaid's point to one anon_vma, this happens
		 * f.e. when mmap() merged new area to previous one and
		 * they will share one anon_vma even if they did not on
		 * original host.
		 *
		 * IT IS OK. To all that I understand, we may merge all
		 * the anon_vma's and rmap can scan all the huge list of vmas
		 * searching for page. It is just "suboptimal".
		 *
		 * Real disaster would happen, if vma already got an anon_vma
		 * with different id. It is very rare case, kernel does the
		 * best efforts to merge anon_vmas when some attributes are
		 * different. In this case we will fall to copying memory.
		 */
		if (avma && vma->anon_vma != avma) {
			up_read(&mm->mmap_sem);
			wprintk_ctx("anon_vma mismatch\n");
			return 0;
		}
	}

	new_avma = vma->anon_vma;
	up_read(&mm->mmap_sem);

	if (!avma) {
		struct anonvma_map *map;

		if (!new_avma)
			return -EINVAL;

		if ((map = kmalloc(sizeof(*map), GFP_KERNEL)) == NULL)
			return -ENOMEM;

		map->id = vmai->cpt_anonvmaid;
		map->avma = new_avma;
		h = hash_long((unsigned long)vmai->cpt_anonvmaid, CPT_ANONVMA_HBITS);
		hlist_add_head(&map->list, &ctx->anonvmas[h]);
	}
	return 0;
}

static int copy_mm_pages(struct mm_struct *src, unsigned long start,
			 unsigned long end)
{
	int err;

	for (; start < end; start += PAGE_SIZE) {
		struct page *page;
		struct page *spage;
		void *maddr, *srcaddr;

		err = get_user_pages(current, current->mm,
				     start, 1, 1, 1, &page, NULL);
		if (err == 0)
			err = -EFAULT;
		if (err < 0)
			return err;

		err = get_user_pages(current, src,
				     start, 1, 0, 1, &spage, NULL);

		if (err == 0)
			err = -EFAULT;
		if (err < 0) {
			page_cache_release(page);
			return err;
		}

		srcaddr = kmap(spage);
		maddr = kmap(page);
		memcpy(maddr, srcaddr, PAGE_SIZE);
		set_page_dirty_lock(page);
		kunmap(page);
		kunmap(spage);
		page_cache_release(page);
		page_cache_release(spage);
	}
	return 0;
}

#include <linux/proc_fs.h>

#ifdef ARCH_HAS_SETUP_ADDITIONAL_PAGES
static int cpt_setup_vdso(unsigned long addr, int is_rhel5)
{
#ifdef CONFIG_COMPAT
	if (test_thread_flag(TIF_IA32))
		return compat_arch_setup_additional_pages(NULL, 0, addr);
#endif
#ifdef CONFIG_X86_64
	if (is_rhel5)
		return arch_setup_additional_pages_rhel5(NULL, 0, addr);
#endif
	return arch_setup_additional_pages(NULL, 0, addr);
}
#else
#define cpt_setup_vdso(addr)	(0)
#endif

static int do_rst_vma(struct cpt_vma_image *vmai, loff_t vmapos, loff_t mmpos,
		struct cpt_context *ctx)
{
	int err = 0;
	unsigned long addr;
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	struct file *file = NULL;
	unsigned long prot;
	int checked = 0;

	if (vmai->cpt_type == CPT_VMA_VDSO || vmai->cpt_type == CPT_VMA_VDSO_OLD) {
		if (ctx->vdso == NULL || !test_thread_flag(TIF_IA32)) {
			int is_rhel5;

			is_rhel5 = (ctx->image_version < CPT_VERSION_32 ||
					vmai->cpt_type == CPT_VMA_VDSO_OLD);

			err = cpt_setup_vdso(vmai->cpt_start, is_rhel5);
			if (err)
				eprintk_ctx("%s: failed to setup vdso: %Ld (rhel5: %d)\n", __func__,
					(unsigned long long)vmai->cpt_start,
					is_rhel5);
			goto out;
		}
	}

	prot = make_prot(vmai);

	if (vmai->cpt_file != CPT_NULL) {
		if (vmai->cpt_type == CPT_VMA_TYPE_0) {
			file = rst_file(vmai->cpt_file, -1, ctx);
			if (IS_ERR(file)) {
				eprintk_ctx("do_rst_vma: rst_file: %Ld\n",
						(unsigned long long)vmai->cpt_file);
				return PTR_ERR(file);
			}
		} else if (vmai->cpt_type == CPT_VMA_TYPE_SHM) {
			file = rst_sysv_shm_vma(vmai, ctx);
			if (IS_ERR(file)) {
				eprintk_ctx("%s: rst_sysv_shm_vma failed: %ld\n",
						__func__, PTR_ERR(file));
				return PTR_ERR(file);
			}
		}
	}

	down_write(&mm->mmap_sem);

	if ((make_flags(vmai) & VM_EXECUTABLE) && mm->exe_file != file)
		set_mm_exe_file(mm, file);

	addr = do_mmap_pgoff(file, vmai->cpt_start,
			     vmai->cpt_end-vmai->cpt_start,
			     prot, make_flags(vmai),
			     vmai->cpt_pgoff);

	if (addr != vmai->cpt_start) {
		up_write(&mm->mmap_sem);

		err = -EINVAL;
		if (IS_ERR((void*)addr))
			err = addr;
		eprintk_ctx("cannot mmap vma %Ld\n", vmapos);
		goto out;
	}

	vma = find_vma(mm, vmai->cpt_start);
	if (vma == NULL) {
		up_write(&mm->mmap_sem);
		eprintk_ctx("cannot find mmapped vma\n");
		err = -ESRCH;
		goto out;
	}

	vma->vm_flags |= VM_NOHUGEPAGE;

	/* do_mmap_pgoff() can merge new area to previous one (not to the next,
	 * we mmap in order, the rest of mm is still unmapped). This can happen
	 * f.e. if flags are to be adjusted later, or if we had different
	 * anon_vma on two adjacent regions. Split it by brute force. */
	if (vma->vm_start != vmai->cpt_start) {
		dprintk_ctx("vma %Ld merged, split\n", vmapos);
		err = split_vma(mm, vma, (unsigned long)vmai->cpt_start, 0);
		if (err) {
			up_write(&mm->mmap_sem);
			eprintk_ctx("cannot split vma\n");
			goto out;
		}
	}
	up_write(&mm->mmap_sem);

	if (vmai->cpt_anonvma && vmai->cpt_anonvmaid) {
		err = verify_create_anonvma(mm, vmai, ctx);
		if (err) {
			eprintk_ctx("cannot verify_create_anonvma %Ld\n", vmapos);
			goto out;
		}
	}

	if (vmai->cpt_type == CPT_VMA_VDSO) {
		struct page *page;
		void *maddr;

		down_read(&mm->mmap_sem);
		err = get_user_pages(current, current->mm,
				(unsigned long)vmai->cpt_start,
				1, 1, 1, &page, NULL);
		up_read(&mm->mmap_sem);
		if (err == 0)
			err = -EFAULT;
		if (err < 0) {
			eprintk_ctx("can't get vdso: get_user_pages: %d\n", err);
			goto out;
		}
		err = 0;
		maddr = kmap(page);
		memcpy(maddr, ctx->vdso, PAGE_SIZE);
		set_page_dirty_lock(page);
		kunmap(page);
		page_cache_release(page);
		goto out;
	}

	if (vmai->cpt_next > vmai->cpt_hdrlen) {
		loff_t offset = vmapos + vmai->cpt_hdrlen;

		do {
			union {
				struct cpt_page_block pb;
				struct cpt_remappage_block rpb;
				struct cpt_copypage_block cpb;
				struct cpt_lazypage_block lpb;
				struct cpt_iterpage_block ipb;
			} u;
			loff_t pos;

			err = rst_get_object(-1, offset, &u, ctx);
			if (err) {
				eprintk_ctx("vma fix object: %d\n", err);
				goto out;
			}
			if (u.rpb.cpt_object == CPT_OBJ_REMAPPAGES) {
				err = sc_remap_file_pages(u.rpb.cpt_start,
							  u.rpb.cpt_end-u.rpb.cpt_start,
							  0, u.rpb.cpt_pgoff, 0);
				if (err < 0) {
					eprintk_ctx("remap_file_pages: %d (%08x,%u,%u)\n", err,
					       (__u32)u.rpb.cpt_start, (__u32)(u.rpb.cpt_end-u.rpb.cpt_start), 
					       (__u32)u.rpb.cpt_pgoff);
					goto out;
				}
				offset += u.rpb.cpt_next;
				continue;
			} else if (u.cpb.cpt_object == CPT_OBJ_LAZYPAGES) {
				err = -EINVAL;
				goto out;
			} else if (u.cpb.cpt_object == CPT_OBJ_COPYPAGES) {
				struct vm_area_struct *vma, *vma1;
				struct mm_struct *src;
				struct anon_vma *src_anon;
				cpt_object_t *mobj;

				if (!vmai->cpt_anonvmaid || !vmai->cpt_anonvma) {
					err = -EINVAL;
					eprintk_ctx("CPT_OBJ_COPYPAGES in !anonvma\n");
					goto out;
				}

				mobj = lookup_cpt_obj_bypos(CPT_OBJ_MM, u.cpb.cpt_source, ctx);
				if (!mobj) {
					eprintk_ctx("lost mm_struct to clone pages from\n");
					err = -ESRCH;
					goto out;
				}
				src = mobj->o_obj;

				down_read(&src->mmap_sem);
				src_anon = NULL;
				vma1 = find_vma(src, u.cpb.cpt_start);
				if (vma1)
					src_anon = vma1->anon_vma;
				up_read(&src->mmap_sem);

				if (!vma1) {
					eprintk_ctx("lost src vm_area_struct\n");
					err = -ESRCH;
					goto out;
				}

				down_read(&mm->mmap_sem);
				if ((vma = find_vma(mm, u.cpb.cpt_start)) == NULL) {
					up_read(&mm->mmap_sem);
					eprintk_ctx("lost vm_area_struct\n");
					err = -ESRCH;
					goto out;
				}

				if (!src_anon ||
				    !vma->anon_vma ||
				    vma->anon_vma != src_anon ||
				    vma->vm_start - vma1->vm_start !=
				    (vma->vm_pgoff - vma1->vm_pgoff) << PAGE_SHIFT) {
					up_read(&mm->mmap_sem);
					wprintk_ctx("anon_vma mismatch in vm_area_struct %Ld\n", vmapos);
					err = copy_mm_pages(mobj->o_obj,
							    u.cpb.cpt_start,
							    u.cpb.cpt_end);
				} else {
					err = __copy_page_range(vma, vma1,
								u.cpb.cpt_start,
								u.cpb.cpt_end-u.cpb.cpt_start);
					up_read(&mm->mmap_sem);
				}
				if (err) {
					eprintk_ctx("clone_page_range: %d (%08x,%u,%ld)\n", err,
						(__u32)u.cpb.cpt_start, (__u32)(u.cpb.cpt_end-u.cpb.cpt_start), 
						(long)u.cpb.cpt_source);
					goto out;
				}

				offset += u.cpb.cpt_next;
				continue;
			} else if (u.pb.cpt_object == CPT_OBJ_ITERPAGES ||
				   u.pb.cpt_object == CPT_OBJ_ITERYOUNGPAGES
				   ) {
#ifdef CONFIG_VZ_CHECKPOINT_ITER
				unsigned long ptr = u.lpb.cpt_start;
				u64 page_pos[16];
				pos = offset + sizeof(u.pb);

				err = ctx->pread(&page_pos,
						 8*(u.lpb.cpt_end-ptr)/PAGE_SIZE,
						 ctx,
						 pos);
				if (err) {
					eprintk_ctx("Oops\n");
					goto out;
				}

				down_read(&mm->mmap_sem);
				if ((vma = find_vma(mm, u.lpb.cpt_start)) == NULL) {
					up_read(&mm->mmap_sem);
					eprintk_ctx("lost vm_area_struct\n");
					err = -ESRCH;
					goto out;
				}
				err = anon_vma_prepare(vma);
				if (err) {
					eprintk_ctx("%s: failed to prepare anon_vma\n", __func__);
					up_read(&mm->mmap_sem);
					goto out;
				}
				while (ptr < u.lpb.cpt_end) {
					err = rst_iter(vma,
						       page_pos[(ptr-u.lpb.cpt_start)/PAGE_SIZE],
						       ptr,
						       ctx);
					if (err) {
						eprintk_ctx("%s: rst_iter failed\n", __func__);
						break;
					}
					ptr += PAGE_SIZE;
				}
				if (u.pb.cpt_object == CPT_OBJ_ITERYOUNGPAGES) {
					make_pages_present((unsigned long)u.lpb.cpt_start,
							   (unsigned long)u.lpb.cpt_end);
				}
				up_read(&mm->mmap_sem);
#else
				err = -EINVAL;
#endif
				if (err)
					goto out;
				offset += u.cpb.cpt_next;
				continue;
			}
			if (u.pb.cpt_object != CPT_OBJ_PAGES) {
				eprintk_ctx("unknown vma fix object %d\n", u.pb.cpt_object);
				err = -EINVAL;
				goto out;
			}
			pos = offset + sizeof(u.pb);
			if (!(vmai->cpt_flags&VM_ACCOUNT) && !(prot&PROT_WRITE) &&
			    u.pb.cpt_content != CPT_CONTENT_PRAM) {
				/* I guess this is get_user_pages() messed things,
				 * this happens f.e. when gdb inserts breakpoints.
				 */
				int i;
				for (i=0; i<(u.pb.cpt_end-u.pb.cpt_start)/PAGE_SIZE; i++) {
					struct page *page;
					void *maddr;
					err = get_user_pages(current, current->mm,
							     (unsigned long)u.pb.cpt_start + i*PAGE_SIZE,
							     1, 1, 1, &page, NULL);
					if (err == 0)
						err = -EFAULT;
					if (err < 0) {
						eprintk_ctx("get_user_pages: %d\n", err);
						goto out;
					}
					err = 0;
					maddr = kmap(page);
					if (u.pb.cpt_content == CPT_CONTENT_VOID) {
						memset(maddr, 0, PAGE_SIZE);
					} else if (u.pb.cpt_content == CPT_CONTENT_DATA) {
						err = ctx->pread(maddr, PAGE_SIZE,
								 ctx, pos + i*PAGE_SIZE);
						if (err)
							eprintk_ctx("%s: ctx->pread failed\n", __func__);
					} else {
						eprintk_ctx("%s: unsupported cpt content (1): %d\n", __func__, u.pb.cpt_content);
						err = -EINVAL;
					}
					if (!err)
						set_page_dirty_lock(page);
					kunmap(page);
					page_cache_release(page);
					if (err)
						goto out;
				}
			} else {
				if (!(prot&PROT_WRITE))
					sc_mprotect(vmai->cpt_start, vmai->cpt_end-vmai->cpt_start, prot | PROT_WRITE);
				if (u.pb.cpt_content == CPT_CONTENT_VOID) {
					int i;
					for (i=0; i<(u.pb.cpt_end-u.pb.cpt_start)/sizeof(unsigned long); i++) {
						err = __put_user(0UL, ((unsigned long __user*)(unsigned long)u.pb.cpt_start) + i);
						if (err) {
							eprintk_ctx("__put_user 2 %d\n", err);
							goto out;
						}
					}
				} else if (u.pb.cpt_content == CPT_CONTENT_DATA) {
					/*
					 * If this is a socket buffer mapping, all pages must be already there,
					 * so there is no need in optimizing out page faults.
					 */
					if ((vma->vm_file && !S_ISSOCK(vma->vm_file->f_dentry->d_inode->i_mode)) ||
						((vma->vm_flags & VM_GROWSDOWN) && u.pb.cpt_start == vma->vm_start))
					{
						struct vm_area_struct *vma;
						struct page *page;
						unsigned long addr;

						/* Fill the area with zero pages in order to avoid IO
						 * caused by page faults.
						 */
						down_read(&mm->mmap_sem);
						if ((vma = find_vma(mm, u.pb.cpt_start)) == NULL) {
							up_read(&mm->mmap_sem);
							eprintk_ctx("lost vm_area_struct\n");
							err = -ESRCH;
							goto out;
						}
						for (addr=u.pb.cpt_start; addr<u.pb.cpt_end; addr+=PAGE_SIZE) {
							err = -ENOMEM;
							page = alloc_zeroed_user_highpage_movable(vma, addr);
							if (!page) {
								eprintk_ctx("%s: failed to alloc zeroed high page\n", __func__);
								break;
							}
							err = install_anon_page(mm, vma, addr, page);
							if (err) {
								eprintk_ctx("install_anon_page: %d\n", err);
								put_page(page);
								break;
							}
						}
						up_read(&mm->mmap_sem);
						if (err)
							goto out;
					}

					err = ctx->pread(cpt_ptr_import(u.pb.cpt_start), 
							 u.pb.cpt_end-u.pb.cpt_start,
							 ctx, pos);
					if (err) {
						eprintk_ctx("%s: VMA context read failed: 0x%Lx - 0x%Lx\n", __func__, vmai->cpt_start, vmai->cpt_end);
						goto out;
					}
				} else if (u.pb.cpt_content == CPT_CONTENT_PRAM) {
					err = rst_undump_pram(mm, u.pb.cpt_start, u.pb.cpt_end, pos, ctx);
					if (err) {
						eprintk_ctx("%s: PRAM undump failed: start %Ld, end %Ld\n", __func__, u.pb.cpt_start, u.pb.cpt_end);
						goto out;
					}
				} else {
					err = -EINVAL;
					eprintk_ctx("%s: unsupported cpt content (2): %d\n", __func__, u.pb.cpt_content);
					goto out;
				}
				if (!(prot&PROT_WRITE))
					sc_mprotect(vmai->cpt_start, vmai->cpt_end-vmai->cpt_start, prot);
			}
			err = 0;
			offset += u.pb.cpt_next;
		} while (offset < vmapos + vmai->cpt_next);
	}

check:
	do {
		struct vm_area_struct *vma;
		down_read(&mm->mmap_sem);
		vma = find_vma(mm, addr);
		if (vma) {

			if (!(vmai->cpt_flags & VM_NOHUGEPAGE))
				vma->vm_flags &= ~VM_NOHUGEPAGE;

			if ((vma->vm_flags^vmai->cpt_flags)&VM_READHINTMASK) {
				VM_ClearReadHint(vma);
				vma->vm_flags |= vmai->cpt_flags&VM_READHINTMASK;
			}
			if ((vma->vm_flags^vmai->cpt_flags)&VM_LOCKED) {
				dprintk_ctx("fixing up VM_LOCKED %Ld\n", vmapos);
				up_read(&mm->mmap_sem);
				if (vma->vm_flags&VM_LOCKED)
					err = __munlock(vmai->cpt_start, vmai->cpt_end-vmai->cpt_start, false);
				else {
					int ret;
					int should_set_cap;
					unsigned long locked;
					unsigned long lock_limit;

					locked = ((vmai->cpt_end - vmai->cpt_start) >> PAGE_SHIFT) +
					          current->mm->locked_vm;
					lock_limit = current->signal->rlim[RLIMIT_MEMLOCK].rlim_cur >> PAGE_SHIFT;
					should_set_cap = ((locked > lock_limit) && !capable(CAP_IPC_LOCK));
					if (unlikely(should_set_cap)) {
						if ((err = set_mlock_creds(1)) != 0) {
							eprintk_ctx("set_mlock_creds: %d\n", err);
							goto out;
						}
					}

					ret = __mlock(vmai->cpt_start, vmai->cpt_end-vmai->cpt_start, false);

					if (unlikely(should_set_cap)) {
						if ((err = set_mlock_creds(0)) != 0) {
							eprintk_ctx("set_mlock_creds: %d\n", err);
							goto out;
						}
					}
					err = ret;
				}
				/* When mlock fails with EFAULT, it means
				 * that it could not bring in pages.
				 * It can happen after mlock() on unreadable
				 * VMAs. But VMA is correctly locked,
				 * so that this error can be ignored. */
				if (err == -EFAULT)
					err = 0;
				if (err) {
					eprintk_ctx("%s: sc_m(un)lock failed\n", __func__);
					goto out;
				}
				goto check;
			}
			if ((vma->vm_page_prot.pgprot^vmai->cpt_pgprot)&~__PAGE_NX)
				wprintk_ctx("VMA %08lx@%ld pgprot mismatch %08Lx %08Lx\n", addr, (long)vmapos,
					    (unsigned long long)vma->vm_page_prot.pgprot,
					    (unsigned long long)vmai->cpt_pgprot);
#if defined(CONFIG_X86_PAE) || defined(CONFIG_X86_64)
			if (((vma->vm_page_prot.pgprot^vmai->cpt_pgprot)&__PAGE_NX) &&
			    (ctx->kernel_config_flags & (1 << CPT_KERNEL_CONFIG_PAE)))
				wprintk_ctx("VMA %08lx@%ld pgprot mismatch %08Lx %08Lx\n", addr, (long)vmapos,
				       (__u64)vma->vm_page_prot.pgprot, (__u64)vmai->cpt_pgprot);
#endif
			if (vma->vm_flags != vmai->cpt_flags) {
				unsigned long x = vma->vm_flags ^ vmai->cpt_flags;
				if (x & VM_EXEC) {
					/* Crap. On i386 this is OK.
					 * It is impossible to make via mmap/mprotect
					 * exec.c clears VM_EXEC on stack. */
					vma->vm_flags &= ~VM_EXEC;
				} else if ((x & VM_ACCOUNT) && !checked) {
					checked = 1;
					if (!(prot&PROT_WRITE)) {
						up_read(&mm->mmap_sem);
						sc_mprotect(vmai->cpt_start, vmai->cpt_end-vmai->cpt_start, prot | PROT_WRITE);
						sc_mprotect(vmai->cpt_start, vmai->cpt_end-vmai->cpt_start, prot);
						goto check;
					}
					wprintk_ctx("VMA %08lx@%ld flag mismatch %08x %08x\n", addr, (long)vmapos,
					       (__u32)vma->vm_flags, (__u32)vmai->cpt_flags);
				} else {
					wprintk_ctx("VMA %08lx@%ld flag mismatch %08x %08x\n", addr, (long)vmapos,
					       (__u32)vma->vm_flags, (__u32)vmai->cpt_flags);
				}
			}
		} else {
			wprintk_ctx("no VMA for %08lx@%ld\n", addr, (long)vmapos);
		}
		up_read(&mm->mmap_sem);
	} while (0);

out:
	if (file)
		fput(file);
	return err;
}

static int do_rst_auxv(struct cpt_object_hdr *hdr, loff_t pos,
		       cpt_context_t *ctx)
{
	struct mm_struct *mm = current->mm;
	__u64 auxv[AT_VECTOR_SIZE];
	unsigned idx, nwords;
	int err;

	nwords = (hdr->cpt_next - hdr->cpt_hdrlen) / sizeof(auxv[0]);
	if (nwords > AT_VECTOR_SIZE - 2)
		return -E2BIG;

	err = ctx->pread(auxv, nwords * sizeof(auxv[0]), ctx,
			pos + hdr->cpt_hdrlen);
	if (!err) {
		mm->saved_auxv[nwords] = 0;
		mm->saved_auxv[nwords + 1] = 0;
		for (idx = 0; idx < nwords; idx++)
			mm->saved_auxv[idx] = auxv[idx];
	}
	return err;
}

#ifndef CONFIG_IA64
#define TASK_UNMAP_START	0
#else
/* On IA64 the first page is a special VM_IO|VM_RESERVED mapping
 * used to accelerate speculative dereferences of NULL pointer. */
#define TASK_UNMAP_START	PAGE_SIZE
#endif

static int do_rst_mm(struct cpt_mm_image *vmi, struct cpt_task_image *ti,
		struct cpt_context *ctx)
{
	int err = 0;
	unsigned int def_flags;
	struct mm_struct *mm = current->mm;
	struct ve_struct *ve = get_exec_env();
#ifdef CONFIG_BEANCOUNTERS
	struct user_beancounter *bc;
#endif

	down_write(&mm->mmap_sem);
	do_munmap(mm, TASK_UNMAP_START, TASK_SIZE-TASK_UNMAP_START);

#ifdef CONFIG_BEANCOUNTERS
	/*
	 * MM beancounter is usually correct from the fork time,
	 * but not for init, for example.
	 * Luckily, mm_ub can be changed for a completely empty MM.
	 */
	bc = rst_lookup_ubc(vmi->cpt_mmub, ctx);
	put_beancounter(bc);
#endif

	mm->start_code = vmi->cpt_start_code;
	mm->end_code = vmi->cpt_end_code;
	mm->start_data = vmi->cpt_start_data;
	mm->end_data = vmi->cpt_end_data;
	mm->start_brk = vmi->cpt_start_brk;
	mm->brk = vmi->cpt_brk;
	mm->start_stack = vmi->cpt_start_stack;
	mm->arg_start = vmi->cpt_start_arg;
	mm->arg_end = vmi->cpt_end_arg;
	mm->env_start = vmi->cpt_start_env;
	mm->env_end = vmi->cpt_end_env;
	mm->def_flags = 0;
	def_flags = vmi->cpt_def_flags;

#ifdef CONFIG_X86_64
	if (!ti->cpt_64bit) {
		set_thread_flag(TIF_IA32);
		/*
		 * Task forked from 64bit app and thus has wrong binfmt pointer
		 */
#ifdef CONFIG_IA32_EMULATION
		set_binfmt(&compat_elf_format);
#endif
	} else if (test_thread_flag(TIF_IA32)) {
		clear_thread_flag(TIF_IA32);
		/*
		 * Task forked from 32bit app and thus has wrong binfmt pointer
		 */
#ifdef CONFIG_IA32_EMULATION
		set_binfmt(&compat_elf_format);
#else
		set_binfmt(&elf_format);
#endif
	}
	mm->free_area_cache = TASK_UNMAPPED_BASE;
	arch_pick_mmap_layout(mm);
#endif

	if (cpt_object_has(vmi, cpt_mm_flags))
		mm->flags = vmi->cpt_mm_flags;
	else
		set_dumpable(mm, vmi->cpt_dumpable);

	mm->vps_dumpable = vmi->cpt_vps_dumpable;
#ifndef CONFIG_IA64
	if (ctx->image_version >= CPT_VERSION_9) {
		mm->context.vdso = cpt_ptr_import(vmi->cpt_vdso);
		current_thread_info()->sysenter_return = 
			VDSO32_SYMBOL(mm->context.vdso, SYSENTER_RETURN);
	}
#endif

#if 0 /* def CONFIG_HUGETLB_PAGE*/
/* NB: ? */
	int used_hugetlb;
#endif
	up_write(&mm->mmap_sem);

	if (vmi->cpt_next > vmi->cpt_hdrlen) {
		loff_t offset = ti->cpt_mm + vmi->cpt_hdrlen;
		do {
			union {
				struct cpt_object_hdr hdr;
				struct cpt_vma_image vmai;
				struct cpt_aio_ctx_image aioi;
				struct cpt_obj_bits bits;
			} u;
			err = rst_get_object(-1, offset, &u, ctx);
			if (err)
				goto out;
			if (u.vmai.cpt_object == CPT_OBJ_VMA) {
#ifdef CONFIG_IA64
				//// Later...
				if (u.vmai.cpt_start)
#endif
				err = do_rst_vma(&u.vmai, offset, ti->cpt_mm, ctx);
				if (err) {
					eprintk_ctx("%s: failed to restore vma 0x%08Lx-0x%08Lx: %d\n",
							__func__, u.vmai.cpt_start, u.vmai.cpt_end, err);
					goto out;
				}
#ifdef CONFIG_X86
			} else if (u.bits.cpt_object == CPT_OBJ_BITS &&
				   u.bits.cpt_content == CPT_CONTENT_MM_CONTEXT) {
				err = do_rst_ldt(&u.bits, offset, ctx);
				if (err) {
					eprintk_ctx("%s: failed to restore ldt: %d\n",
							__func__, err);
					goto out;
				}
#endif
			} else if (u.aioi.cpt_object == CPT_OBJ_AIO_CONTEXT) {
				err = do_rst_aio(&u.aioi, offset, ctx);
				if (err) {
					eprintk_ctx("%s: failed to restore aio: %d\n",
							__func__, err);
					goto out;
				}
			} else if (u.hdr.cpt_object == CPT_OBJ_MM_AUXV) {
				err = do_rst_auxv(&u.hdr, offset, ctx);
				if (err) {
					eprintk_ctx("%s: failed to restore auxv: %d\n",
							__func__, err);
					goto out;
				}
			} else {
				eprintk_ctx("unknown object %u in mm image\n",
						u.vmai.cpt_object);
				err = -EINVAL;
				goto out;
			}
			offset += u.vmai.cpt_next;
		} while (offset < ti->cpt_mm + vmi->cpt_next);
	}

	down_write(&mm->mmap_sem);
	mm->def_flags = def_flags;
	up_write(&mm->mmap_sem);

	if (ve->aio_nr > ve->aio_max_nr)
		wprintk_ctx("aio-nr=%lu exceed aio-max-nr=%lu\n",
				ve->aio_nr, ve->aio_max_nr);
out:
	return err;
}

extern void exit_mm(struct task_struct * tsk);

int rst_mm_complete(struct cpt_task_image *ti, struct cpt_context *ctx)
{
	int err = 0;
	cpt_object_t *mobj;
	void *tmp = (void*)__get_free_page(GFP_KERNEL);
	struct cpt_mm_image *vmi = (struct cpt_mm_image *)tmp;

	if (!tmp)
		return -ENOMEM;

	if (ti->cpt_mm == CPT_NULL) {
		if (current->mm)
			exit_mm(current);
		goto out;
	}

	mobj = lookup_cpt_obj_bypos(CPT_OBJ_MM, ti->cpt_mm, ctx);
	if (mobj) {
		if (current->mm != mobj->o_obj) BUG();
		goto out;
	}

	if (current->mm == NULL) {
		struct mm_struct *mm = mm_alloc();
		if (mm == NULL) {
			err = -ENOMEM;
			goto out;
		}
		err = init_new_context(current, mm);
		if (err) {
			mmdrop(mm);
			goto out;
		}
		current->mm = mm;
	}

	if ((err = rst_get_object(CPT_OBJ_MM, ti->cpt_mm, vmi, ctx)) != 0)
		goto out;
	if ((err = do_rst_mm(vmi, ti, ctx)) != 0) {
		eprintk_ctx("do_rst_mm %Ld\n", (unsigned long long)ti->cpt_mm);
		goto out;
	}
	err = -ENOMEM;
	mobj = cpt_object_add(CPT_OBJ_MM, current->mm, ctx);
	if (mobj != NULL) {
		err = 0;
		cpt_obj_setpos(mobj, ti->cpt_mm, ctx);
	}

out:
	if (tmp)
		free_page((unsigned long)tmp);
	return err;
}

/* This is part of mm setup, made in parent context. Mostly, it is the place,
 * where we graft mm of another process to child.
 */

int rst_mm_basic(cpt_object_t *obj, struct cpt_task_image *ti, struct cpt_context *ctx)
{
	struct task_struct *tsk = obj->o_obj;
	cpt_object_t *mobj;

	/* Task without mm. Just get rid of this. */
	if (ti->cpt_mm == CPT_NULL) {
		if (tsk->mm) {
			mmput(tsk->mm);
			tsk->mm = NULL;
		}
		return 0;
	}

	mobj = lookup_cpt_obj_bypos(CPT_OBJ_MM, ti->cpt_mm, ctx);
	if (mobj) {
		struct mm_struct *newmm = mobj->o_obj;
		/* Good, the MM is already created. */
		if (newmm == tsk->mm) {
			/* Already done by clone(). */
			return 0;
		}
		mmput(tsk->mm);
		atomic_inc(&newmm->mm_users);
		tsk->mm = newmm;
		tsk->active_mm = newmm;
	}
	return 0;
}

/* We use CLONE_VM when mm of child is going to be shared with parent.
 * Otherwise mm is copied.
 */

__u32 rst_mm_flag(struct cpt_task_image *ti, struct cpt_context *ctx)
{
	if (ti->cpt_mm == CPT_NULL ||
	    lookup_cpt_obj_bypos(CPT_OBJ_MM, ti->cpt_mm, ctx))
		return CLONE_VM;
	return 0;
}
