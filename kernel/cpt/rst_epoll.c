/*
 *
 *  kernel/cpt/rst_epoll.c
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
#include <linux/errno.h>
#include <linux/major.h>
#include <linux/pipe_fs_i.h>
#include <linux/mman.h>
#include <linux/mnt_namespace.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/smp_lock.h>
#include <asm/uaccess.h>
#include <linux/vzcalluser.h>
#include <linux/eventpoll.h>
#include <linux/cpt_image.h>

#include <linux/cpt_obj.h>
#include <linux/cpt_context.h>
#include "cpt_mm.h"
#include "cpt_files.h"
#include "cpt_kernel.h"
#include "cpt_fsmagic.h"
#include "cpt_syscalls.h"

struct file *cpt_open_epolldev(struct cpt_file_image *fi,
			       unsigned flags,
			       struct cpt_context *ctx)
{
	struct file *file;
	int efd;

	/* Argument "size" is ignored, use just 1 */
	efd = sys_epoll_create(1);
	if (efd < 0)
		return ERR_PTR(efd);

	file = fget(efd);
	sys_close(efd);
	return file;
}

static int restore_one_epoll(cpt_object_t *obj,
			     loff_t pos,
			     struct cpt_epoll_image *ebuf,
			     cpt_context_t *ctx)
{
	int err = 0;
	loff_t endpos;
	struct file *file = obj->o_obj;
	struct eventpoll *ep;

	if (file->f_op != &eventpoll_fops) {
		eprintk_ctx("bad epoll file\n");
		return -EINVAL;
	}

	ep = file->private_data;

	if (unlikely(ep == NULL)) {
		eprintk_ctx("bad epoll device\n");
		return -EINVAL;
	}

	endpos = pos + ebuf->cpt_next;
	pos += ebuf->cpt_hdrlen;
	while (pos < endpos) {
		struct cpt_epoll_file_image efi;
		struct epoll_event epds;

		cpt_object_t *tobj;

		err = rst_get_object(CPT_OBJ_EPOLL_FILE, pos, &efi, ctx);
		if (err)
			return err;
		tobj = lookup_cpt_obj_bypos(CPT_OBJ_FILE, efi.cpt_file, ctx);
		if (!tobj) {
			eprintk_ctx("epoll file not found\n");
			return -EINVAL;
		}
		epds.events = efi.cpt_events;
		epds.data = efi.cpt_data;
		mutex_lock(&epmutex);
		mutex_lock(&ep->mtx);
		err = ep_insert(ep, &epds, tobj->o_obj, efi.cpt_fd, 1);
		clear_tfile_check_list();
		if (!err) {
			struct epitem *epi;
			epi = ep_find(ep, tobj->o_obj, efi.cpt_fd);
			if (epi) {
				if (efi.cpt_ready) {
					unsigned long flags;
					spin_lock_irqsave(&ep->lock, flags);
					if (list_empty(&epi->rdllink))
						list_add_tail(&epi->rdllink, &ep->rdllist);
					spin_unlock_irqrestore(&ep->lock, flags);
				}
			}
		}
		mutex_unlock(&ep->mtx);
		mutex_unlock(&epmutex);
		if (err)
			break;
		pos += efi.cpt_next;
	}
	return err;
}

int rst_eventpoll(cpt_context_t *ctx)
{
	int err;
	loff_t sec = ctx->sections[CPT_SECT_EPOLL];
	loff_t endsec;
	struct cpt_section_hdr h;

	if (sec == CPT_NULL)
		return 0;

	err = ctx->pread(&h, sizeof(h), ctx, sec);
	if (err)
		return err;
	if (h.cpt_section != CPT_SECT_EPOLL || h.cpt_hdrlen < sizeof(h))
		return -EINVAL;

	endsec = sec + h.cpt_next;
	sec += h.cpt_hdrlen;
	while (sec < endsec) {
		cpt_object_t *obj;
		struct cpt_epoll_image *ebuf = cpt_get_buf(ctx);
		err = rst_get_object(CPT_OBJ_EPOLL, sec, ebuf, ctx);
		if (err) {
			cpt_release_buf(ctx);
			return err;
		}
		obj = lookup_cpt_obj_bypos(CPT_OBJ_FILE, ebuf->cpt_file, ctx);
		if (obj == NULL) {
			eprintk_ctx("cannot find epoll file object\n");
			cpt_release_buf(ctx);
			return -EINVAL;
		}
		err = restore_one_epoll(obj, sec, ebuf, ctx);
		cpt_release_buf(ctx);
		if (err)
			return err;
		sec += ebuf->cpt_next;
	}
	return 0;
}
