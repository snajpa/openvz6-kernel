/*
 *
 *  kernel/cpt/cpt_epoll.c
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

int cpt_dump_epolldev(cpt_object_t *obj, cpt_context_t *ctx)
{
	int err = 0;
	struct file *file = obj->o_obj;
	struct eventpoll *ep;
	struct rb_node *rbp;
	struct cpt_epoll_image ei;

	if (file->f_op != &eventpoll_fops) {
		eprintk_ctx("bad epoll file\n");
		return -EINVAL;
	}

	ep = file->private_data;

	/* eventpoll.c does not protect open /proc/N/fd, silly.
	 * Opener will get an invalid file with uninitialized private_data
	 */
	if (unlikely(ep == NULL)) {
		eprintk_ctx("bad epoll device\n");
		return -EINVAL;
	}

	cpt_open_object(NULL, ctx);

	ei.cpt_next = CPT_NULL;
	ei.cpt_object = CPT_OBJ_EPOLL;
	ei.cpt_hdrlen = sizeof(ei);
	ei.cpt_content = CPT_CONTENT_ARRAY;
	ei.cpt_file = obj->o_pos;

	ctx->write(&ei, sizeof(ei), ctx);

	mutex_lock(&epmutex);
	for (rbp = rb_first(&ep->rbr); rbp; rbp = rb_next(rbp)) {
		loff_t saved_obj;
		cpt_object_t *tobj;
		struct cpt_epoll_file_image efi;
		struct epitem *epi;
		epi = rb_entry(rbp, struct epitem, rbn);
		tobj = lookup_cpt_object(CPT_OBJ_FILE, epi->ffd.file, ctx);
		if (tobj == NULL) {
			eprintk_ctx("epoll device refers to an external file\n");
			err = -EBUSY;
			break;
		}
		cpt_push_object(&saved_obj, ctx);
		cpt_open_object(NULL, ctx);

		efi.cpt_next = CPT_NULL;
		efi.cpt_object = CPT_OBJ_EPOLL_FILE;
		efi.cpt_hdrlen = sizeof(efi);
		efi.cpt_content = CPT_CONTENT_VOID;
		efi.cpt_file = tobj->o_pos;
		efi.cpt_fd = epi->ffd.fd;
		efi.cpt_events = epi->event.events;
		efi.cpt_data = epi->event.data;
		efi.cpt_revents = 0;
		efi.cpt_ready = 0;
		if (!list_empty(&epi->rdllink))
			efi.cpt_ready = 1;

		ctx->write(&efi, sizeof(efi), ctx);
		cpt_close_object(ctx);
		cpt_pop_object(&saved_obj, ctx);
	}
	mutex_unlock(&epmutex);

	cpt_close_object(ctx);

	return err;
}

