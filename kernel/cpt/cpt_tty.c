/*
 *
 *  kernel/cpt/cpt_tty.c
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
#include <linux/tty.h>
#include <linux/tty.h>
#include <linux/nsproxy.h>
#include <asm/uaccess.h>
#include <linux/cpt_image.h>

#include <linux/cpt_obj.h>
#include <linux/cpt_context.h>

#include "cpt_process.h"

/* We must support at least N_TTY. */

int cpt_dump_content_tty(struct file *file, struct cpt_context *ctx)
{
	struct tty_struct *tty = file_tty(file);
	cpt_object_t *obj;
	struct cpt_obj_ref o;
	loff_t saved_pos;

	obj = lookup_cpt_object(CPT_OBJ_TTY, tty, ctx);
	if (!obj)
		return -EINVAL;

	cpt_push_object(&saved_pos, ctx);

	o.cpt_next = sizeof(o);
	o.cpt_object = CPT_OBJ_REF;
	o.cpt_hdrlen = sizeof(o);
	o.cpt_content = CPT_CONTENT_VOID;
	o.cpt_pos = obj->o_pos;
	ctx->write(&o, sizeof(o), ctx);

	cpt_pop_object(&saved_pos, ctx);

	return 0;
}

int cpt_collect_tty(struct file *file, cpt_context_t * ctx)
{
	struct tty_struct *tty = file_tty(file);
	cpt_object_t *obj;
	dev_t dev = file->f_dentry->d_inode->i_rdev;

	if (tty) {
		obj = cpt_object_add(CPT_OBJ_TTY, tty, ctx);
		if (obj == NULL)
			return -ENOMEM;
		if (MAJOR(dev) == TTY_MAJOR || dev == MKDEV(TTYAUX_MAJOR, 1)) {
			obj->o_flags |= CPT_TTY_NOPAIR;
		} else if (tty->link) {
			obj = cpt_object_add(CPT_OBJ_TTY, tty->link, ctx);
			if (obj == NULL)
				return -ENOMEM;
			/* Undo o_count, tty->link is not a reference */
			obj->o_count--;
		}
	}
	return 0;
}

int cpt_dump_tty(cpt_object_t *obj, struct cpt_context *ctx)
{
	struct tty_struct *tty = obj->o_obj;
	struct cpt_tty_image *v;

	if (tty->link) {
		if (!(obj->o_flags & CPT_TTY_NOPAIR) &&
		    lookup_cpt_object(CPT_OBJ_TTY, tty->link, ctx) == NULL) {
			eprintk_ctx("orphan pty %s %d\n", tty->name, tty->driver->subtype == PTY_TYPE_SLAVE);
			return -EINVAL;
		}
		if (tty->link->link != tty) {
			eprintk_ctx("bad pty pair\n");
			return -EINVAL;
		}
		if (tty->driver->type == TTY_DRIVER_TYPE_PTY &&
		    tty->driver->subtype == PTY_TYPE_SLAVE &&
		    tty->link->count)
			obj->o_count++;
		if (test_bit(TTY_EXTRA_REFERENCE, &tty->flags))
			obj->o_count++;
	}
	if (obj->o_count != tty->count) {
		eprintk_ctx("tty %s is referenced outside %d %d\n", tty->name, obj->o_count, tty->count);
		return -EBUSY;
	}

	cpt_open_object(obj, ctx);

	v = cpt_get_buf(ctx);
	v->cpt_next = -1;
	v->cpt_object = CPT_OBJ_TTY;
	v->cpt_hdrlen = sizeof(*v);
	v->cpt_content = CPT_CONTENT_ARRAY;

	v->cpt_index = tty->index;
	v->cpt_link = -1;
	if (tty->link)
		v->cpt_link = tty->link->index;
	v->cpt_drv_type = tty->driver->type;
	v->cpt_drv_subtype = tty->driver->subtype;
	v->cpt_drv_flags = tty->driver->flags;
	v->cpt_packet = tty->packet;
	v->cpt_stopped = tty->stopped;
	v->cpt_hw_stopped = tty->hw_stopped;
	v->cpt_flow_stopped = tty->flow_stopped;
	v->cpt_flags = tty->flags;
	v->cpt_ctrl_status = tty->ctrl_status;
	v->cpt_canon_data = tty->canon_data;
	v->cpt_canon_head = tty->canon_head - tty->read_tail;
	v->cpt_canon_column = tty->canon_column;
	v->cpt_column = tty->column;
	v->cpt_erasing = tty->erasing;
	v->cpt_lnext = tty->lnext;
	v->cpt_icanon = tty->icanon;
	v->cpt_raw = tty->raw;
	v->cpt_real_raw = tty->real_raw;
	v->cpt_closing = tty->closing;
	v->cpt_minimum_to_wake = tty->minimum_to_wake;
	v->cpt_pgrp = 0;
	if (tty->pgrp) {
		v->cpt_pgrp = cpt_pid_nr(tty->pgrp);
		if ((int)v->cpt_pgrp < 0) {
			dprintk_ctx("cannot map tty->pgrp %d -> %d\n", cpt_pid_nr(tty->pgrp), (int)v->cpt_pgrp);
			v->cpt_pgrp = -1;
		}
	}
	v->cpt_session = 0;
	if (tty->session) {
		v->cpt_session = cpt_pid_nr(tty->session);
		if ((int)v->cpt_session < 0) {
			eprintk_ctx("cannot map tty->session %d -> %d\n", pid_nr(tty->session), (int)v->cpt_session);
			cpt_release_buf(ctx);
			return -EINVAL;
		}
	}
	memcpy(v->cpt_name, tty->name, 64);
	v->cpt_ws_row = tty->winsize.ws_row;
	v->cpt_ws_col = tty->winsize.ws_col;
	v->cpt_ws_prow = tty->winsize.ws_ypixel;
	v->cpt_ws_pcol = tty->winsize.ws_xpixel;
	if (tty->termios == NULL) {
		eprintk_ctx("NULL termios\n");
		cpt_release_buf(ctx);
		return -EINVAL;
	}
	v->cpt_c_line = tty->termios->c_line;
	v->cpt_c_iflag = tty->termios->c_iflag;
	v->cpt_c_oflag = tty->termios->c_oflag;
	v->cpt_c_cflag = tty->termios->c_cflag;
	v->cpt_c_lflag = tty->termios->c_lflag;
	memcpy(v->cpt_c_cc, tty->termios->c_cc, NCCS);
	if (NCCS < 32)
		memset(v->cpt_c_cc + NCCS, 255, 32 - NCCS);
	memcpy(v->cpt_read_flags, tty->read_flags, sizeof(v->cpt_read_flags));

	ctx->write(v, sizeof(*v), ctx);
	cpt_release_buf(ctx);

	if (tty->read_buf && tty->read_cnt) {
		struct cpt_obj_bits *v = cpt_get_buf(ctx);
		loff_t saved_pos;

		cpt_push_object(&saved_pos, ctx);
		cpt_open_object(NULL, ctx);
		v->cpt_next = CPT_NULL;
		v->cpt_object = CPT_OBJ_BITS;
		v->cpt_hdrlen = sizeof(*v);
		v->cpt_content = CPT_CONTENT_DATA;
		v->cpt_size = tty->read_cnt;
		ctx->write(v, sizeof(*v), ctx);
		cpt_release_buf(ctx);

		if (tty->read_cnt) {
			int n = min(tty->read_cnt, N_TTY_BUF_SIZE - tty->read_tail);
			ctx->write(tty->read_buf + tty->read_tail, n, ctx);
			if (tty->read_cnt > n)
				ctx->write(tty->read_buf, tty->read_cnt-n, ctx);
			ctx->align(ctx);
		}

		cpt_close_object(ctx);
		cpt_pop_object(&saved_pos, ctx);
	}

	cpt_close_object(ctx);

	return 0;
}

__u32 cpt_tty_fasync(struct file *file, struct cpt_context *ctx)
{
	struct tty_struct * tty;
	struct fasync_struct *fa;

	tty = (struct tty_struct *)file_tty(file);

	for (fa = tty->fasync; fa; fa = fa->fa_next) {
		if (fa->fa_file == file)
			return fa->fa_fd;
	}
	return -1;
}
