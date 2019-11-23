/*
 *
 *  kernel/cpt/rst_tty.c
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
#include <linux/mount.h>
#include <linux/tty.h>
#include <linux/vmalloc.h>
#include <linux/nsproxy.h>
#include <asm/unistd.h>
#include <asm/uaccess.h>
#include <linux/cpt_image.h>

#include <linux/cpt_obj.h>
#include <linux/cpt_context.h>
#include "cpt_mm.h"
#include "cpt_process.h"
#include "cpt_files.h"
#include "cpt_kernel.h"

static int pty_setup(struct tty_struct *stty, loff_t pos,
		     struct cpt_tty_image *pi, struct cpt_context *ctx)
{
	stty->pgrp = NULL;
	stty->session = NULL;
	stty->packet = pi->cpt_packet;
	stty->stopped = pi->cpt_stopped;
	stty->hw_stopped = pi->cpt_hw_stopped;
	stty->flow_stopped = pi->cpt_flow_stopped;
#define TTY_BEHAVIOR_FLAGS ((1<<TTY_EXCLUSIVE)|(1<<TTY_HW_COOK_OUT)| \
				(1<<TTY_HW_COOK_IN)|(1<<TTY_PTY_LOCK))
	stty->flags &= ~TTY_BEHAVIOR_FLAGS;
	stty->flags |= pi->cpt_flags & TTY_BEHAVIOR_FLAGS;
	stty->ctrl_status = pi->cpt_ctrl_status;
	stty->winsize.ws_row = pi->cpt_ws_row;
	stty->winsize.ws_col = pi->cpt_ws_col;
	stty->winsize.ws_ypixel = pi->cpt_ws_prow;
	stty->winsize.ws_xpixel = pi->cpt_ws_pcol;
	stty->canon_column = pi->cpt_canon_column;
	stty->column = pi->cpt_column;
	stty->raw = pi->cpt_raw;
	stty->real_raw = pi->cpt_real_raw;
	stty->erasing = pi->cpt_erasing;
	stty->lnext = pi->cpt_lnext;
	stty->icanon = pi->cpt_icanon;
	stty->closing = pi->cpt_closing;
	stty->minimum_to_wake = pi->cpt_minimum_to_wake;

	stty->termios->c_iflag = pi->cpt_c_iflag;
	stty->termios->c_oflag = pi->cpt_c_oflag;
	stty->termios->c_lflag = pi->cpt_c_lflag;
	stty->termios->c_cflag = pi->cpt_c_cflag;
	memcpy(&stty->termios->c_cc, &pi->cpt_c_cc, NCCS);
	memcpy(stty->read_flags, pi->cpt_read_flags, sizeof(stty->read_flags));

	if (pi->cpt_next > pi->cpt_hdrlen) {
		int err;
		struct cpt_obj_bits b;
		err = rst_get_object(CPT_OBJ_BITS, pos + pi->cpt_hdrlen, &b, ctx);
		if (err)
			return err;
		if (b.cpt_size == 0)
			return 0;
		err = ctx->pread(stty->read_buf, b.cpt_size, ctx, pos + pi->cpt_hdrlen + b.cpt_hdrlen);
		if (err)
			return err;

		spin_lock_irq(&stty->read_lock);
		stty->read_tail = 0;
		stty->read_cnt = b.cpt_size;
		stty->read_head = b.cpt_size;
		stty->canon_head = stty->read_tail + pi->cpt_canon_head;
		stty->canon_data = pi->cpt_canon_data;
		spin_unlock_irq(&stty->read_lock);
	}

	return 0;
}

/* Find slave/master tty in image, when we already know master/slave.
 * It might be optimized, of course. */
static loff_t find_pty_pair(struct tty_struct *stty, loff_t pos, struct cpt_tty_image *pi, struct cpt_context *ctx)
{
	int err;
	loff_t sec = ctx->sections[CPT_SECT_TTY];
	loff_t endsec;
	loff_t ret = CPT_NULL;
	struct cpt_section_hdr h;
	struct cpt_tty_image *pibuf;

	err = ctx->pread(&h, sizeof(h), ctx, sec);
	if (err)
		return CPT_NULL;
	if (h.cpt_section != CPT_SECT_TTY || h.cpt_hdrlen < sizeof(h))
		return CPT_NULL;
	pibuf = kmalloc(sizeof(*pibuf), GFP_KERNEL);
	if (pibuf == NULL) {
		eprintk_ctx("cannot allocate buffer\n");
		return CPT_NULL;
	}
	endsec = sec + h.cpt_next;
	sec += h.cpt_hdrlen;
	while (sec < endsec) {
		if (rst_get_object(CPT_OBJ_TTY, sec, pibuf, ctx))
			goto out;
		if (pibuf->cpt_index == pi->cpt_index &&
		    !((pi->cpt_drv_flags^pibuf->cpt_drv_flags)&TTY_DRIVER_DEVPTS_MEM) &&
		    pos != sec &&
		    ((pi->cpt_drv_flags & TTY_DRIVER_DEVPTS_MEM) == 0 ||
		     ((pi->cpt_name[0] == 'v') == (pibuf->cpt_name[0] == 'v')))) {
			pty_setup(stty, sec, pibuf, ctx);
			ret = sec;
			goto out;
		}
		sec += pibuf->cpt_next;
	}
out:
	kfree(pibuf);
	return ret;
}

static int fixup_tty_attrs(struct cpt_inode_image *ii, struct file *master,
			   struct cpt_context *ctx)
{
	int err;
	struct iattr newattrs;
	struct dentry *d = master->f_dentry;

	newattrs.ia_valid = ATTR_UID|ATTR_GID|ATTR_MODE;
	newattrs.ia_uid = ii->cpt_uid;
	newattrs.ia_gid = ii->cpt_gid;
	newattrs.ia_mode = ii->cpt_mode;

	mutex_lock(&d->d_inode->i_mutex);
	err = notify_change(d, &newattrs);
	mutex_unlock(&d->d_inode->i_mutex);

	return err;
}

/* NOTE: "portable", but ugly thing. To allocate /dev/pts/N, we open
 * /dev/ptmx until we get pty with desired index.
 */

struct file *ptmx_open(int index, unsigned int flags)
{
	struct file *file;
	struct file **stack = NULL;
	int depth = 0;

	for (;;) {
		struct tty_struct *tty;

		file = filp_open("/dev/ptmx", flags|O_NONBLOCK|O_NOCTTY|O_RDWR, 0);
		if (IS_ERR(file))
			break;
		tty = file_tty(file);
		if (tty->index == index)
			break;

		if (depth == PAGE_SIZE/sizeof(struct file *)) {
			fput(file);
			file = ERR_PTR(-EBUSY);
			break;
		}
		if (stack == NULL) {
			stack = (struct file **)__get_free_page(GFP_KERNEL);
			if (!stack) {
				fput(file);
				file = ERR_PTR(-ENOMEM);
				break;
			}
		}
		stack[depth] = file;
		depth++;
	}
	while (depth > 0) {
		depth--;
		fput(stack[depth]);
	}
	if (stack)
		free_page((unsigned long)stack);
	return file;
}


struct file * rst_open_tty(cpt_object_t *mntobj, char *name,
			   struct cpt_file_image *fi, struct cpt_inode_image *ii,
			   unsigned flags, struct cpt_context *ctx)
{
	int err;
	cpt_object_t *obj;
	struct file *master, *slave;
	struct tty_struct *stty;
	struct cpt_tty_image *pi;
	static char *a = "pqrstuvwxyzabcde";
	static char *b = "0123456789abcdef";
	char pairname[16];
	unsigned master_flags, slave_flags;

	if (fi->cpt_priv == CPT_NULL)
		return ERR_PTR(-EINVAL);

	obj = lookup_cpt_obj_bypos(CPT_OBJ_TTY, fi->cpt_priv, ctx);
	if (obj && obj->o_parent) {
		dprintk_ctx("obtained pty as pair to existing\n");
		master = obj->o_parent;
		stty = file_tty(master);

		if (stty->driver->subtype == PTY_TYPE_MASTER &&
		    (stty->driver->flags&TTY_DRIVER_DEVPTS_MEM)) {
			wprintk_ctx("cloning ptmx\n");
			get_file(master);
			return master;
		}

		master = dentry_open(dget(master->f_dentry),
				     mntget(master->f_vfsmnt), flags,
				     current_cred());
		if (!IS_ERR(master)) {
			stty = file_tty(master);
			if (stty->driver->subtype != PTY_TYPE_MASTER)
				fixup_tty_attrs(ii, master, ctx);
		}
		return master;
	}

	pi = cpt_get_buf(ctx);
	err = rst_get_object(CPT_OBJ_TTY, fi->cpt_priv, pi, ctx);
	if (err) {
		cpt_release_buf(ctx);
		return ERR_PTR(err);
	}

	if (MAJOR(ii->cpt_rdev) == TTY_MAJOR ||
	    ii->cpt_rdev == MKDEV(TTYAUX_MAJOR, 1) ||
	    (ii->cpt_rdev == MKDEV(TTYAUX_MAJOR, 0) &&
	     !strncmp(pi->cpt_name, "vtty", 4))) {
		if (mntobj && (mntobj->o_flags & CPT_VFSMOUNT_DELAYFS)) {
			cpt_release_buf(ctx);
			return ERR_PTR(-ENOTSUPP);
		}
		master = rst_open_file(mntobj, name, fi,
				flags|O_NONBLOCK|O_NOCTTY, ctx);
		if (IS_ERR(master)) {
			eprintk_ctx("rst_open_tty: %s %Ld %ld\n",
					name, (long long)fi->cpt_priv,
					PTR_ERR(master));
			cpt_release_buf(ctx);
			return master;
		} else if (master->f_dentry->d_inode->i_rdev != ii->cpt_rdev) {
			eprintk_ctx("rst_open_tty: wrong rdev %llx(saved %llx)",
				    (u64)master->f_dentry->d_inode->i_rdev,
				    ii->cpt_rdev);
			fput(master);
			cpt_release_buf(ctx);
			return ERR_PTR(-ENODEV);
		}

		stty = file_tty(master);
		obj = cpt_object_add(CPT_OBJ_TTY, stty, ctx);
		obj->o_parent = master;
		cpt_obj_setpos(obj, fi->cpt_priv, ctx);

		obj = cpt_object_add(CPT_OBJ_FILE, master, ctx);
		cpt_obj_setpos(obj, CPT_NULL, ctx);
		get_file(master);

		/* Do not restore /dev/ttyX state */
		cpt_release_buf(ctx);
		return master;
	}

	master_flags = slave_flags = 0;
	if (pi->cpt_drv_subtype == PTY_TYPE_MASTER)
		master_flags = flags;
	else
		slave_flags = flags;

	/*
	 * Open pair master/slave.
	 */
	if (pi->cpt_drv_flags&TTY_DRIVER_DEVPTS_MEM) {
		master = ptmx_open(pi->cpt_index, master_flags);
	} else {
		sprintf(pairname, "/dev/pty%c%c", a[pi->cpt_index/16], b[pi->cpt_index%16]);
		master = filp_open(pairname, master_flags|O_NONBLOCK|O_NOCTTY|O_RDWR, 0);
	}
	if (IS_ERR(master)) {
		eprintk_ctx("filp_open master: %Ld %ld\n", (long long)fi->cpt_priv, PTR_ERR(master));
		cpt_release_buf(ctx);
		return master;
	}
	if (!chrdev_is_tty(master->f_dentry->d_inode->i_rdev)) {
		eprintk_ctx("rst_open_tty: rdev is not tty\n");
		fput(master);
		cpt_release_buf(ctx);
		return ERR_PTR(-ENODEV);
	}

	stty = file_tty(master);
	clear_bit(TTY_PTY_LOCK, &stty->flags);
	if (pi->cpt_drv_flags&TTY_DRIVER_DEVPTS_MEM)
		sprintf(pairname, "/dev/pts/%d", stty->index);
	else
		sprintf(pairname, "/dev/tty%c%c", a[stty->index/16], b[stty->index%16]);
	slave = filp_open(pairname, slave_flags|O_NONBLOCK|O_NOCTTY|O_RDWR, 0);
	if (IS_ERR(slave)) {
		eprintk_ctx("filp_open slave %s: %ld\n", pairname, PTR_ERR(slave));
		fput(master);
		cpt_release_buf(ctx);
		return slave;
	}

	if (pi->cpt_drv_subtype != PTY_TYPE_MASTER)
		fixup_tty_attrs(ii, slave, ctx);

	cpt_object_add(CPT_OBJ_TTY, file_tty(master), ctx);
	cpt_object_add(CPT_OBJ_TTY, file_tty(slave), ctx);
	cpt_object_add(CPT_OBJ_FILE, master, ctx);
	cpt_object_add(CPT_OBJ_FILE, slave, ctx);

	if (pi->cpt_drv_subtype == PTY_TYPE_MASTER) {
		loff_t pos;
		obj = lookup_cpt_object(CPT_OBJ_TTY, file_tty(master), ctx);
		obj->o_parent = master;
		cpt_obj_setpos(obj, fi->cpt_priv, ctx);
		pty_setup(stty, fi->cpt_priv, pi, ctx);

		obj = lookup_cpt_object(CPT_OBJ_TTY, file_tty(slave), ctx);
		obj->o_parent = slave;
		pos = find_pty_pair(stty->link, fi->cpt_priv, pi, ctx);
		cpt_obj_setpos(obj, pos, ctx);

		obj = lookup_cpt_object(CPT_OBJ_FILE, slave, ctx);
		cpt_obj_setpos(obj, CPT_NULL, ctx);
		get_file(master);
		cpt_release_buf(ctx);
		return master;
	} else {
		loff_t pos;
		obj = lookup_cpt_object(CPT_OBJ_TTY, file_tty(slave), ctx);
		obj->o_parent = slave;
		cpt_obj_setpos(obj, fi->cpt_priv, ctx);
		pty_setup(stty->link, fi->cpt_priv, pi, ctx);

		obj = lookup_cpt_object(CPT_OBJ_TTY, file_tty(master), ctx);
		obj->o_parent = master;
		pos = find_pty_pair(stty, fi->cpt_priv, pi, ctx);
		cpt_obj_setpos(obj, pos, ctx);

		obj = lookup_cpt_object(CPT_OBJ_FILE, master, ctx);
		cpt_obj_setpos(obj, CPT_NULL, ctx);
		get_file(slave);
		cpt_release_buf(ctx);
		return slave;
	}
}

int rst_tty_jobcontrol(struct cpt_context *ctx)
{
	int err;
	loff_t sec = ctx->sections[CPT_SECT_TTY];
	loff_t endsec;
	struct cpt_section_hdr h;

	err = ctx->pread(&h, sizeof(h), ctx, sec);
	if (err)
		return err;
	if (h.cpt_section != CPT_SECT_TTY || h.cpt_hdrlen < sizeof(h))
		return -EINVAL;
	endsec = sec + h.cpt_next;
	sec += h.cpt_hdrlen;
	while (sec < endsec) {
		cpt_object_t *obj;
		struct cpt_tty_image *pibuf = cpt_get_buf(ctx);

		if (rst_get_object(CPT_OBJ_TTY, sec, pibuf, ctx)) {
			cpt_release_buf(ctx);
			return -EINVAL;
		}

		obj = lookup_cpt_obj_bypos(CPT_OBJ_TTY, sec, ctx);
		if (obj) {
			struct tty_struct *stty = obj->o_obj;
			if ((int)pibuf->cpt_pgrp > 0) {
				stty->pgrp = rst_alloc_pid(pibuf->cpt_pgrp);
				if (!stty->pgrp)
					dprintk_ctx("unknown tty pgrp %d\n", pibuf->cpt_pgrp);
			} else if (pibuf->cpt_pgrp) {
				stty->pgrp = rst_alloc_pid(0);
				if (!stty->pgrp) {
					eprintk_ctx("cannot allocate stray tty->pgr\n");
					cpt_release_buf(ctx);
					return -EINVAL;
				}
			}
			if ((int)pibuf->cpt_session > 0) {
				stty->session = rst_alloc_pid(pibuf->cpt_session);
				if (!stty->session)
					dprintk_ctx("unknown tty session %d\n", pibuf->cpt_session);
			}
		}
		sec += pibuf->cpt_next;
		cpt_release_buf(ctx);
	}
	return 0;
}
