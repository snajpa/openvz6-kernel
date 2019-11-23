/*
 *
 *  kernel/cpt/rst_proc.c
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
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/proc_fs.h>
#include <linux/smp_lock.h>
#include <asm/uaccess.h>
#include <linux/cpt_ioctl.h>
#include <linux/kmod.h>

#include <linux/cpt_obj.h>
#include <linux/cpt_context.h>
#include "cpt_dump.h"
#include "cpt_files.h"
#include "cpt_mm.h"
#include "cpt_kernel.h"

MODULE_AUTHOR("Alexey Kuznetsov <alexey@sw.ru>");
MODULE_LICENSE("GPL");

/* List of contexts and lock protecting the list */
static struct list_head cpt_context_list;
static spinlock_t cpt_context_lock;

static int proc_read(char *buffer, char **start, off_t offset,
		     int length, int *eof, void *data)
{
	off_t pos = 0;
	off_t begin = 0;
	int len = 0;
	cpt_context_t *ctx;

	len += sprintf(buffer, "Ctx      Id       VE       State\n");

	spin_lock(&cpt_context_lock);

	list_for_each_entry(ctx, &cpt_context_list, ctx_list) {
		len += sprintf(buffer+len,"%p %08x %-8u %d",
			       ctx,
			       ctx->contextid,
			       ctx->ve_id,
			       ctx->ctx_state
			       );

		buffer[len++] = '\n';

		pos = begin+len;
		if (pos < offset) {
			len = 0;
			begin = pos;
		}
		if (pos > offset+length)
			goto done;
	}
	*eof = 1;

done:
	spin_unlock(&cpt_context_lock);
	*start = buffer + (offset - begin);
	len -= (offset - begin);
	if(len > length)
		len = length;
	if(len < 0)
		len = 0;
	return len;
}

void rst_context_release(cpt_context_t *ctx)
{
	list_del(&ctx->ctx_list);
	spin_unlock(&cpt_context_lock);

	if (ctx->ctx_state > 0)
		rst_kill(ctx);
	ctx->ctx_state = CPT_CTX_ERROR;

	rst_close_dumpfile(ctx);

	rst_close_pram(ctx);

	if (ctx->anonvmas) {
		int h;
		for (h = 0; h < CPT_ANONVMA_HSIZE; h++) {
			while (!hlist_empty(&ctx->anonvmas[h])) {
				struct hlist_node *elem = ctx->anonvmas[h].first;
				hlist_del(elem);
				kfree(elem);
			}
		}
		free_page((unsigned long)ctx->anonvmas);
	}
	cpt_flush_error(ctx);
	if (ctx->errorfile) {
		fput(ctx->errorfile);
		ctx->errorfile = NULL;
	}
	if (ctx->error_msg) {
		free_page((unsigned long)ctx->error_msg);
		ctx->error_msg = NULL;
	}
#ifdef CONFIG_VZ_CHECKPOINT_ITER
	rst_drop_iter_rbtree(ctx);
	if (ctx->pagein_file_out)
		fput(ctx->pagein_file_out);
	if (ctx->pagein_file_in)
		fput(ctx->pagein_file_in);
#endif
	if (ctx->filejob_queue)
		rst_flush_filejobs(ctx);
	if (ctx->vdso)
		free_page((unsigned long)ctx->vdso);
	if (ctx->objcount)
		eprintk_ctx("%d objects leaked\n", ctx->objcount);
	kfree(ctx);

	spin_lock(&cpt_context_lock);
}

static void __cpt_context_put(cpt_context_t *ctx)
{
	if (!--ctx->refcount)
		rst_context_release(ctx);
}

static void cpt_context_put(cpt_context_t *ctx)
{
	spin_lock(&cpt_context_lock);
	__cpt_context_put(ctx);
	spin_unlock(&cpt_context_lock);
}

cpt_context_t * rst_context_open(void)
{
	cpt_context_t *ctx;

	if ((ctx = kmalloc(sizeof(*ctx), GFP_KERNEL)) != NULL) {
		rst_context_init(ctx);
		spin_lock(&cpt_context_lock);
		list_add_tail(&ctx->ctx_list, &cpt_context_list);
		spin_unlock(&cpt_context_lock);
		ctx->error_msg = (char*)__get_free_page(GFP_KERNEL);
		if (ctx->error_msg != NULL)
			ctx->error_msg[0] = 0;
	}
	return ctx;
}

void rst_report_error(int err, cpt_context_t *ctx)
{
	if (ctx->statusfile) {
		mm_segment_t oldfs;
		int status = 7 /* VZ_ENVCREATE_ERROR */;

		oldfs = get_fs(); set_fs(KERNEL_DS);
		if (ctx->statusfile->f_op && ctx->statusfile->f_op->write)
			ctx->statusfile->f_op->write(ctx->statusfile, (char*)&status, sizeof(status), &ctx->statusfile->f_pos);
		set_fs(oldfs);
		fput(ctx->statusfile);
		ctx->statusfile = NULL;
	}
}


static cpt_context_t * cpt_context_lookup(unsigned int ctxid)
{
	cpt_context_t *ctx;

	spin_lock(&cpt_context_lock);
	list_for_each_entry(ctx, &cpt_context_list, ctx_list) {
		if (ctx->contextid == ctxid) {
			ctx->refcount++;
			spin_unlock(&cpt_context_lock);
			return ctx;
		}
	}
	spin_unlock(&cpt_context_lock);
	return NULL;
}

static int rst_ioctl(struct inode * inode, struct file * file, unsigned int cmd, unsigned long arg)
{
	int err = 0;
	cpt_context_t *ctx;
	struct file *dfile = NULL;

	unlock_kernel();

	request_module("vzcptpram");

	if (cmd == CPT_TEST_CAPS) {
		err = test_cpu_caps_and_features();
		goto out_lock;
	}

	if (cmd == CPT_TEST_VERSION) {
		err = rst_image_acceptable(arg);
		goto out_lock;
	}

	if (cmd == CPT_JOIN_CONTEXT || cmd == CPT_PUT_CONTEXT) {
		cpt_context_t *old_ctx;

		ctx = NULL;
		if (cmd == CPT_JOIN_CONTEXT) {
			err = -ENOENT;
			ctx = cpt_context_lookup(arg);
			if (!ctx)
				goto out_lock;
		}

		spin_lock(&cpt_context_lock);
		old_ctx = (cpt_context_t*)file->private_data;
		file->private_data = ctx;

		if (old_ctx) {
			if (cmd == CPT_PUT_CONTEXT && old_ctx->sticky) {
				old_ctx->sticky = 0;
				old_ctx->refcount--;
			}
			__cpt_context_put(old_ctx);
		}
		spin_unlock(&cpt_context_lock);
		err = 0;
		goto out_lock;
	}

	spin_lock(&cpt_context_lock);
	ctx = (cpt_context_t*)file->private_data;
	if (ctx)
		ctx->refcount++;
	spin_unlock(&cpt_context_lock);

	if (!ctx) {
		cpt_context_t *old_ctx;

		err = -ENOMEM;
		ctx = rst_context_open();
		if (!ctx)
			goto out_lock;

		spin_lock(&cpt_context_lock);
		old_ctx = (cpt_context_t*)file->private_data;
		if (!old_ctx) {
			ctx->refcount++;
			file->private_data = ctx;
		} else {
			old_ctx->refcount++;
		}
		if (old_ctx) {
			__cpt_context_put(ctx);
			ctx = old_ctx;
		}
		spin_unlock(&cpt_context_lock);
	}

	if (cmd == CPT_GET_CONTEXT) {
		unsigned int contextid = (unsigned int)arg;

		err = -EINVAL;
		if (ctx->contextid && ctx->contextid != contextid)
			goto out_nosem;
		if (!ctx->contextid) {
			cpt_context_t *c1 = cpt_context_lookup(contextid);
			if (c1) {
				cpt_context_put(c1);
				err = -EEXIST;
				goto out_nosem;
			}
			ctx->contextid = contextid;
		}
		spin_lock(&cpt_context_lock);
		if (!ctx->sticky) {
			ctx->sticky = 1;
			ctx->refcount++;
		}
		spin_unlock(&cpt_context_lock);
		err = 0;
		goto out_nosem;
	}

	down(&ctx->main_sem);

	err = -EBUSY;
	if (ctx->ctx_state < 0)
		goto out;

	err = 0;
	switch (cmd) {
	case CPT_SET_DUMPFD:
		if (ctx->ctx_state > 0) {
			err = -EBUSY;
			break;
		}
		if (arg >= 0) {
			err = -EBADF;
			dfile = fget(arg);
			if (dfile == NULL)
				break;
			if (dfile->f_op == NULL ||
			    dfile->f_op->read == NULL) {
				fput(dfile);
				break;
			}
			err = 0;
		}
		if (ctx->file)
			fput(ctx->file);
		ctx->file = dfile;
		break;
#ifdef CONFIG_VZ_CHECKPOINT_ITER
	case CPT_SET_PAGEINFDIN:
		if (ctx->ctx_state > 0) {
			err = -EBUSY;
			break;
		}
		if (arg >= 0) {
			dfile = fget(arg);
			if (dfile == NULL) {
				err = -EBADF;
				break;
			}
		}
		if (ctx->pagein_file_in)
			fput(ctx->pagein_file_in);
		ctx->pagein_file_in = dfile;
		break;
	case CPT_SET_PAGEINFDOUT:
		if (ctx->ctx_state > 0) {
			err = -EBUSY;
			break;
		}
		if (arg >= 0) {
			dfile = fget(arg);
			if (dfile == NULL) {
				err = -EBADF;
				break;
			}
		}
		if (ctx->pagein_file_out)
			fput(ctx->pagein_file_out);
		ctx->pagein_file_out = dfile;
		break;
	case CPT_ITER:
		err = rst_iteration(ctx);
		break;
#endif
	case CPT_SET_LOCKFD:
	case CPT_SET_LOCKFD2:
		if (ctx->ctx_state > 0) {
			err = -EBUSY;
			break;
		}
		if (arg >= 0) {
			dfile = fget(arg);
			if (dfile == NULL) {
				err = -EBADF;
				break;
			}
		}
		if (ctx->lockfile)
			fput(ctx->lockfile);
		ctx->lockfile = dfile;
		ctx->lockfile_new = (cmd == CPT_SET_LOCKFD2);
		break;
	case CPT_SET_STATUSFD:
		if (ctx->ctx_state > 0) {
			err = -EBUSY;
			break;
		}
		if (arg >= 0) {
			dfile = fget(arg);
			if (dfile == NULL) {
				err = -EBADF;
				break;
			}
		}
		if (ctx->statusfile)
			fput(ctx->statusfile);
		ctx->statusfile = dfile;
		break;
	case CPT_SET_ERRORFD:
		if (arg >= 0) {
			dfile = fget(arg);
			if (dfile == NULL) {
				err = -EBADF;
				break;
			}
		}
		if (ctx->errorfile)
			fput(ctx->errorfile);
		ctx->errorfile = dfile;
		break;
	case CPT_HARDLNK_ON:
		ctx->hardlinked_on = 1;
		break;
	case CPT_SET_VEID:
		if (ctx->ctx_state > 0) {
			err = -EBUSY;
			break;
		}
		ctx->ve_id = arg;
		break;
	case CPT_UNDUMP:
		if (ctx->ctx_state > 0) {
			err = -ENOENT;
			break;
		}
		ctx->ctx_state = CPT_CTX_UNDUMPING;
#ifdef ITER_DEBUG
		rst_iteration(ctx);
#endif
		err = vps_rst_undump(ctx);
		if (err) {
			int ret;

			rst_report_error(err, ctx);

			ret = rst_kill(ctx);
			if (ret == 0 || ret == -ESRCH)
				ctx->ctx_state = CPT_CTX_IDLE;
			else
				ctx->ctx_state = CPT_CTX_ERROR;
		} else {
			ctx->ctx_state = CPT_CTX_UNDUMPED;
			printk(KERN_INFO "CT: %d: restored\n", ctx->ve_id);
		}
		break;
	case CPT_RESUME:
		if (ctx->ctx_state != CPT_CTX_UNDUMPED) {
			err = -ENOENT;
			break;
		}
		err = rst_resume(ctx);
		if (!err)
			ctx->ctx_state = CPT_CTX_IDLE;
		break;
	case CPT_KILL:
		if (!ctx->ctx_state) {
			err = -ENOENT;
			break;
		}
		err = rst_kill(ctx);
		if (!err)
			ctx->ctx_state = CPT_CTX_IDLE;
		break;
	default:
		err = -EINVAL;
		break;
	}

out:
	cpt_flush_error(ctx);
	up(&ctx->main_sem);
out_nosem:
	cpt_context_put(ctx);
out_lock:
	lock_kernel();
	if (err == -ERESTARTSYS || err == -ERESTARTNOINTR ||
	    err == -ERESTARTNOHAND || err == -ERESTART_RESTARTBLOCK)
		err = -EINTR;
	return err;
}

static int rst_open(struct inode * inode, struct file * file)
{
	if (!try_module_get(THIS_MODULE))
		return -EBUSY;

	return 0;
}

static int rst_release(struct inode * inode, struct file * file)
{
	cpt_context_t *ctx;

	spin_lock(&cpt_context_lock);
	ctx = (cpt_context_t*)file->private_data;
	file->private_data = NULL;
	if (ctx)
		__cpt_context_put(ctx);
	spin_unlock(&cpt_context_lock);


	module_put(THIS_MODULE);
	return 0;
}

static struct file_operations rst_fops =
{
	.owner		= THIS_MODULE,
	.ioctl		= rst_ioctl,
	.open		= rst_open,
	.release	= rst_release,
};


static struct proc_dir_entry *proc_ent;
extern void *schedule_tail_p;
extern void schedule_tail_hook(void);
extern struct ctl_table delayfs_table[];

static struct ctl_table_header *ctl_header;

static ctl_table debug_table[] = {
	{
		.procname	= "rst",
		.data		= &debug_level,
		.maxlen		= sizeof(debug_level),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "delayfs",
		.mode		= 0555,
		.child		= delayfs_table,
	},
	{ .ctl_name = 0 }
};
static ctl_table root_table[] = {
	{
		.ctl_name	= CTL_DEBUG,
		.procname	= "debug",
		.mode		= 0555,
		.child		= debug_table,
	},
	{ .ctl_name = 0 }
};

static int __init init_rst(void)
{
	int err;

	err = register_filesystem(&delayfs_type);
	if (err)
		goto err_fs;

	err = -ENOMEM;
	ctl_header = register_sysctl_table(root_table);
	if (!ctl_header)
		goto err_mon;

	spin_lock_init(&cpt_context_lock);
	INIT_LIST_HEAD(&cpt_context_list);

	err = -EINVAL;
	proc_ent = proc_create("rst", 0600, NULL, NULL);
	if (!proc_ent)
		goto err_out;

	rst_fops.read = proc_ent->proc_fops->read;
	rst_fops.write = proc_ent->proc_fops->write;
	rst_fops.llseek = proc_ent->proc_fops->llseek;
	proc_ent->proc_fops = &rst_fops;

	proc_ent->read_proc = proc_read;
	proc_ent->data = NULL;
	return 0;

err_out:
	unregister_sysctl_table(ctl_header);
err_mon:
	unregister_filesystem(&delayfs_type);
err_fs:
	return err;
}
module_init(init_rst);

static void __exit exit_rst(void)
{
	remove_proc_entry("rst", NULL);
	unregister_sysctl_table(ctl_header);

	spin_lock(&cpt_context_lock);
	while (!list_empty(&cpt_context_list)) {
		cpt_context_t *ctx;
		ctx = list_entry(cpt_context_list.next, cpt_context_t, ctx_list);

		if (!ctx->sticky)
			ctx->refcount++;
		ctx->sticky = 0;

		BUG_ON(ctx->refcount != 1);

		__cpt_context_put(ctx);
	}
	spin_unlock(&cpt_context_lock);
	unregister_filesystem(&delayfs_type);
}
module_exit(exit_rst);
