/*
 *
 *  kernel/cpt/cpt_files.c
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
#include <linux/pagemap.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/vzcalluser.h>
#include <linux/ve_nfs.h>
#include <linux/ve_proto.h>
#include <bc/kmem.h>
#include <linux/cpt_image.h>
#include <linux/if_tun.h>
#include <linux/fdtable.h>
#include <linux/shm.h>
#include <linux/signalfd.h>
#include <linux/nsproxy.h>
#include <linux/fs_struct.h>
#include <linux/miscdevice.h>
#include <linux/eventpoll.h>
#include <linux/splice.h>
#include <linux/tty.h>
#include <linux/timerfd.h>
#include <linux/cgroup.h>
#include <linux/eventfd.h>
#include <linux/anon_inodes.h>
#include <linux/genhd.h>

#include <linux/nfs_mount.h>
#include <linux/nfs_fs.h>
#undef dprintk

#include "../../fs/autofs4/autofs_i.h"
#include <linux/cpt_obj.h>
#include <linux/cpt_context.h>
#include "cpt_mm.h"
#include "cpt_files.h"
#include "cpt_socket.h"
#include "cpt_kernel.h"
#include "cpt_fsmagic.h"
#include "cpt_syscalls.h"
#include "cpt_process.h"

static cpt_object_t *
cpt_lookup_bind_source(struct vfsmount *mnt, cpt_context_t *ctx);

void (*vefs_track_notify_hook)(struct dentry *vdentry, int track_cow);
void (*vefs_track_force_stop_hook)(struct super_block *super);
struct dentry * (*vefs_replaced_dentry_hook)(struct dentry *de);
int (*vefs_is_renamed_dentry_hook)(struct dentry *vde, struct dentry *pde);
EXPORT_SYMBOL(vefs_track_notify_hook);
EXPORT_SYMBOL(vefs_track_force_stop_hook);
EXPORT_SYMBOL(vefs_replaced_dentry_hook);
EXPORT_SYMBOL(vefs_is_renamed_dentry_hook);

static inline int is_signalfd_file(struct file *file)
{
	/* no other users of it yet */
	return file->f_op == &signalfd_fops;
}

static inline int is_timerfd_file(struct file *file)
{
	/* no other users of it yet */
	return file->f_op == &timerfd_fops;
}

static inline int is_eventfd_file(struct file *file)
{
	/* no other users of it yet */
	return file->f_op == &eventfd_fops;
}

static inline int is_fake_file(struct file *file)
{
	if (file->f_op != &bad_file_ops)
		return 0;

	return file->f_dentry->d_inode == anon_inode_inode;
}

int chrdev_is_tty(dev_t dev)
{
	int major = MAJOR(dev);

	return (major == PTY_MASTER_MAJOR ||
	    (major >= UNIX98_PTY_MASTER_MAJOR &&
	     major < UNIX98_PTY_MASTER_MAJOR+UNIX98_PTY_MAJOR_COUNT) ||
	    major == PTY_SLAVE_MAJOR ||
	    major == UNIX98_PTY_SLAVE_MAJOR ||
	    major == TTYAUX_MAJOR || major == TTY_MAJOR);
}
EXPORT_SYMBOL(chrdev_is_tty);

void cpt_printk_dentry(struct dentry *d, struct vfsmount *mnt)
{
	char *path;
	struct path p;
	unsigned long pg = __get_free_page(GFP_KERNEL);

	if (!pg)
		return;

	p.dentry = d;
	p.mnt = mnt;
	path = d_path(&p, (char *)pg, PAGE_SIZE);

	if (!IS_ERR(path))
		eprintk("<%s>\n", path);
	free_page(pg);
}

int cpt_need_delayfs(struct vfsmount *mnt)
{
	if (slab_ub(mnt) != get_exec_ub_top())
		return 0;
	if (mnt->mnt_sb->s_magic == FSMAGIC_NFS)
		return 1;
	if (is_autofs_mount(mnt))
		return 1;
	if (is_autofs_mount(mnt->mnt_parent))
		return 1;
	return 0;
}

int cpt_need_vfsmount(struct dentry *dentry, struct vfsmount *vfsmnt)
{
	if (vfsmnt == get_exec_env()->shmem_mnt)
		return 0;

	switch (dentry->d_inode->i_sb->s_magic) {
		case FSMAGIC_PIPEFS:
		case FSMAGIC_SOCKFS:
		case FSMAGIC_BDEV:
		case FSMAGIC_FUTEX:
		case FSMAGIC_INOTIFY:
		case FSMAGIC_MQUEUE:
		case FSMAGIC_ANON:
			return 0;
		default:
			eprintk("no vfsmount: ");
			cpt_printk_dentry(dentry, vfsmnt);
			eprintk(" magic:%lx\n", dentry->d_inode->i_sb->s_magic);
			return 1;
	}
}

static int
cpt_replaced(struct dentry * de, struct vfsmount *mnt, cpt_context_t * ctx)
{
	int result = 0;
	char *path;
	unsigned long pg;
	struct dentry * renamed_dentry;
	struct path p;

	if (de->d_sb->s_magic != FSMAGIC_VEFS)
		return 0;
	if (de->d_inode->i_nlink != 0 ||
	    atomic_read(&de->d_inode->i_writecount) > 0) 
		return 0;

	renamed_dentry = vefs_replaced_dentry_hook(de);
	if (renamed_dentry == NULL)
		return 0;

	pg = __get_free_page(GFP_KERNEL);
	if (!pg)
		return 0;

	p.dentry = de;
	p.mnt = mnt;
	path = d_path(&p, (char *)pg, PAGE_SIZE);
	if (!IS_ERR(path)) {
		int len;
		struct nameidata nd;

		len = pg + PAGE_SIZE - 1 - (unsigned long)path;
		if (len >= sizeof("(deleted) ") - 1 &&
		    !memcmp(path, "(deleted) ", sizeof("(deleted) ") - 1)) {
			len -= sizeof("(deleted) ") - 1;
			path += sizeof("(deleted) ") - 1;
		}

		if (path_lookup(path, 0, &nd) == 0) {
			if (mnt == nd.path.mnt &&
			    vefs_is_renamed_dentry_hook(nd.path.dentry, renamed_dentry))
				result = 1;
			path_put(&nd.path);
		}
	}
	free_page(pg);
	return result;
}

static int cpt_dump_path(struct dentry *d, struct vfsmount *mnt,
			   int replaced, cpt_context_t *ctx)
{
	int len;
	char *path;
	char *pg = cpt_get_buf(ctx);
	loff_t saved;
	struct path p;

	p.dentry = d;
	p.mnt = mnt;

	path = d_path(&p, pg, PAGE_SIZE);
	len = PTR_ERR(path);

	if (IS_ERR(path)) {
		struct cpt_object_hdr o;
		char tmp[1];

		/* VZ changes d_path() to return EINVAL, when path
		 * is not supposed to be visible inside VE.
		 * This changes behaviour of d_path() comparing
		 * to mainstream kernel, f.e. d_path() fails
		 * on any kind of shared memory. Maybe, there are
		 * another cases, but I am aware only about this one.
		 * So, we just ignore error on shmem mounts and proceed.
		 * Otherwise, checkpointing is prohibited because
		 * of reference to an invisible file.
		 */
		if (len != -EINVAL ||
		    mnt != get_exec_env()->shmem_mnt)
			eprintk_ctx("d_path err=%d\n", len);
		else
			len = 0;

		cpt_push_object(&saved, ctx);
		cpt_open_object(NULL, ctx);
		o.cpt_next = CPT_NULL;
		o.cpt_object = CPT_OBJ_NAME;
		o.cpt_hdrlen = sizeof(o);
		o.cpt_content = CPT_CONTENT_NAME;
		tmp[0] = 0;

		ctx->write(&o, sizeof(o), ctx);
		ctx->write(tmp, 1, ctx);
		ctx->align(ctx);
		cpt_close_object(ctx);
		cpt_pop_object(&saved, ctx);

		__cpt_release_buf(ctx);
		return len;
	} else {
		struct cpt_object_hdr o;

		len = pg + PAGE_SIZE - 1 - path;
		if (replaced &&
		    len >= sizeof("(deleted) ") - 1 &&
		    !memcmp(path, "(deleted) ", sizeof("(deleted) ") - 1)) {
			len -= sizeof("(deleted) ") - 1;
			path += sizeof("(deleted) ") - 1;
		}
		o.cpt_next = CPT_NULL;
		o.cpt_object = CPT_OBJ_NAME;
		o.cpt_hdrlen = sizeof(o);
		o.cpt_content = CPT_CONTENT_NAME;
		path[len] = 0;

		cpt_push_object(&saved, ctx);
		cpt_open_object(NULL, ctx);
		ctx->write(&o, sizeof(o), ctx);
		ctx->write(path, len+1, ctx);
		ctx->align(ctx);
		cpt_close_object(ctx);
		cpt_pop_object(&saved, ctx);
		__cpt_release_buf(ctx);
	}
	return 0;
}

static int cpt_dump_nfs_path(struct dentry *d, struct vfsmount *mnt,
			     cpt_context_t *ctx)
{
	char *path;
	char *pg = cpt_get_buf(ctx);
	loff_t saved;
	struct path p;
	struct nfs_unlinkdata *ud = d->d_fsdata;
	int dentry_name_len = ud->args.name.len;
	struct cpt_object_hdr o;

	p.dentry = d->d_parent;
	p.mnt = mnt;

	path = d_path(&p, pg, PAGE_SIZE);
	if (IS_ERR(path)) {
		eprintk_ctx("getting path failed\n");
		__cpt_release_buf(ctx);
		return PTR_ERR(path);
	}

	if (path - pg < dentry_name_len + 1) {
		eprintk_ctx("full path is too long\n");
		__cpt_release_buf(ctx);
		return -ENOMEM;
	}

	path = strcpy(pg, path);
	strcat(path, "/");
	strncat(path, ud->args.name.name, dentry_name_len);

	cpt_push_object(&saved, ctx);
	cpt_open_object(NULL, ctx);
	o.cpt_next = CPT_NULL;
	o.cpt_object = CPT_OBJ_NAME;
	o.cpt_hdrlen = sizeof(o);
	o.cpt_content = CPT_CONTENT_NAME;

	ctx->write(&o, sizeof(o), ctx);
	ctx->write(path, strlen(path) + 1, ctx);
	ctx->align(ctx);
	cpt_close_object(ctx);
	cpt_pop_object(&saved, ctx);

	__cpt_release_buf(ctx);
	return 0;
}

int cpt_dump_string(const char *s, struct cpt_context *ctx)
{
	int len;
	struct cpt_object_hdr o;

	cpt_open_object(NULL, ctx);
	len = strlen(s);
	o.cpt_next = CPT_NULL;
	o.cpt_object = CPT_OBJ_NAME;
	o.cpt_hdrlen = sizeof(o);
	o.cpt_content = CPT_CONTENT_NAME;

	ctx->write(&o, sizeof(o), ctx);
	ctx->write(s, len+1, ctx);
	ctx->align(ctx);
	cpt_close_object(ctx);
	return 0;
}

cpt_object_t *cpt_lookup_vfsmount_obj(struct vfsmount *mnt,
		struct cpt_context *ctx)
{
	while (is_nfs_automount(mnt))
		mnt = mnt->mnt_parent;

	if (is_autofs_mount(mnt->mnt_parent))
		mnt = mnt->mnt_parent;

	return lookup_cpt_object(CPT_OBJ_VFSMOUNT_REF, mnt, ctx);
}

int cpt_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat)
{
	if (cpt_need_delayfs(mnt)) {
		generic_fillattr(dentry->d_inode, stat);
		return 0;
	}

	return vfs_getattr(mnt, dentry, stat);
}

int cpt_dump_inode(struct dentry *d, struct vfsmount *mnt, struct cpt_context *ctx)
{
	int err;
	struct cpt_inode_image *v = cpt_get_buf(ctx);
	struct kstat sbuf;
	cpt_object_t *mntobj;

	v->cpt_next = sizeof(*v);
	v->cpt_object = CPT_OBJ_INODE;
	v->cpt_hdrlen = sizeof(*v);
	v->cpt_content = CPT_CONTENT_ARRAY;

	if ((err = cpt_getattr(mnt, d, &sbuf)) != 0) {
		cpt_release_buf(ctx);
		return err;
	}

	mntobj = cpt_lookup_vfsmount_obj(mnt, ctx);
	if (!mntobj && cpt_need_vfsmount(d, mnt)) {
		cpt_release_buf(ctx);
		return -ENODEV;
	}

	v->cpt_dev	= d->d_inode->i_sb->s_dev;
	v->cpt_ino	= d->d_inode->i_ino;
	v->cpt_mode	= sbuf.mode;
	v->cpt_nlink	= sbuf.nlink;
	v->cpt_uid	= sbuf.uid;
	v->cpt_gid	= sbuf.gid;
	v->cpt_rdev	= d->d_inode->i_rdev;
	v->cpt_size	= sbuf.size;
	v->cpt_atime	= cpt_timespec_export(&sbuf.atime);
	v->cpt_mtime	= cpt_timespec_export(&sbuf.mtime);
	v->cpt_ctime	= cpt_timespec_export(&sbuf.ctime);
	v->cpt_blksize	= sbuf.blksize;
	v->cpt_blocks	= sbuf.blocks;
	v->cpt_sb	= d->d_inode->i_sb->s_magic;
	v->cpt_vfsmount = mntobj ? mntobj->o_pos : CPT_NULL;

	ctx->write(v, sizeof(*v), ctx);
	cpt_release_buf(ctx);
	return 0;
}

int cpt_collect_files(cpt_context_t * ctx)
{
	int err;
	cpt_object_t *obj;
	int index = 0;

	/* Collect process fd sets */
	for_each_object(obj, CPT_OBJ_TASK) {
		struct task_struct *tsk = obj->o_obj;
		if (tsk->files && cpt_object_add(CPT_OBJ_FILES, tsk->files, ctx) == NULL)
			return -ENOMEM;
	}

	/* Collect files from fd sets */
	for_each_object(obj, CPT_OBJ_FILES) {
		int fd;
		struct files_struct *f = obj->o_obj;

		cpt_obj_setindex(obj, index++, ctx);

		if (obj->o_count != atomic_read(&f->count)) {
			eprintk_ctx("files_struct is referenced outside %d %d\n", obj->o_count, atomic_read(&f->count));
			return -EBUSY;
		}

		for (fd = 0; fd < f->fdt->max_fds; fd++) {
			struct file *file = fcheck_files(f, fd);
			if (file && cpt_object_add(CPT_OBJ_FILE, file, ctx) == NULL)
				return -ENOMEM;
		}
	}

	/* Collect files queued by AF_UNIX sockets. */
	if ((err = cpt_collect_passedfds(ctx)) < 0)
		return err;

	/* OK. At this point we should count all the references. */
	for_each_object(obj, CPT_OBJ_FILE) {
		struct file *file = obj->o_obj;
		struct file *parent;
		cpt_object_t *ino_obj;

		if (obj->o_count != atomic_long_read(&file->f_count)) {
			eprintk_ctx("file struct is referenced outside %d %ld\n", obj->o_count, atomic_long_read(&file->f_count));
			cpt_printk_dentry(file->f_dentry, file->f_vfsmnt);
			return -EBUSY;
		}

		switch (file->f_dentry->d_inode->i_sb->s_magic) {
		case FSMAGIC_FUTEX:
		case FSMAGIC_MQUEUE:
		case FSMAGIC_BDEV:
#ifndef CONFIG_INOTIFY_USER
		case FSMAGIC_INOTIFY:
#endif
			eprintk_ctx("file on unsupported FS: magic %08lx\n", file->f_dentry->d_inode->i_sb->s_magic);
			return -EBUSY;
		}

		/* Collect inode. It is necessary mostly to resolve deleted
		 * hard links. */
		ino_obj = cpt_object_add(CPT_OBJ_INODE, file->f_dentry->d_inode, ctx);
		if (ino_obj == NULL)
			return -ENOMEM;

		parent = ino_obj->o_parent;
		if (!parent || (!IS_ROOT(parent->f_dentry) && d_unhashed(parent->f_dentry)))
			ino_obj->o_parent = file;

		if (S_ISCHR(file->f_dentry->d_inode->i_mode)) {
			if (chrdev_is_tty(file->f_dentry->d_inode->i_rdev)) {
				err = cpt_collect_tty(file, ctx);
				if (err)
					return err;
			}
		}

		if (S_ISSOCK(file->f_dentry->d_inode->i_mode)) {
			err = cpt_collect_socket(file, ctx);
			if (err)
				return err;
		}
	}

	err = cpt_index_sockets(ctx);

	return err;
}

/* /dev/ptmx is special, all the files share one inode, but real tty backend
 * is attached via file->private_data.
 */

static inline int is_cloning_inode(struct inode *ino)
{
	return S_ISCHR(ino->i_mode) && 
		ino->i_rdev == MKDEV(TTYAUX_MAJOR,2);
}

static int dump_one_flock(struct file_lock *fl, int owner,
		struct cpt_context *ctx, int delay)
{
	pid_t pid;
	struct cpt_flock_image *v;

	if (delay && !fl->fl_ops)
		delay = 0; /* no remote locks */
	/* NFS4 is not supported yet, so we don't dump such locks */
	if (delay && !fl->fl_ops->fl_owner_id)
		return 0;

	v = cpt_get_buf(ctx);

	v->cpt_next = sizeof(*v);
	v->cpt_object = CPT_OBJ_FLOCK;
	v->cpt_hdrlen = sizeof(*v);
	v->cpt_content = CPT_CONTENT_VOID;

	v->cpt_owner = owner;

	if (fl->fl_nspid)
		pid = cpt_pid_nr(fl->fl_nspid);
	else
		pid = fl->fl_pid;

	if (pid == -1) {
		if (!(fl->fl_flags&FL_FLOCK)) {
			eprintk_ctx("posix lock from another container?\n");
			cpt_release_buf(ctx);
			return -EBUSY;
		}
		pid = 0;
	}

	v->cpt_pid = pid;
	v->cpt_start = fl->fl_start;
	v->cpt_end = fl->fl_end;
	v->cpt_flags = fl->fl_flags;
	if (delay)
		v->cpt_flags |= CPT_FLOCK_DELAYED;
	v->cpt_type = fl->fl_type;
	v->cpt_svid = delay ? fl->fl_ops->fl_owner_id(fl, &v->cpt_lsid) :
			      CPT_NOINDEX;

	ctx->write(v, sizeof(*v), ctx);
	cpt_release_buf(ctx);

	return 0;
}


int cpt_dump_flock(struct file *file, struct cpt_context *ctx)
{
	int err = 0, delay;
	struct file_lock *fl;

	lock_kernel();
	for (fl = file->f_dentry->d_inode->i_flock;
	     fl; fl = fl->fl_next) {
		if (file != fl->fl_file)
			continue;
		if (fl->fl_flags & FL_LEASE) {
			eprintk_ctx("lease lock is not supported\n");
			err = -EINVAL;
			break;
		}

		delay = cpt_need_delayfs(file->f_vfsmnt);

		if (fl->fl_flags & FL_POSIX) {
			cpt_object_t *obj;
			obj = lookup_cpt_object(CPT_OBJ_FILES, fl->fl_owner, ctx);
			if (obj) {
				dump_one_flock(fl, obj->o_index, ctx, delay);
				continue;
			} else {
				eprintk_ctx("unknown lock owner %p\n", fl->fl_owner);
				err = -EINVAL;
			}
		}
		if (fl->fl_flags & FL_FLOCK) {
			dump_one_flock(fl, -1, ctx, delay);
			continue;
		}
	}
	unlock_kernel();
	return err;
}

static int dump_content_timerfd(struct file *file, struct cpt_context *ctx)
{
	struct cpt_timerfd_image o;
	loff_t saved_pos;
	struct timerfd_ctx *timerfd_ctx = file->private_data;
	struct timespec tv;

	cpt_push_object(&saved_pos, ctx);

	o.cpt_next = sizeof(o);
	o.cpt_object = CPT_OBJ_TIMERFD;
	o.cpt_hdrlen = sizeof(o);
	o.cpt_content = CPT_CONTENT_VOID;

	o.cpt_clockid = timerfd_ctx->clockid;
	o.cpt_ticks = timerfd_ctx->ticks;
	o.cpt_expired = timerfd_ctx->expired;

	tv = ktime_to_timespec(timerfd_get_remaining(timerfd_ctx));
	o.cpt_it_value = cpt_timespec_export(&tv);
	tv = ktime_to_timespec(timerfd_ctx->tintv);
	o.cpt_it_interval = cpt_timespec_export(&tv);

	ctx->write(&o, sizeof(o), ctx);

	cpt_pop_object(&saved_pos, ctx);

	return 0;
}

static int dump_content_eventfd(struct file *file, struct cpt_context *ctx)
{
	struct cpt_eventfd_image o;
	loff_t saved_pos;
	struct eventfd_ctx *eventfd_ctx = file->private_data;

	cpt_push_object(&saved_pos, ctx);

	o.cpt_next = sizeof(o);
	o.cpt_object = CPT_OBJ_EVENTFD;
	o.cpt_hdrlen = sizeof(o);
	o.cpt_content = CPT_CONTENT_VOID;

	o.cpt_count = eventfd_ctx->count;
	o.cpt_flags = eventfd_ctx->flags;

	ctx->write(&o, sizeof(o), ctx);

	cpt_pop_object(&saved_pos, ctx);

	return 0;
}

int cpt_pipe_fasync(struct file *file, struct cpt_context *ctx)
{
	struct pipe_inode_info *pipe = file->f_dentry->d_inode->i_pipe;
	struct fasync_struct *fa;

	for (fa = pipe->fasync_readers; fa; fa = fa->fa_next) {
		if (fa->fa_file == file)
			return fa->fa_fd;
	}
	for (fa = pipe->fasync_writers; fa; fa = fa->fa_next) {
		if (fa->fa_file == file)
			return fa->fa_fd;
	}
	return -1;
}

static int dump_one_file(cpt_object_t *obj, struct file *file, cpt_context_t *ctx)
{
	int err = 0;
	cpt_object_t *iobj;
	struct cpt_file_image *v = cpt_get_buf(ctx);
	struct kstat sbuf;
	int replaced = 0;
	cpt_object_t *mntobj;

	cpt_open_object(obj, ctx);

	v->cpt_next = CPT_NULL;
	v->cpt_object = CPT_OBJ_FILE;
	v->cpt_hdrlen = sizeof(*v);
	v->cpt_content = CPT_CONTENT_ARRAY;

	v->cpt_flags = file->f_flags;
	v->cpt_mode = file->f_mode;
	v->cpt_pos = file->f_pos;
	v->cpt_uid = file->f_cred->uid;
	v->cpt_gid = file->f_cred->gid;

	cpt_getattr(file->f_vfsmnt, file->f_dentry, &sbuf);

	mntobj = cpt_lookup_vfsmount_obj(file->f_vfsmnt, ctx);
	if (!mntobj && cpt_need_vfsmount(file->f_dentry, file->f_vfsmnt)) {
		cpt_release_buf(ctx);
		return -ENODEV;
	}
	v->cpt_i_mode = sbuf.mode;
	v->cpt_lflags = 0;

	if (file->f_dentry->d_inode->i_sb->s_magic == FSMAGIC_PROC) {
		v->cpt_lflags |= CPT_DENTRY_PROC;
		if (proc_dentry_of_dead_task(file->f_dentry))
			v->cpt_lflags |= CPT_DENTRY_PROCPID_DEAD;
	}

	if (cpt_need_delayfs(file->f_vfsmnt)) {
		struct dentry *de = file->f_dentry;

		if (obj)
			obj->o_flags |= CPT_FILE_DELAYFS;

		if (de->d_flags & DCACHE_NFSFS_RENAMED) {
			v->cpt_lflags |= CPT_DENTRY_SILLYRENAME;
			if (obj)
				obj->o_flags |= CPT_FILE_SILLYRENAME;
		}
	}

	if (is_fake_file(file))
		v->cpt_lflags |= CPT_DENTRY_FAKEFILE;
	else if (IS_ROOT(file->f_dentry))
		v->cpt_lflags |= CPT_DENTRY_ROOT;
	else if (d_unhashed(file->f_dentry)) {
		if (cpt_replaced(file->f_dentry, file->f_vfsmnt, ctx)) {
			v->cpt_lflags |= CPT_DENTRY_REPLACED;
			replaced = 1;
		} else if (!(v->cpt_lflags & CPT_DENTRY_PROCPID_DEAD)) {
			if (file->f_dentry->d_flags & DCACHE_NFSFS_RENAMED)
				v->cpt_lflags |= CPT_DENTRY_SILLYRENAME;
			v->cpt_lflags |= CPT_DENTRY_DELETED;
		}
	}
	if (is_cloning_inode(file->f_dentry->d_inode))
		v->cpt_lflags |= CPT_DENTRY_CLONING;

	v->cpt_inode = CPT_NULL;
	if (!(v->cpt_lflags & CPT_DENTRY_REPLACED)) {
		iobj = lookup_cpt_object(CPT_OBJ_INODE, file->f_dentry->d_inode, ctx);
		if (iobj) {
			v->cpt_inode = iobj->o_pos;
			if (iobj->o_flags & CPT_INODE_HARDLINKED)
				v->cpt_lflags |= CPT_DENTRY_HARDLINKED;
		}
	}
	v->cpt_priv = CPT_NULL;
	v->cpt_fown_fd = -1;
	if (S_ISCHR(v->cpt_i_mode)) {
		dev_t dev = file->f_dentry->d_inode->i_rdev;

		if (chrdev_is_tty(dev)) {
			if (file->private_data) {
				iobj = lookup_cpt_object(CPT_OBJ_TTY, file_tty(file), ctx);
				if (iobj) {
					v->cpt_priv = iobj->o_pos;
					if (file->f_flags&FASYNC)
						v->cpt_fown_fd = cpt_tty_fasync(file, ctx);
				}
			} else if (hlist_empty(&file->f_dentry->d_inode->i_fsnotify_mark_entries)) {
				eprintk_ctx("BUG: tty char dev without tty "
					    "struct and not inotify watched\n");
				cpt_release_buf(ctx);
				return -EINVAL;
			}
		} else if (dev == MKDEV(MISC_MAJOR, TUN_MINOR))
			v->cpt_lflags |= CPT_DENTRY_TUNTAP;
	}
	if (S_ISSOCK(v->cpt_i_mode)) {
		if (obj) {
			if (obj->o_index < 0) {
				eprintk_ctx("BUG: no socket index\n");
				cpt_release_buf(ctx);
				return -EINVAL;
			}
			v->cpt_priv = obj->o_index;
		}
		if (file->f_flags&FASYNC)
			v->cpt_fown_fd = cpt_socket_fasync(file, ctx);
	}
	if (S_ISFIFO(v->cpt_i_mode)) {
		if (file->f_flags & FASYNC)
			v->cpt_fown_fd = cpt_pipe_fasync(file, ctx);
	}
	if (file->f_op == &eventpoll_fops) {
		v->cpt_priv = file->f_dentry->d_inode->i_ino;
		v->cpt_lflags |= CPT_DENTRY_EPOLL;
	}
	if (file->f_dentry->d_inode->i_sb->s_magic == FSMAGIC_INOTIFY) {
		v->cpt_priv = file->f_dentry->d_inode->i_ino;
		v->cpt_lflags |= CPT_DENTRY_INOTIFY;
	}

	v->cpt_fown_pid = (file->f_owner.pid == NULL ?
			   CPT_FOWN_STRAY_PID : cpt_pid_nr(file->f_owner.pid));
	v->cpt_fown_uid = file->f_owner.uid;
	v->cpt_fown_euid = file->f_owner.euid;
	v->cpt_fown_signo = file->f_owner.signum;

	if (is_signalfd_file(file)) {
		struct signalfd_ctx *ctx = file->private_data;
		v->cpt_lflags |= CPT_DENTRY_SIGNALFD;
		v->cpt_priv = cpt_sigset_export(&ctx->sigmask);
	} else if (is_timerfd_file(file))
		v->cpt_lflags |= CPT_DENTRY_TIMERFD;
	else if (is_eventfd_file(file))
		v->cpt_lflags |= CPT_DENTRY_EVENTFD;

	v->cpt_vfsmount = mntobj ? mntobj->o_pos : CPT_NULL;

	ctx->write(v, sizeof(*v), ctx);
	cpt_release_buf(ctx);

	err = cpt_dump_path(file->f_dentry, file->f_vfsmnt, replaced, ctx);

	if (err)
		return err;

	if ((file->f_mode & FMODE_WRITE) &&
	     file->f_dentry->d_inode->i_sb->s_magic == FSMAGIC_VEFS)
		vefs_track_notify_hook(file->f_dentry, 1);

	if (is_timerfd_file(file))
		dump_content_timerfd(file, ctx);

	if (is_eventfd_file(file))
		dump_content_eventfd(file, ctx);

	if (file->f_dentry->d_inode->i_flock)
		err = cpt_dump_flock(file, ctx);

	cpt_close_object(ctx);

	if ((file->f_flags & FASYNC) && (v->cpt_fown_fd == -1)) {
		eprintk_ctx("No fd for FASYNC %pS\n", file->f_op);
		return -EINVAL;
	}

	return err;
}

int cpt_page_is_zero(struct page * page)
{
	int res;
	unsigned long *kaddr = kmap_atomic(page, KM_USER0);

	if (kaddr[0] ||
	    memcmp(kaddr, kaddr + 1, PAGE_SIZE - sizeof(unsigned long)))
		res = 0;
	else
		res = 1;

	kunmap_atomic(kaddr, KM_USER0);
	return res;
}

enum {
	TYPE_NONE,
	TYPE_ZERO,
	TYPE_DATA,
	TYPE_ITER
};

struct dump_data
{
	cpt_context_t * ctx;
	loff_t obj_opened;
	struct cpt_page_block pgb;
	int type;
};

static void flush_block(struct dump_data *dat)
{
	cpt_context_t * ctx = dat->ctx;

	if (dat->type == TYPE_NONE)
		return;
	if (dat->type == TYPE_ZERO)
		return;

	ctx->pwrite(&dat->pgb.cpt_end, 8, ctx,
		    dat->obj_opened + offsetof(struct cpt_page_block, cpt_end));
	ctx->align(ctx);
	cpt_close_object(ctx);

	dat->obj_opened = CPT_NULL;
	dat->type = TYPE_NONE;
}

static int
dump_actor(struct pipe_inode_info *pipe, struct pipe_buffer *buf,
		struct splice_desc *sd)
{
	struct dump_data * dat = sd->u.data;
	cpt_context_t * ctx = dat->ctx;
	struct page *page = buf->page;
	unsigned long size;
	int ret;

	ret = buf->ops->confirm(pipe, buf);
	if (unlikely(ret))
		return ret;

	size = sd->len;

	if (page == ZERO_PAGE(0) ||
	    cpt_page_is_zero(page)) {
		if (dat->type == TYPE_ZERO) {
			/* Just append. */
			dat->pgb.cpt_end += PAGE_SIZE;
		}
		/* Flush opened segment */
		if (dat->type != TYPE_NONE)
			flush_block(dat);

		dat->pgb.cpt_start = page->index << PAGE_CACHE_SHIFT;
		dat->type = TYPE_ZERO;
	} else {
		int ntype = TYPE_DATA;

#ifdef CONFIG_VZ_CHECKPOINT_ITER
		if (PageCheckpointed(page) &&
		    ctx->iter_shm_start &&
		    !cpt_verify_wrprot(page, ctx))
			ntype = TYPE_ITER;
#endif
		if (ntype != dat->type ||
		    (ntype == TYPE_ITER &&
		     dat->pgb.cpt_end - dat->pgb.cpt_start >= 16*PAGE_SIZE))
			flush_block(dat);

		if (ntype != dat->type) {
			cpt_open_object(NULL, ctx);
			dat->obj_opened = ctx->file->f_pos;
			dat->pgb.cpt_next = CPT_NULL;
			dat->pgb.cpt_object = ntype == TYPE_DATA ? CPT_OBJ_PAGES :
				CPT_OBJ_ITERPAGES;
			dat->pgb.cpt_hdrlen = sizeof(dat->pgb);
			dat->pgb.cpt_content = CPT_CONTENT_DATA;
			dat->pgb.cpt_start = page->index << PAGE_CACHE_SHIFT;
			dat->pgb.cpt_end = dat->pgb.cpt_start;

			ctx->write(&dat->pgb, sizeof(dat->pgb), ctx);
			dat->type = ntype;
		}

		if (ntype == TYPE_DATA) {
			char * kaddr = kmap(page);
			ctx->write(kaddr, size, ctx);
			kunmap(page);
			if (size < PAGE_SIZE) {
				kaddr = kmap(ZERO_PAGE(0));
				ctx->write(kaddr, PAGE_SIZE - size, ctx);
				kunmap(ZERO_PAGE(0));
				size = PAGE_SIZE;
			}
		} else {
			__u64 pfn = page_to_pfn(page);
			ctx->write(&pfn, 8, ctx);
			size = PAGE_SIZE;
		}
	}
	dat->pgb.cpt_end += size;

	return sd->len;
}

static int
dump_splice_actor(struct pipe_inode_info *pipe, struct splice_desc *sd)
{
	return __splice_from_pipe(pipe, sd, dump_actor);
}

static int dump_content_regular(struct file *file, struct cpt_context *ctx)
{
	loff_t saved_pos;
	struct dump_data dat;
	long retval;
	struct splice_desc sd;

	if (file->f_op == NULL)
		return -EINVAL;

	if (file->f_op == &shm_file_operations)
		file = ((struct shm_file_data *)file->private_data)->file;

	if (file->f_op == &shmem_file_operations) {
		cpt_object_t *obj;

		obj = lookup_cpt_object(CPT_OBJ_FILE, file, ctx);
		if (!obj) {
			eprintk_ctx("failed to find tmpfs file %p\n", file);
			return -ENOENT;
		}

		if (obj->o_flags & CPT_FILE_SYSVIPC) {
			retval = cpt_dump_content_sysvshm(file, ctx);
			if (retval < 0) {
				eprintk_ctx("cannot dump SysV IPC Shared Memory %ld\n", retval);
				return retval;
			}
		}
	}

	if (!(file->f_mode & FMODE_READ) || (file->f_flags & O_DIRECT)) {
		struct file *filp;

		filp = dentry_open(dget(file->f_dentry),
					mntget(file->f_vfsmnt),
					O_RDONLY | O_LARGEFILE,
					current_cred());
		if (IS_ERR(filp)) {
			cpt_printk_dentry(file->f_dentry, file->f_vfsmnt);
			eprintk_ctx("cannot reopen file for read %ld\n", PTR_ERR(filp));
			return PTR_ERR(filp);
		}
		file = filp;
	} else
		get_file(file);

	dat.ctx = ctx;
	dat.type = TYPE_NONE;

	cpt_push_object(&saved_pos, ctx);

	sd.len = 0;
	sd.total_len = 0x40000000UL;
	sd.flags = 0;
	sd.pos = 0;
	sd.u.data = &dat;

	retval = splice_direct_to_actor(file, &sd, dump_splice_actor);
	if (unlikely(retval < 0)) {
		fput(file);
		return retval;
	}

	if (dat.type != TYPE_NONE)
		flush_block(&dat);

	cpt_pop_object(&saved_pos, ctx);

	fput(file);

	return 0;
}


static int dump_content_chrdev(struct file *file, struct cpt_context *ctx)
{
	dev_t dev = file->f_dentry->d_inode->i_rdev;

	if (MAJOR(dev) == MEM_MAJOR || dev == MKDEV(MISC_MAJOR, TUN_MINOR))
		return 0;
	if (chrdev_is_tty(dev))
		return cpt_dump_content_tty(file, ctx);

	eprintk_ctx("unsupported chrdev %d/%d\n", MAJOR(dev), MINOR(dev));
	return -EINVAL;
}

static int dump_content_blkdev(struct file *file, struct cpt_context *ctx)
{
	struct inode *ino = file->f_dentry->d_inode;

	/* We are not going to transfer them. */
	eprintk_ctx("unsupported blkdev %d/%d\n", imajor(ino), iminor(ino));
	return -EINVAL;
}

static int dump_content_fifo(struct file *file, struct cpt_context *ctx)
{
	struct inode *ino = file->f_dentry->d_inode;
	cpt_object_t *obj;
	loff_t saved_pos;
	int readers;
	int writers;
	int anon = 0;

	mutex_lock(&ino->i_mutex);
	readers = ino->i_pipe->readers;
	writers = ino->i_pipe->writers;
	for_each_object(obj, CPT_OBJ_FILE) {
		struct file *file1 = obj->o_obj;
		if (file1->f_dentry->d_inode == ino) {
			if (file1->f_mode & FMODE_READ)
				readers--;
			if (file1->f_mode & FMODE_WRITE)
				writers--;
		}
	}
	mutex_unlock(&ino->i_mutex);
	if (readers || writers) {
		struct dentry *dr = file->f_dentry->d_sb->s_root;
		if (dr->d_name.len == 7 && memcmp(dr->d_name.name,"pipefs:",7) == 0)
			anon = 1;

		if (anon) {
			eprintk_ctx("pipe has %d/%d external readers/writers\n", readers, writers);
			return -EBUSY;
		}
		/* If fifo has external readers/writers, we are in troubles.
		 * If the buffer is not empty, we must move its content.
		 * But if the fifo is owned by a service, we cannot do
		 * this. See?
		 *
		 * For now we assume, that if fifo is opened by another
		 * process, we do not own it and, hence, migrate without
		 * data.
		 */
		return 0;
	}

	/* OK, we must save fifo state. No semaphores required. */

	if (ino->i_pipe->nrbufs) {
		struct cpt_obj_bits *v;
		struct pipe_inode_info *info;
		int count, buf, nrbufs;

		cpt_push_object(&saved_pos, ctx);
		cpt_close_object(ctx);
		mutex_lock(&ino->i_mutex);
		info =  ino->i_pipe;
		count = 0;
		buf = info->curbuf;
		nrbufs = info->nrbufs;
		while (--nrbufs >= 0) {
			if (!info->bufs[buf].ops->can_merge) {
				mutex_unlock(&ino->i_mutex);
				cpt_pop_object(&saved_pos, ctx);
				eprintk_ctx("unknown format of pipe buffer\n");
				return -EINVAL;
			}
			count += info->bufs[buf].len;
			buf = (buf+1) & (PIPE_BUFFERS-1);
		}

		if (!count) {
			mutex_unlock(&ino->i_mutex);
			cpt_pop_object(&saved_pos, ctx);
			return 0;
		}
		v = cpt_get_buf(ctx);
		cpt_open_object(NULL, ctx);
		v->cpt_next = CPT_NULL;
		v->cpt_object = CPT_OBJ_BITS;
		v->cpt_hdrlen = sizeof(*v);
		v->cpt_content = CPT_CONTENT_DATA;
		v->cpt_size = count;
		ctx->write(v, sizeof(*v), ctx);
		cpt_release_buf(ctx);

		count = 0;
		buf = info->curbuf;
		nrbufs = info->nrbufs;
		while (--nrbufs >= 0) {
			struct pipe_buffer *b = info->bufs + buf;
			/* need to ->pin first? */
			void * addr = b->ops->map(info, b, 0);
			ctx->write(addr + b->offset, b->len, ctx);
			b->ops->unmap(info, b, addr);
			buf = (buf+1) & (PIPE_BUFFERS-1);
		}

		mutex_unlock(&ino->i_mutex);

		ctx->align(ctx);
		cpt_close_object(ctx);
		cpt_pop_object(&saved_pos, ctx);
	}

	return 0;
}

static int dump_content_socket(struct file *file, struct cpt_context *ctx)
{
	return 0;
}

struct cpt_dirent {
	unsigned long	ino;
	char		*name;
	int		namelen;
	int		found;
};

static int cpt_filldir(void * __buf, const char * name, int namelen,
		loff_t offset, u64 ino, unsigned int d_type)
{
	struct cpt_dirent * dirent = __buf;

	if ((ino == dirent->ino) && (namelen < PAGE_SIZE - 1)) {
		memcpy(dirent->name, name, namelen);
		dirent->name[namelen] = '\0';
		dirent->namelen = namelen;
		dirent->found = 1;
		return 1;
	}
	return 0;
}

struct dentry *get_linked_dentry(struct dentry *d, struct vfsmount *mnt,
					struct cpt_context *ctx)
{
	struct inode *ino = d->d_inode;
	int err = -EBUSY;
	struct file *f = NULL;
	struct cpt_dirent entry;
	struct dentry *de, *found = NULL;

	dprintk_ctx("deleted reference to existing inode, try to find file\n");
	/* 1. Try to find not deleted dentry in ino->i_dentry list */
	spin_lock(&dcache_lock);
	list_for_each_entry(de, &ino->i_dentry, d_alias) {
		if (!IS_ROOT(de) && d_unhashed(de))
			continue;
		found = de;
		dget_locked(found);
		break;
	}
	spin_unlock(&dcache_lock);
	if (found) {
		dprintk_ctx("dentry found in aliases\n");
		return found;
	}

	/* 2. Try to find file in current dir */
	de = dget_parent(d);
	if (found)
		return ERR_PTR(-EINVAL);

	mntget(mnt);
	f = dentry_open(de, mnt, O_RDONLY | O_LARGEFILE, current_cred());
	if (IS_ERR(f))
		return (void *)f;

	entry.ino = ino->i_ino;
	entry.found = 0;
	entry.name = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!entry.name) {
		fput(f);
		return ERR_PTR(-ENOMEM);
	}

	err = vfs_readdir(f, cpt_filldir, &entry);
	fput(f);
	if (err || !entry.found) {
		found = err ? ERR_PTR(err) : ERR_PTR(-ENOENT);
		goto err_readdir;
	}

	mutex_lock(&de->d_inode->i_mutex);
	found = lookup_one_len(entry.name, de, entry.namelen);
	mutex_unlock(&de->d_inode->i_mutex);
	if (IS_ERR(found))
		goto err_readdir;

	if (found->d_inode != ino) {
		dput(found);
		found = ERR_PTR(-ENOENT);
	} else
		dprintk_ctx("dentry found in dir\n");

err_readdir:
	kfree(entry.name);
	return found;
}

static int dump_unlinked_dentry(struct dentry *d, struct vfsmount *mnt,
				     struct cpt_context *ctx)
{
	struct dentry *found;
	int err;

	if (d->d_flags & DCACHE_NFSFS_RENAMED)
		return cpt_dump_nfs_path(d, mnt, ctx);

	found = get_linked_dentry(d, mnt, ctx);
	if (IS_ERR(found))
		return PTR_ERR(found);

	err = cpt_dump_path(found, mnt, 0, ctx);

	dput(found);
	return err;
}

static struct dentry *find_linkdir(struct vfsmount *mnt, struct cpt_context *ctx)
{
	int i;

	for (i = 0; i < ctx->linkdirs_num; i++)
		if (ctx->linkdirs[i]->f_vfsmnt == mnt)
			return ctx->linkdirs[i]->f_dentry;
	return NULL;
}

static struct dentry *cpt_fake_link(struct dentry *d, struct vfsmount *mnt,
				    struct inode *ino, struct cpt_context *ctx)
{
	int err;
	int order = 8;
	const char *prefix = ".cpt_hardlink.";
	int preflen = strlen(prefix) + order;
	char name[preflen + 1];
	struct dentry *dirde, *hardde;

	dirde = find_linkdir(mnt, ctx);
	if (!dirde) {
		eprintk_ctx("Can't find fake link mntdir\n");
		err = -ENOENT;
		goto out;
	}

	ctx->linkcnt++;
	snprintf(name, sizeof(name), "%s%0*u", prefix, order, ctx->linkcnt);

	mutex_lock(&dirde->d_inode->i_mutex);
	hardde = lookup_one_len(name, dirde, strlen(name));
	if (IS_ERR(hardde)) {
		eprintk_ctx("Can't find hardde: %s\n", name);
		err = PTR_ERR(hardde);
		goto out_unlock;
	}

	if (hardde->d_inode) {
		/* Userspace should clean hardlinked files from previous
		 * dump/undump
		 */
		eprintk_ctx("Hardlinked file already exists: %s\n", name);
		err = -EEXIST;
		goto out_put;
	}

	if (d == NULL) {
		struct nameidata nd;

		nd.flags = LOOKUP_CREATE;
		nd.intent.open.flags = O_EXCL;

		err = vfs_create(dirde->d_inode, hardde, 0600, &nd);
	} else
		err = vfs_link(d, dirde->d_inode, hardde);
	if (err) {
		eprintk_ctx("error hardlink %s, %d\n", name, err);
		goto out_put;
	}

out_unlock:
	mutex_unlock(&dirde->d_inode->i_mutex);
out:
	return err ? ERR_PTR(err) : hardde;

out_put:
	dput(hardde);
	goto out_unlock;
}

static int create_dump_hardlink(struct dentry *d, struct vfsmount *mnt,
				struct inode *ino, struct cpt_context *ctx)
{
	int err;
	struct dentry *hardde;

	hardde = cpt_fake_link(d, mnt, ino, ctx);
	if (IS_ERR(hardde))
		return PTR_ERR(hardde);

	err = cpt_dump_path(hardde, mnt, 0, ctx);
	dput(hardde);

	return err;
}

static int dump_one_inode(struct file *file, struct dentry *d,
			  struct vfsmount *mnt, struct cpt_context *ctx)
{
	int err = 0;
	struct inode *ino = d->d_inode;
	cpt_object_t *iobj;
	int dump_it = 0;

	iobj = lookup_cpt_object(CPT_OBJ_INODE, ino, ctx);
	if (!iobj)
		return -EINVAL;

	if (iobj->o_pos >= 0)
		return 0;

	if (ino->i_sb->s_magic == FSMAGIC_PROC &&
	    proc_dentry_of_dead_task(d))
		return 0;

	if ((!IS_ROOT(d) && d_unhashed(d)) &&
	    !cpt_replaced(d, mnt, ctx))
		dump_it = 1;
	if (!S_ISREG(ino->i_mode) && !S_ISDIR(ino->i_mode)) {
		if (file->f_dentry->d_inode == anon_inode_inode)
			return 0;
		dump_it = 1;
	}

	if (!dump_it)
		return 0;

	cpt_open_object(iobj, ctx);
	cpt_dump_inode(d, mnt, ctx);

	if (!IS_ROOT(d) && d_unhashed(d)) {
		struct file *parent;
		parent = iobj->o_parent;
		if (!parent ||
		    (!IS_ROOT(parent->f_dentry) && d_unhashed(parent->f_dentry))) {
			/* Inode is not deleted, but it does not
			 * have references from inside checkpointed
			 * process group. */
			if (ino->i_nlink != 0) {
				err = dump_unlinked_dentry(d, mnt, ctx);
				if (err && S_ISREG(ino->i_mode)) {
					err = create_dump_hardlink(d, mnt, ino, ctx);
					iobj->o_flags |= CPT_INODE_HARDLINKED;
				} else if (S_ISCHR(ino->i_mode) ||
					   S_ISBLK(ino->i_mode) ||
					   S_ISFIFO(ino->i_mode))
					err = 0;

				if (err) {
					eprintk_ctx("deleted reference to existing inode, checkpointing is impossible: %d\n", err);
					return -EBUSY;
				}
				if (S_ISREG(ino->i_mode) || S_ISDIR(ino->i_mode))
					dump_it = 0;
			}
		} else {
			/* Refer to _another_ file name. */
			err = cpt_dump_path(parent->f_dentry,
					parent->f_vfsmnt, 0, ctx);
			if (err)
				return err;
			if (S_ISREG(ino->i_mode) || S_ISDIR(ino->i_mode))
				dump_it = 0;
		}
	}
	if (dump_it) {
		if (S_ISREG(ino->i_mode)) {
			if ((err = dump_content_regular(file, ctx)) != 0) {
				eprintk_ctx("dump_content_regular ");
				cpt_printk_dentry(d, mnt);
			}
		} else if (S_ISDIR(ino->i_mode)) {
			/* We cannot do anything. The directory should be
			 * empty, so it is not a big deal.
			 */
		} else if (S_ISCHR(ino->i_mode)) {
			err = dump_content_chrdev(file, ctx);
		} else if (S_ISBLK(ino->i_mode)) {
			err = dump_content_blkdev(file, ctx);
		} else if (S_ISFIFO(ino->i_mode)) {
			err = dump_content_fifo(file, ctx);
		} else if (S_ISSOCK(ino->i_mode)) {
			err = dump_content_socket(file, ctx);
		} else {
			eprintk_ctx("unknown inode mode %o, magic 0x%lx\n", ino->i_mode & S_IFMT, ino->i_sb->s_magic);
			err = -EINVAL;
		}
	}
	cpt_close_object(ctx);

	return err;
}

static void cpt_stop_vzfs_trackers(struct cpt_context *ctx)
{
	cpt_object_t *obj;

	for_each_object(obj, CPT_OBJ_VFSMOUNT_REF) {
		struct vfsmount *mnt = obj->o_obj;
		if (mnt->mnt_sb->s_magic == FSMAGIC_VEFS)
			vefs_track_force_stop_hook(mnt->mnt_sb);
	}
}

void cpt_stop_tracker(struct cpt_context *ctx)
{
	cpt_object_t *obj;
	struct kstat sbuf;

	for_each_object(obj, CPT_OBJ_FILE) {
		struct file *file = obj->o_obj;

		cpt_getattr(file->f_vfsmnt, file->f_dentry, &sbuf);

		if (!S_ISSOCK(sbuf.mode) && (file->f_mode & FMODE_WRITE) &&
		    file->f_dentry->d_inode->i_sb->s_magic == FSMAGIC_VEFS)
			vefs_track_notify_hook(file->f_dentry, 1);
	}

	cpt_stop_vzfs_trackers(ctx);
}

int cpt_dump_files(struct cpt_context *ctx)
{
	int epoll_nr, inotify_nr;
	cpt_object_t *obj;

	cpt_open_section(ctx, CPT_SECT_TTY);
	for_each_object(obj, CPT_OBJ_TTY) {
		int err;

		if ((err = cpt_dump_tty(obj, ctx)) != 0)
			return err;
	}
	cpt_close_section(ctx);

	cpt_open_section(ctx, CPT_SECT_INODE);
	for_each_object(obj, CPT_OBJ_FILE) {
		struct file *file = obj->o_obj;
		int err;

		if ((err = dump_one_inode(file, file->f_dentry,
					  file->f_vfsmnt, ctx)) != 0)
			return err;
	}
	for_each_object(obj, CPT_OBJ_FS) {
		struct fs_struct *fs = obj->o_obj;
		int err;

		if (fs->root.dentry &&
		    (err = dump_one_inode(NULL, fs->root.dentry, fs->root.mnt, ctx)) != 0)
			return err;
		if (fs->pwd.dentry &&
		    (err = dump_one_inode(NULL, fs->pwd.dentry, fs->pwd.mnt, ctx)) != 0)
			return err;
	}
	cpt_close_section(ctx);

	epoll_nr = 0;
	inotify_nr = 0;
	cpt_open_section(ctx, CPT_SECT_FILES);
	for_each_object(obj, CPT_OBJ_FILE) {
		struct file *file = obj->o_obj;
		int err;

		if ((err = dump_one_file(obj, file, ctx)) != 0)
			return err;
		if (file->f_op == &eventpoll_fops)
			epoll_nr++;
		if (file->f_dentry->d_inode->i_sb->s_magic == FSMAGIC_INOTIFY)
			inotify_nr++;
	}
	cpt_close_section(ctx);

	if (epoll_nr) {
		cpt_open_section(ctx, CPT_SECT_EPOLL);
		for_each_object(obj, CPT_OBJ_FILE) {
			struct file *file = obj->o_obj;
			if (file->f_op == &eventpoll_fops) {
				int err;
				if ((err = cpt_dump_epolldev(obj, ctx)) != 0)
					return err;
			}
		}
		cpt_close_section(ctx);
	}

	if (inotify_nr) {
		cpt_open_section(ctx, CPT_SECT_INOTIFY);
		for_each_object(obj, CPT_OBJ_FILE) {
			struct file *file = obj->o_obj;
			if (file->f_dentry->d_inode->i_sb->s_magic == FSMAGIC_INOTIFY) {
				int err = -EINVAL;
#ifdef CONFIG_INOTIFY_USER
				if ((err = cpt_dump_inotify(obj, ctx)) != 0)
#endif
					return err;
			}
		}
		cpt_close_section(ctx);
	}

	cpt_open_section(ctx, CPT_SECT_SOCKET);
	for_each_object(obj, CPT_OBJ_SOCKET) {
		int err;

		if ((err = cpt_dump_socket(obj, obj->o_obj, obj->o_index, -1, ctx)) != 0)
			return err;
	}
	cpt_close_section(ctx);

	cpt_stop_vzfs_trackers(ctx);

	return 0;
}

static int dump_filedesc(int fd, struct file *file,
			 struct files_struct *f, struct cpt_context *ctx)
{
	struct cpt_fd_image *v = cpt_get_buf(ctx);
	cpt_object_t *obj;

	cpt_open_object(NULL, ctx);

	v->cpt_next = CPT_NULL;
	v->cpt_object = CPT_OBJ_FILEDESC;
	v->cpt_hdrlen = sizeof(*v);
	v->cpt_content = CPT_CONTENT_VOID;

	v->cpt_fd = fd;
	obj = lookup_cpt_object(CPT_OBJ_FILE, file, ctx);
	if (!obj) BUG();
	v->cpt_file = obj->o_pos;
	v->cpt_flags = 0;
	if (FD_ISSET(fd, f->fdt->close_on_exec))
		v->cpt_flags = CPT_FD_FLAG_CLOSEEXEC;

	ctx->write(v, sizeof(*v), ctx);
	cpt_release_buf(ctx);
	cpt_close_object(ctx);

	return 0;
}

static int dump_one_file_struct(cpt_object_t *obj, struct cpt_context *ctx)
{
	struct files_struct *f = obj->o_obj;
	struct cpt_files_struct_image *v = cpt_get_buf(ctx);
	int fd;
	loff_t saved_obj;

	cpt_open_object(obj, ctx);

	v->cpt_next = CPT_NULL;
	v->cpt_object = CPT_OBJ_FILES;
	v->cpt_hdrlen = sizeof(*v);
	v->cpt_content = CPT_CONTENT_ARRAY;

	v->cpt_index = obj->o_index;
	v->cpt_max_fds = f->fdt->max_fds;
	v->cpt_next_fd = f->next_fd;

	ctx->write(v, sizeof(*v), ctx);
	cpt_release_buf(ctx);

	cpt_push_object(&saved_obj, ctx);
	for (fd = 0; fd < f->fdt->max_fds; fd++) {
		struct file *file = fcheck_files(f, fd);
		if (file)
			dump_filedesc(fd, file, f, ctx);
	}
	cpt_pop_object(&saved_obj, ctx);

	cpt_close_object(ctx);

	return 0;
}

int cpt_dump_files_struct(struct cpt_context *ctx)
{
	cpt_object_t *obj;

	cpt_open_section(ctx, CPT_SECT_FILES_STRUCT);

	for_each_object(obj, CPT_OBJ_FILES) {
		int err;

		if ((err = dump_one_file_struct(obj, ctx)) != 0)
			return err;
	}

	cpt_close_section(ctx);
	return 0;
}

int cpt_collect_fs(cpt_context_t * ctx)
{
	cpt_object_t *obj;

	for_each_object(obj, CPT_OBJ_TASK) {
		struct task_struct *tsk = obj->o_obj;
		if (tsk->fs) {
			if (cpt_object_add(CPT_OBJ_FS, tsk->fs, ctx) == NULL)
				return -ENOMEM;
			if (tsk->fs->pwd.dentry &&
			    cpt_object_add(CPT_OBJ_INODE, tsk->fs->pwd.dentry->d_inode, ctx) == NULL)
				return -ENOMEM;
			if (tsk->fs->root.dentry &&
			    cpt_object_add(CPT_OBJ_INODE, tsk->fs->root.dentry->d_inode, ctx) == NULL)
				return -ENOMEM;
		}
	}
	return 0;
}

int cpt_dump_dir(struct dentry *d, struct vfsmount *mnt, struct cpt_context *ctx)
{
	struct dentry new_d;
	struct file file;

	memset(&file, 0, sizeof(file));

	if (!d) {
		memset(&new_d, 0, sizeof(new_d));
		new_d.d_parent = &new_d;
		new_d.d_inode = anon_inode_inode;
		new_d.d_name.name = FAKE_FILE_NAME;
		new_d.d_name.len = strlen(FAKE_FILE_NAME);
		file.f_op = &bad_file_ops;
		d = &new_d;
	}

	file.f_dentry = d;
	file.f_vfsmnt = mnt;
	file.f_mode = FMODE_READ|FMODE_PREAD|FMODE_LSEEK;
	file.f_cred = current->cred;

	return dump_one_file(NULL, &file, ctx);
}

static int dump_one_fs(cpt_object_t *obj, struct cpt_context *ctx)
{
	struct fs_struct *fs = obj->o_obj;
	struct cpt_fs_struct_image *v = cpt_get_buf(ctx);
	loff_t saved_obj;
	int err;

	cpt_open_object(obj, ctx);

	v->cpt_next = CPT_NULL;
	v->cpt_object = CPT_OBJ_FS;
	v->cpt_hdrlen = sizeof(*v);
	v->cpt_content = CPT_CONTENT_ARRAY;

	v->cpt_umask = fs->umask;

	ctx->write(v, sizeof(*v), ctx);
	cpt_release_buf(ctx);

	cpt_push_object(&saved_obj, ctx);
	err = cpt_dump_dir(fs->root.dentry, fs->root.mnt, ctx);
	if (!err)
		err = cpt_dump_dir(fs->pwd.dentry, fs->pwd.mnt, ctx);

	cpt_pop_object(&saved_obj, ctx);

	cpt_close_object(ctx);

	return err;
}

int cpt_dump_fs_struct(struct cpt_context *ctx)
{
	cpt_object_t *obj;

	cpt_open_section(ctx, CPT_SECT_FS);

	for_each_object(obj, CPT_OBJ_FS) {
		int err;

		if ((err = dump_one_fs(obj, ctx)) != 0)
			return err;
	}

	cpt_close_section(ctx);
	return 0;
}

static int check_autofs(struct super_block *sb, struct cpt_context *ctx)
{
	struct autofs_sb_info *si;
	struct file *f;

	si = autofs4_sbi(sb);
	if (si->version > 5) {
		eprintk_ctx("autofs higher than ver5 is not supported\n");
		return -EINVAL;
	}

	f = get_task_file(si->pipe_pid, si->pipefd);
	if (IS_ERR(f)) {
		eprintk_ctx("autofs pipe is not attached (%ld)\n", PTR_ERR(f));
		return PTR_ERR(f);
	}

	if (f != si->pipe) {
		eprintk_ctx("autofs pipe is not attached\n");
		fput(f);
		return -EBADF;
	}

	if (f->f_mode & FMODE_READ) {
		fput(f);
		eprintk_ctx("autofs pipe is attached by the wrong end\n");
		return -EBADF;
	}

	/*
	 * currently autofs' pipefd is
	 *  a) opened write only
	 *  b) attached to the daemon task
	 * these two points make our life very easy:
	 *  a) we can attach the file to sbi on restore after
	 *     unfreeze - daemon will not try to write in there
	 *  b) we can avoid dumping the fd for sbi separately,
	 *     since the required file will be restore with the
	 *     task struct in question
	 *
	 * In case this breaks some time later (I don't believe it)
	 * we'll have to dump the opened file ID to the pipe_fd_id
	 * field of the autofs_mount_data
	 */
	fput(f);

	return cpt_object_add(CPT_OBJ_FILE, si->pipe, ctx) ? 0 : -ENOMEM;
}

static int collect_vfsmount_tree(struct vfsmount *tree, cpt_object_t *ns_obj,
				 cpt_context_t *ctx)
{
	int err = 0;
	char *path_buf, *path;
	struct vfsmount *mnt;
	cpt_object_t *obj;

	path_buf = (char *) __get_free_page(GFP_KERNEL);
	if (!path_buf)
		return -ENOMEM;

	down_read(&namespace_sem);
	for (mnt = tree; mnt; mnt = next_mnt(mnt, tree)) {
		struct path pt;

		pt.dentry = mnt->mnt_root;
		pt.mnt = mnt;
		path = d_path(&pt, path_buf, PAGE_SIZE);
		if (IS_ERR(path))
			continue;

		if (check_one_vfsmount(mnt)) {
			eprintk_ctx("unsupported fs type %s\n", mnt->mnt_sb->s_type->name);
			err = -EINVAL;
			break;
		}

		if (is_autofs_mount(mnt->mnt_parent))
			continue;

		if (is_nfs_automount(mnt))
			continue;

		if (cpt_need_delayfs(mnt->mnt_parent)) {
			eprintk_ctx("unsupported delayfs submount: %s\n", path);
			err = -EINVAL;
			break;
		}

		if (strncmp(path, " (deleted)", 10) == 0) {
			eprintk_ctx("unsupported deleted submount: %s\n", path);
			err = -EINVAL;
			break;
		}

		if (is_autofs_mount(mnt)) {
			err = check_autofs(mnt->mnt_sb, ctx);
			if (err)
				break;
		}

		obj = cpt_object_add(CPT_OBJ_VFSMOUNT_REF, mnt, ctx);
		if (!obj) {
			err = -ENOMEM;
			break;
		}
		mntget(mnt);

		if (mnt != tree) {
			obj->o_parent = lookup_cpt_object(CPT_OBJ_VFSMOUNT_REF,
							mnt->mnt_parent, ctx);
			if (!obj->o_parent) {
				err = -ENOLINK;
				break;
			}
		}
	}
	up_read(&namespace_sem);

	free_page((unsigned long) path_buf);

	return err;
}

int cpt_collect_namespace(cpt_context_t * ctx)
{
	struct vfsmount *root;
	cpt_object_t *obj, *ns_obj;
	int err;

	/*
	 * Main namespace shared between all containers,
	 * here we want to collect only subtree for one ve.
	 */
	root = get_exec_env()->root_path.mnt;
	ns_obj = cpt_object_add(CPT_OBJ_NAMESPACE, root->mnt_ns, ctx);
	if (!ns_obj)
		return -ENOMEM;
	ns_obj->o_flags |= CPT_NAMESPACE_MAIN;

	err = collect_vfsmount_tree(root, ns_obj, ctx);
	if (err)
		return err;

	for_each_object(obj, CPT_OBJ_TASK) {
		struct task_struct *tsk = obj->o_obj;

		if (!tsk->nsproxy || !tsk->nsproxy->mnt_ns)
			continue;

		root = tsk->nsproxy->mnt_ns->root;
		ns_obj = cpt_object_add(CPT_OBJ_NAMESPACE, root->mnt_ns, ctx);
		if (!ns_obj)
			return -ENOMEM;
		if (ns_obj->o_count > 1)
			continue;
		err = collect_vfsmount_tree(root, ns_obj, ctx);
		if (err)
			 break;
	}

	return err;
}

static void *collect_nfs_mount_data(struct vfsmount *mnt) 
{
	struct nfs_mount_data_dump *d;
	struct nfs_server *nfss = NFS_SB(mnt->mnt_sb);
	struct nfs_fh *mntfh = NFS_FH(mnt->mnt_root->d_inode);
	struct nfs_client *clp = nfss->nfs_client;
	struct rpc_clnt *rpc_clp = clp->cl_rpcclient;
	char *tmp;

	d = (void *)__get_free_pages(GFP_KERNEL, 1);
	if (!d)
		return NULL;

	memset(d, 0, PAGE_SIZE << 1);

	d->version = NFS_MOUNT_MIGRATED;
	d->flags = nfss->flags;
	d->rsize = nfss->rsize;
	d->wsize = nfss->wsize;
	d->timeo = 10U * rpc_clp->cl_timeout->to_initval / HZ;
	d->retrans = rpc_clp->cl_timeout->to_retries;
	d->acregmin = nfss->acregmin/HZ;
	d->acregmax = nfss->acregmax/HZ;
	d->acdirmin = nfss->acdirmin/HZ;
	d->acdirmax = nfss->acdirmax/HZ;
	d->namlen = nfss->namelen;
	d->options = nfss->options;
	d->bsize = nfss->bsize;
	d->minorversion = clp->cl_minorversion;

	strcpy(d->client_address, clp->cl_ipaddr);

	nfs_fscache_dup_uniq_id(d->fscache_uniq, mnt->mnt_sb);

	d->mount_server.addrlen = nfss->mountd_addrlen;
	memcpy(&d->mount_server.address, &nfss->mountd_address,
			d->mount_server.addrlen);

	d->mount_server.version = nfss->mountd_version;
	d->mount_server.port = nfss->mountd_port;
	d->mount_server.protocol = nfss->mountd_protocol;

	d->nfs_server.addrlen = clp->cl_addrlen;
	memcpy(&d->nfs_server.address, &clp->cl_addr,
			d->nfs_server.addrlen);
	strcpy(d->nfs_server.hostname, clp->cl_hostname);

	tmp = strchr(mnt->mnt_devname, '/');
	if (tmp)
		strcpy(d->nfs_server.export_path, tmp);

	d->nfs_server.port = nfss->port;
	d->nfs_server.protocol = clp->cl_proto;

	d->auth_flavors = clp->cl_rpcclient->cl_auth->au_flavor;

	d->root.size = mntfh->size;
	memcpy(d->root.data, mntfh->data, sizeof(d->root.data));

	BUILD_BUG_ON(sizeof(*d) > (PAGE_SIZE << 1));

	return d;
}

static int dump_nfs_mount_data(struct vfsmount *mnt, cpt_context_t * ctx)
{
	struct cpt_object_hdr o;
	void *data;

	BUG_ON(mnt->mnt_sb->s_magic != FSMAGIC_NFS);

	data = collect_nfs_mount_data(mnt);
	if (!data)
		return -ENOMEM;

	o.cpt_next = CPT_NULL;
	o.cpt_object = CPT_OBJ_MOUNT_DATA;
	o.cpt_hdrlen = sizeof(o);
	o.cpt_content = CPT_CONTENT_VOID;

	cpt_open_object(NULL, ctx);
	ctx->write(&o, sizeof(o), ctx);
	ctx->write(data, PAGE_SIZE << 1, ctx);
	ctx->align(ctx);
	cpt_close_object(ctx);

	free_pages((unsigned long)data, 1);
	return 0;
}

static void dump_autofs_mount_data(struct vfsmount *mnt, cpt_context_t * ctx)
{
	struct autofs_mount_data d;
	struct autofs_sb_info *si;
	struct cpt_object_hdr o;

	si = autofs4_sbi(mnt->mnt_sb);

	d.i_uid = mnt->mnt_sb->s_root->d_inode->i_uid;
	d.i_gid = mnt->mnt_sb->s_root->d_inode->i_gid;
	d.oz_pgrp = cpt_pid_nr(si->oz_pgrp);
	d.type = si->type;
	d.min_proto = si->min_proto;
	d.max_proto = si->max_proto;
	d.exp_timeout = si->exp_timeout;
	d.pipefd = si->pipefd;
	d.pipe_pid = si->pipe_pid;
	d.is32bit = 0;
#if defined CONFIG_X86_64 && defined CONFIG_IA32_EMULATION
	d.is32bit = si->is32bit;
#endif
	d.pipe_fd_id = CPT_NULL;

	o.cpt_next = CPT_NULL;
	o.cpt_object = CPT_OBJ_MOUNT_DATA;
	o.cpt_hdrlen = sizeof(o);
	o.cpt_content = CPT_CONTENT_VOID;

	cpt_open_object(NULL, ctx);
	ctx->write(&o, sizeof(o), ctx);
	ctx->write(&d, sizeof(d), ctx);
	ctx->align(ctx);
	cpt_close_object(ctx);
}

struct args_t
{
	int* pfd;
	char* path;
	envid_t veid;
	struct vfsmount *mnt;
	char *buf;
};

static int dumptmpfs(void *arg)
{
	int i;
	struct args_t *args = arg;
	int *pfd = args->pfd;
	int fd0, fd2;
	char *path = args->path;
	char *argv[] = { "tar", "-c", "-S", "--numeric-owner", path, NULL, NULL, NULL };

	i = real_env_create(args->veid, VE_ENTER|VE_SKIPLOCK, 2, NULL, 0);
	if (i < 0) {
		eprintk("cannot enter ve to dump tmpfs\n");
		module_put(THIS_MODULE);
		return 255 << 8;
	}

	if (args->mnt && !list_empty(&args->mnt->mnt_mounts) && strcmp(path, ".") != 0) {
		/*
		 * Child mounts prevent dumping of parent tmpfs content.
		 * We use bind mount to make them hidden. Trick with
		 * "--transform" allows to save full path in tar file.
		 */
		args->buf = vmalloc(strlen(path) + sizeof("s,^,//,S") + 1);
		if (!args->buf) {
			eprintk("cannot alloc memory\n");
			module_put(THIS_MODULE);
			return 255 << 8;
		}

		sprintf(args->buf, "s,^,%s/,S", path); /* Add a prefix to path */
		path = ".";
		argv[4] = path;
		argv[5] = "--transform";
		argv[6] = args->buf;
	}

	if (strcmp(path, ".") == 0) {
		struct path pwd;

		pwd.mnt = vfs_bind_mount_private(args->mnt, args->mnt->mnt_root);
		if (IS_ERR(pwd.mnt)) {
			eprintk("cannot create bind mount to dump tmpfs\n");
			module_put(THIS_MODULE);
			return 255 << 8;
		}
		pwd.dentry = pwd.mnt->mnt_root;
		set_fs_pwd(current->fs, &pwd);
		mntput(pwd.mnt);
	}

	if (pfd[1] != 1)
		sc_dup2(pfd[1], 1);
	set_fs(KERNEL_DS);
	fd0 = sc_open("/dev/null", O_RDONLY, 0);
	fd2 = sc_open("/dev/null", O_WRONLY, 0);
	if (fd0 < 0 || fd2 < 0) {
		eprintk("can not open /dev/null for tar: %d %d\n", fd0, fd2);
		module_put(THIS_MODULE);
		return 255 << 8;
	}
	if (fd0 != 0)
		sc_dup2(fd0, 0);
	if (fd2 != 2)
		sc_dup2(fd2, 2);

	for (i = 3; i < current->files->fdt->max_fds; i++) {
		sc_close(i);
	}

	module_put(THIS_MODULE);

	i = kernel_execve("/bin/tar", argv, NULL);
	eprintk("failed to exec /bin/tar: %d\n", i);
	return 255 << 8;
}

static int cpt_dump_tmpfs(char *path, struct vfsmount *mnt,
			  struct cpt_context *ctx)
{
	int err;
	int pid;
	int pfd[2];
	struct file *f;
	struct cpt_obj_tar v;
	char buf[16];
	int n, tar_ret;
	loff_t saved_obj;
	struct args_t args;
	int status;
	mm_segment_t oldfs;
	sigset_t ignore, blocked;
	struct ve_struct *oldenv;
	u32 len;
	loff_t start_pos = ctx->file->f_pos;
again:
	len = 0;

	err = sc_pipe(pfd);
	if (err < 0)
		return err;
	args.pfd = pfd;
	args.path = path;
	args.veid = VEID(get_exec_env());
	args.mnt = mnt;
	args.buf = NULL;
	ignore.sig[0] = CPT_SIG_IGNORE_MASK;
	sigprocmask(SIG_BLOCK, &ignore, &blocked);
	oldenv = set_exec_env(get_ve0());
	err = pid = local_kernel_thread(dumptmpfs, (void*)&args,
			SIGCHLD | CLONE_VFORK, 0);
	set_exec_env(oldenv);
	if (err < 0) {
		eprintk_ctx("tmpfs local_kernel_thread: %d\n", err);
		goto out;
	}
	f = fget(pfd[0]);
	sc_close(pfd[1]);
	sc_close(pfd[0]);

	cpt_push_object(&saved_obj, ctx);
	cpt_open_object(NULL, ctx);
	v.cpt_next = CPT_NULL;
	v.cpt_object = CPT_OBJ_NAME;
	v.cpt_hdrlen = sizeof(v);
	v.cpt_content = CPT_CONTENT_DATA;
	v.cpt_len = 0;

	ctx->write(&v, sizeof(v), ctx);

	do {
		oldfs = get_fs(); set_fs(KERNEL_DS);
		n = f->f_op->read(f, buf, sizeof(buf), &f->f_pos);
		set_fs(oldfs);
		if (n > 0)
			ctx->write(buf, n, ctx);
		len += n;
	} while (n > 0);

	fput(f);

	/* Write real tar'ed lenght */
	ctx->pwrite(&len, sizeof(len), ctx,
		    ctx->current_object + offsetof(struct cpt_obj_tar, cpt_len));

	oldfs = get_fs(); set_fs(KERNEL_DS);
	tar_ret = 0xffff;
	err = sc_waitx(pid, 0, &status);
	if (err < 0)
		eprintk_ctx("wait4: %d\n", err);
	else if ((status & 0x7f) == 0) {
		err = tar_ret = (status & 0xff00) >> 8;
		if (tar_ret != 0) {
			eprintk_ctx("tar exited with %d\n", tar_ret);
			err = -EINVAL;
		}
	} else {
		eprintk_ctx("tar terminated\n");
		err = -EINVAL;
	}
	if (args.buf)
		vfree(args.buf);
	set_fs(oldfs);
	sigprocmask(SIG_SETMASK, &blocked, NULL);

	buf[0] = 0;
	ctx->write(buf, 1, ctx);
	ctx->align(ctx);
	cpt_close_object(ctx);
	cpt_pop_object(&saved_obj, ctx);

	if ((tar_ret == 64 || tar_ret == 2) && mnt &&
	    !list_empty(&mnt->mnt_mounts) && strcmp(path, ".") != 0) {
		eprintk_ctx("old tar version is detected inside container, "
			    "it does not allow us to dump child tmpfs bindmounts "
			    "correctly, using workaround\n");
		mnt = NULL;
		ctx->file->f_pos = start_pos;
		goto again;
	}

	return n ? : err;

out:
	if (pfd[1] >= 0)
		sc_close(pfd[1]);
	if (pfd[0] >= 0)
		sc_close(pfd[0]);
	sigprocmask(SIG_SETMASK, &blocked, NULL);
	return err;
}

static cpt_object_t *cpt_lookup_bind_source(struct vfsmount *mnt,
		cpt_context_t *ctx)
{
	cpt_object_t *obj;
	struct vfsmount *src;
	struct path p;

	p.dentry = mnt->mnt_root;

	for_each_object(obj, CPT_OBJ_VFSMOUNT_REF) {
		src = obj->o_obj;
		p.mnt = src;

		if (src == mnt)
			break;
		if (src->mnt_sb != mnt->mnt_sb)
			continue;
		if (IS_ERR(d_path(&p, NULL, 0)))
			continue;
		return obj;
	}
	if (mnt->mnt_root != mnt->mnt_sb->s_root)
		return ERR_PTR(-ENODEV);
	return NULL;
}

void uuid_bytes_to_hex(char *buf, const u8 *u)
{
	sprintf(buf, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
			(((((u[0] * 0x100) + u[1]) * 0x100) + u[2]) * 0x100 + u[3]),
			u[4] * 0x100 + u[5],
			u[6] * 0x100 + u[7],
			u[8], u[9],
			u[10], u[11], u[12], u[13], u[14], u[15]);
}

EXPORT_SYMBOL(uuid_bytes_to_hex);

static void cpt_dump_uuid(struct vfsmount *mnt, cpt_context_t *ctx)
{
	const u8 *uuid = mnt->mnt_sb->s_uuid;
	char *buf = cpt_get_buf(ctx);

	uuid_bytes_to_hex(buf, uuid);
	cpt_dump_string(buf, ctx);

	__cpt_release_buf(ctx);
}

/* Checks if mnt is ploop, which is mounted inside container */
static int is_ploop(struct vfsmount *mnt, struct cpt_context *ctx)
{
	struct super_block *sb = mnt->mnt_sb;
	const char *name;

	BUG_ON(!rwsem_is_locked(&namespace_sem));

	if (slab_ub(mnt) != get_exec_ub_top())
		return 0;

	if (!sb->s_bdev || !sb->s_bdev->bd_disk)
		return 0;

	name = sb->s_bdev->bd_disk->disk_name;

	if (strncmp(name, "ploop", 5) != 0)
		return 0;

	if (mnt->mnt_root != mnt->mnt_sb->s_root)
		return 0;

	return (cpt_lookup_bind_source(mnt, ctx) == NULL);
}

bool mnt_is_tmpfs(struct vfsmount *mnt)
{
	return !strcmp(mnt->mnt_sb->s_type->name, "tmpfs") ||
	       !strcmp(mnt->mnt_sb->s_type->name, "devtmpfs");
}
EXPORT_SYMBOL(mnt_is_tmpfs);

static int dump_vfsmount(cpt_object_t *obj, cpt_object_t *ns_obj,
			 struct cpt_context *ctx)
{
	struct vfsmount *mnt = obj->o_obj;
	int err = 0;
	struct cpt_vfsmount_image v;
	loff_t saved_obj;
	char *path_buf, *path;
	struct path p;
	cpt_object_t *parent_obj = obj->o_parent, *bind_obj = NULL;
	int is_cgroup;

	path_buf = (char *) __get_free_page(GFP_KERNEL);
	if (!path_buf)
		return -ENOMEM;

	p.dentry = mnt->mnt_root;
	p.mnt = mnt;
	path = d_path(&p, path_buf, PAGE_SIZE);
	if (IS_ERR(path)) {
		free_page((unsigned long) path_buf);
		return PTR_ERR(path) == -EINVAL ? 0 : PTR_ERR(path);
	}

	cpt_open_object(obj, ctx);

	v.cpt_next = CPT_NULL;
	v.cpt_object = CPT_OBJ_VFSMOUNT;
	v.cpt_hdrlen = sizeof(v);
	v.cpt_content = CPT_CONTENT_ARRAY;

	v.cpt_mntflags = mnt->mnt_flags;
	v.cpt_mnt_bind = CPT_NULL;
	v.cpt_mnt_parent = parent_obj ? parent_obj->o_pos : CPT_NULL;

	v.cpt_mnt_shared = CPT_NULL;
	if ((mnt->mnt_flags & MNT_SHARED) && !list_empty(&mnt->mnt_share)) {
		struct vfsmount *m;
		cpt_object_t *shared = NULL;
		bool found = false;

		list_for_each_entry(m, &mnt->mnt_share, mnt_share) {
			shared = lookup_cpt_object(CPT_OBJ_VFSMOUNT_REF, m, ctx);
			if (!shared)
				continue;
			found = true;
			if (shared->o_pos == CPT_NULL)
				continue;
			v.cpt_mnt_shared = shared->o_pos;
			break;
		}
		if (!found) {
			eprintk_ctx("shared mount not found: %s\n", path);
			err = -ENOENT;
			goto out_err;
		}
	}

	v.cpt_mnt_master = CPT_NULL;
	if (mnt->mnt_master) {
		cpt_object_t *master;

		master = lookup_cpt_object(CPT_OBJ_VFSMOUNT_REF,
				mnt->mnt_master, ctx);
		if (!master || master->o_pos == CPT_NULL) {
			eprintk_ctx("master mount not found: %s\n", path);
			err = -ENOENT;
			goto out_err;
		}
		v.cpt_mnt_master = master->o_pos;
	}

	is_cgroup = !strcmp(mnt->mnt_sb->s_type->name, "cgroup");

	if (slab_ub(mnt) != get_exec_ub_top()) {
		v.cpt_mntflags |= CPT_MNT_EXT;
	} else if (is_ploop(mnt, ctx)) {
		v.cpt_mntflags |= CPT_MNT_PLOOP;
	} else if (cpt_need_delayfs(mnt)) {
		v.cpt_mntflags |= CPT_MNT_DELAYFS;
		obj->o_flags |= CPT_VFSMOUNT_DELAYFS;
	} else if (is_cgroup) {
		v.cpt_mnt_bind = cpt_add_cgroup(mnt, ctx);
		if (v.cpt_mnt_bind == CPT_NOINDEX) {
			err = -ENOENT;
			goto out_err;
		}
	} else {
		bind_obj = cpt_lookup_bind_source(mnt, ctx);
		if (IS_ERR(bind_obj)) {
			err = PTR_ERR(bind_obj);
			eprintk_ctx("bind mount source not found: %s\n", path);
			goto out_err;
		} else if (bind_obj) {
			v.cpt_mntflags |= CPT_MNT_BIND;
			v.cpt_mnt_bind = bind_obj->o_pos;
		} /* else non-bindmount */
	}
	v.cpt_flags = mnt->mnt_sb->s_flags;

	ctx->write(&v, sizeof(v), ctx);

	cpt_push_object(&saved_obj, ctx);
	if (!is_ploop(mnt, ctx))
		cpt_dump_string(mnt->mnt_devname ? : "none", ctx);
	else
		cpt_dump_uuid(mnt, ctx);
	cpt_dump_string(path, ctx);
	cpt_dump_string(mnt->mnt_sb->s_type->name, ctx);

	if (v.cpt_mntflags & CPT_MNT_BIND)
		err = cpt_dump_path(mnt->mnt_root, bind_obj->o_obj, 0, ctx);
	else if (!(v.cpt_mntflags & CPT_MNT_EXT) &&
		 !(v.cpt_mntflags & CPT_MNT_PLOOP)) {
		if (mnt->mnt_sb->s_type->fs_flags & FS_REQUIRES_DEV) {
			eprintk_ctx("Checkpoint supports only nodev fs: %s\n",
				    mnt->mnt_sb->s_type->name);
			err = -EXDEV;
		} else if (mnt_is_tmpfs(mnt)) {
			mntget(mnt);
			up_read(&namespace_sem);
			if (ns_obj->o_flags & CPT_NAMESPACE_MAIN)
				err = cpt_dump_tmpfs(path, mnt, ctx);
			else
				err = cpt_dump_tmpfs(".", mnt, ctx);
			down_read(&namespace_sem);
			if (!err && list_empty(&mnt->mnt_list))
				err = -EBUSY;
			mntput(mnt);
		}
	}
	if (v.cpt_mntflags & CPT_MNT_DELAYFS) {
		if (mnt->mnt_sb->s_magic == FSMAGIC_NFS) {
			dump_nfs_mount_data(mnt, ctx);
		} else if (is_autofs_mount(mnt)) {
			dump_autofs_mount_data(mnt, ctx);
		} else {
			//FIXME dump sb show_options output
			BUG();
		}
	}

	cpt_pop_object(&saved_obj, ctx);

	cpt_close_object(ctx);

out_err:
	free_page((unsigned long) path_buf);

	return err;
}

static int dump_one_namespace(cpt_object_t *obj, struct cpt_context *ctx)
{
	struct mnt_namespace *ns = obj->o_obj;
	struct cpt_object_hdr v;
	cpt_object_t *mnt_obj;
	loff_t saved_obj;
	int err = 0;

	cpt_open_object(obj, ctx);

	v.cpt_next = -1;
	v.cpt_object = CPT_OBJ_NAMESPACE;
	v.cpt_hdrlen = sizeof(v);
	v.cpt_content = CPT_CONTENT_ARRAY;

	ctx->write(&v, sizeof(v), ctx);

	cpt_push_object(&saved_obj, ctx);

	down_read(&namespace_sem);
	for_each_object(mnt_obj, CPT_OBJ_VFSMOUNT_REF) {
		struct vfsmount *mnt = mnt_obj->o_obj;

		if (!mnt->mnt_ns) {
			eprintk_ctx("detached vfsmount %s\n", mnt->mnt_devname);
			err = -ENOLINK;
			break;
		}

		if (mnt->mnt_ns != ns)
			continue;

		err = dump_vfsmount(mnt_obj, obj, ctx);
		if (err)
			break;
	}
	up_read(&namespace_sem);

	cpt_pop_object(&saved_obj, ctx);

	cpt_close_object(ctx);

	return err;
}

int cpt_dump_namespace(struct cpt_context *ctx)
{
	cpt_object_t *obj;

	cpt_open_section(ctx, CPT_SECT_NAMESPACE);

	for_each_object(obj, CPT_OBJ_NAMESPACE) {
		int err;

		if ((err = dump_one_namespace(obj, ctx)) != 0)
			return err;
	}

	cpt_close_section(ctx);
	return 0;
}

void cpt_finish_vfsmount_ref(struct cpt_context *ctx)
{
	cpt_object_t *obj;

	for_each_object(obj, CPT_OBJ_VFSMOUNT_REF)
		mntput(obj->o_obj);
}
