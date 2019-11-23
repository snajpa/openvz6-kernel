/*
 *  kernel/cpt/rst_delayfs.c
 *
 *  Copyright (C) 2009 Parallels
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 *  TODO:
 *	- handling of a case when top mount got broken
 *	- FIXMEs below
 *	- do_coredump (filp_open, do_truncate)
 *
 */

#include <linux/version.h>
#include <linux/namei.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/lockd/bind.h>
#include <linux/socket.h>
#include <linux/nfs_mount.h>
#include <linux/sched.h>
#include <linux/ve_nfs.h>
#include <linux/fs_struct.h>
#include <linux/fdtable.h>
#include <linux/pipe_fs_i.h>
#include <linux/seq_file.h>
#include <net/af_unix.h>
#include <linux/nfs4.h>

#include <linux/cpt_obj.h>
#include <linux/cpt_context.h>
#include "cpt_files.h"
#include "cpt_kernel.h"
#include "cpt_socket.h"
#include "cpt_syscalls.h"

#define DEBUG

#define D(FMT, ...)	dprintk( \
		"delayfs %d(%s) %s:%d " FMT "\n", \
		current->pid, current->comm, \
		__func__, __LINE__, ##__VA_ARGS__)

enum {
	SB_INITIAL = 0,
	SB_LOCKED,
	SB_FINISHED,
	SB_BROKEN
};

struct delayfs_file_private {
	struct delayed_flock_info *dfi;
	struct file *real_fs_file;
};

struct delay_sb_info {
	int state;
	wait_queue_head_t blocked_tasks;

	struct file_system_type *hidden_type;
	void *data;
	struct vfsmount *real;
	spinlock_t file_lock;

	struct unix_bind_info *bi_list;

	unsigned long delay_tmo;
	void (*handle_mount_failure)(struct delay_sb_info *si);
	void (*restore_mount_params)(struct delay_sb_info *si);

	/* NFS original mount options */
	int nfs_mnt_soft;
	int nfs_delay_tmo;
	int nfs_mnt_retrans;
};

#define FNAME(file) ((file)->f_dentry->d_name.name)

/* mm */

static int delay_remmap(struct vm_area_struct *vma,
		struct file* fake, struct file *real)
{
	struct address_space *mapping;

	if (vma->vm_file != fake)
		return VM_FAULT_RETRY;

	if (IS_ERR(real))
		return VM_FAULT_OOM;

	if ((vma->vm_flags & VM_DENYWRITE) && deny_write_access(real))
		return VM_FAULT_SIGBUS;

	unlink_file_vma(vma);
	vma->vm_file = real;
	if (real->f_op->mmap(real, vma)) {
		vma->vm_file = fake;
		mapping = fake->f_mapping;
		spin_lock(&mapping->i_mmap_lock);
		__vma_link_file(vma);
		spin_unlock(&mapping->i_mmap_lock);
		if (vma->vm_flags & VM_DENYWRITE)
			allow_write_access(real);

		return VM_FAULT_SIGBUS;
	}

	mapping = real->f_mapping;
	spin_lock(&mapping->i_mmap_lock);
	__vma_link_file(vma);
	vma->vm_truncate_count = mapping->truncate_count;
	spin_unlock(&mapping->i_mmap_lock);
	get_file(real);
	vma->vm_flags &= ~VM_DONTEXPAND;
	fput(fake);
	if (vma->vm_flags & VM_DENYWRITE)
		allow_write_access(real);

	return VM_FAULT_RETRY;
}

/*
 * NOTE: Called with mmap_sem held for read.
 */
static int delay_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct delay_sb_info *si;
	struct file *fake, **real;
	static DEFINE_MUTEX(lock); /* protect cross-thread remmap */
	int ret = 0;
	pgoff_t offset = vmf->pgoff;
	struct delayfs_file_private *priv;

	mutex_lock(&lock);
	if (vma->vm_ops->fault != delay_fault) {
		mutex_unlock(&lock);
		ret = VM_FAULT_RETRY;	/* race with other thread */
		goto out;
	}
	fake = vma->vm_file;
	get_file(fake);
	mutex_unlock(&lock);

	si = fake->f_dentry->d_sb->s_fs_info;
	priv = fake->private_data;
	real = &priv->real_fs_file;

	D("addr:%p mnt:%p file:%p(%s)", (void *)offset, fake->f_vfsmnt, fake, FNAME(fake));
	if (debug_level > 3)
		dump_stack();

	if (si->state == SB_INITIAL) {
		if (vma->vm_flags & VM_SHARED) {
			ret = VM_FAULT_SIGBUS;
			goto out_put;
		}
		/* special case for restoring private mappings */
		vmf->page = ZERO_PAGE(address);
		get_page(vmf->page);
		goto out_put;
	}

	if (!wait_event_timeout(si->blocked_tasks, *real, si->delay_tmo)) {
		ret = VM_FAULT_SIGBUS;
		goto out_put;
	}

	mutex_lock(&lock);
	ret = delay_remmap(vma, fake, *real);
	mutex_unlock(&lock);
out_put:
	fput(fake);
out:
	if (ret == VM_FAULT_RETRY)
		up_read(&current->mm->mmap_sem);
	return ret;
}

static struct vm_operations_struct delay_vma_ops = {
	.fault = delay_fault,
};

static int delay_mmap(struct file *file, struct vm_area_struct *vma)
{
	D("mnt:%p file:%p(%s) offset:%lu range:%p-%p", file->f_vfsmnt, file,
			FNAME(file), vma->vm_pgoff,
			(void *)vma->vm_start, (void *)vma->vm_end);
	vma->vm_ops = &delay_vma_ops;
	vma->vm_flags |= VM_DONTEXPAND;
	return 0;
}

/* switch */

static void delay_switch_mm(struct mm_struct *mm, struct super_block *sb)
{
	struct vm_area_struct *vma;
	struct file *fake, *real, *exe;
	struct delayfs_file_private *priv;

	down_write(&mm->mmap_sem);
	for ( vma = mm->mmap ; vma ; vma = vma->vm_next ) {
		fake = vma->vm_file;
		if (!fake || fake->f_vfsmnt->mnt_sb != sb)
			continue;
		priv = vma->vm_file->private_data;
		real = priv->real_fs_file;
		if (real)
			delay_remmap(vma, fake, real);
	}
	exe = mm->exe_file;
	if (exe && exe->f_vfsmnt->mnt_sb == sb) {
		priv = exe->private_data;
		real = priv->real_fs_file;
		if (real && !IS_ERR(real)) {
			get_file(real);
			fput(exe);
			mm->exe_file = real;
		}
	}
	up_write(&mm->mmap_sem);
}

struct delayed_flock_info {
	struct file_lock *fl;
	u32 svid;
	u64 lsid;
	struct delayed_flock_info *next;
};

static void delayed_flock(struct delayed_flock_info *dfi, struct file *file)
{
	int err;
	struct file_lock *fl = dfi->fl;
	u32 cpt_pid = fl->fl_pid;

	err = nlmclnt_set_lockowner(file->f_dentry->d_inode, fl, dfi->svid);
	if (err)
		goto out;

	err = nfs4_set_lockowner(file, fl, dfi->svid, dfi->lsid);
	if (err)
		goto out;

	fl->fl_file = file;
	fl->fl_flags |= FL_LOCAL;

	if (fl->fl_flags & FL_FLOCK)
		err = file->f_op->flock(file, F_SETLK, fl);
	else
		err = file->f_op->lock(file, F_SETLK, fl);

out:
	locks_free_lock(fl);
	dfi->fl = NULL;
	kfree(dfi);

	if (err)
		eprintk("oh shit :( can't lock file back in %d:%s (%d)\n",
				get_exec_env()->veid,
				file->f_dentry->d_name.name, err);
	else
		fixup_lock_pid(file->f_path.dentry->d_inode, cpt_pid, get_exec_env());
}

static void apply_delayed_locks(struct delayed_flock_info *dfi, struct file *real)
{
	while (dfi) {
		delayed_flock(dfi, real);
		dfi = dfi->next;
	}
}

static void delay_switch_fd(struct files_struct *files, struct super_block *sb)
{
	struct fdtable *fdt;
	int i;
	struct file *fake, *real;
	struct delayfs_file_private *priv;

	i = 0;
restart:
	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	for ( ; i < fdt->max_fds ; i++ ) {
		struct delayed_flock_info *dfi;

		fake = fdt->fd[i];
		if (!fake || fake->f_vfsmnt->mnt_sb != sb)
			continue;

		priv = fake->private_data;
		real = priv->real_fs_file;
		if (!real || IS_ERR(real))
			continue;

		get_file(real);
		rcu_assign_pointer(fdt->fd[i], real);

		/*
		 * Flock applying have to be done only once per file. That's
		 * why we drop the link.
		 * And file can be shared between processes, do file_lock is
		 * not enough.
		 */
		spin_lock(&fake->f_lock);
		dfi = priv->dfi;
		priv->dfi = NULL;
		spin_unlock(&fake->f_lock);
		spin_unlock(&files->file_lock);

		apply_delayed_locks(dfi, real);

		fput(fake);
		goto restart;
	}
	spin_unlock(&files->file_lock);
}

static void delay_switch_fs(struct fs_struct *fs, struct super_block *sb)
{
	struct file *filp;
	struct path old_root = { .dentry = NULL, .mnt = NULL };
	struct path old_pwd  = { .dentry = NULL, .mnt = NULL };

	spin_lock(&fs->lock);

	if (fs->root.mnt->mnt_sb == sb) {
		filp = fs->root.dentry->d_fsdata;
		if (!IS_ERR_OR_NULL(filp)) {
			old_root = fs->root;
			fs->root = filp->f_path;
			path_get(&fs->root);
		}
	}

	if (fs->pwd.mnt->mnt_sb == sb) {
		filp = fs->pwd.dentry->d_fsdata;
		if (!IS_ERR_OR_NULL(filp)) {
			old_pwd = fs->pwd;
			fs->pwd = filp->f_path;
			path_get(&fs->pwd);
		}
	}

	spin_unlock(&fs->lock);

	path_put(&old_root);
	path_put(&old_pwd);
}

static void delay_switch_current(struct super_block *sb)
{
	delay_switch_fs(current->fs, sb);
	if (current->files)
		delay_switch_fd(current->files, sb);
	if (current->mm)
		delay_switch_mm(current->mm, sb);
}

static void delay_switch_one(struct task_struct *p, struct vfsmount *mnt)
{
	struct files_struct *files;
	struct fs_struct *fs;
	struct mm_struct *mm;

	D("mnt:%p task:%d(%s)", mnt, p->pid, p->comm);
	task_lock(p);
	fs = p->fs;
	if (fs) {
		int kill;

		spin_lock(&fs->lock);
		fs->users++;
		spin_unlock(&fs->lock);
		task_unlock(p);

		delay_switch_fs(fs, mnt->mnt_sb);

		spin_lock(&fs->lock);
		kill = !--fs->users;
		spin_unlock(&fs->lock);
		if (kill)
			free_fs_struct(fs);
	} else
		task_unlock(p);

	files = get_files_struct(p);
	if (files) {
		delay_switch_fd(files, mnt->mnt_sb);
		put_files_struct(files);
	}

	mm = get_task_mm(p);
	if (mm) {
		delay_switch_mm(mm, mnt->mnt_sb);
		mmput(mm);
	}
}

static void delayfs_switch_all(struct vfsmount *mnt)
{
	struct ve_struct *env;
	struct task_struct *p;

	env = get_exec_env();

	tasklist_write_lock_irq();
	do {
		if (list_empty(&env->vetask_auxlist))
			break;

		p = list_entry(env->vetask_auxlist.prev,
				struct task_struct, ve_task_info.aux_list);
		list_del(&VE_TASK_INFO(p)->aux_list);
		list_add(&VE_TASK_INFO(p)->aux_list, &env->vetask_auxlist);

		get_task_struct(p);
		write_unlock_irq(&tasklist_lock);

		delay_switch_one(p, mnt);

		put_task_struct(p);

		cond_resched();

		tasklist_write_lock_irq();
	} while (p != __first_task_ve(env));
	write_unlock_irq(&tasklist_lock);
}

/* wait */

static int delayfs_restart(void)
{
	if (signal_pending(current))
		return -EINTR;

	set_tsk_thread_flag(current, TIF_SIGPENDING);
	return -ERESTARTSYS;
}

static int delayfs_wait_mnt(struct super_block *sb)
{
	struct delay_sb_info *si = sb->s_fs_info;
	long res;

	if (si->state == SB_INITIAL) {
		WARN_ON(1);
		return -EDEADLK;
	}

	if (si->state == SB_BROKEN)
		return -EIO;

	D("si:%p from:%p", si, __builtin_return_address(0));
	if (debug_level > 3)
		dump_stack();

	res = wait_event_interruptible_timeout(si->blocked_tasks,
						si->state >= SB_FINISHED,
						si->delay_tmo);
	if (!res)
		return -EIO;
	if (res < 0)
		return -EINTR;

	delay_switch_current(sb);

	return delayfs_restart();
}

static int delayfs_preopen(struct file *fake, struct delay_sb_info *si);

static int delayfs_wait_file(struct file *fake)
{
	struct delay_sb_info *si = fake->f_dentry->d_sb->s_fs_info;
	struct delayfs_file_private *priv = fake->private_data;
	struct file **real = &priv->real_fs_file;
	long res;

	if (si->state == SB_INITIAL) {
		WARN_ON(1);
		return -EDEADLK;
	}

	D("mnt:%p file:%p(%s) from:%p", fake->f_vfsmnt, fake, FNAME(fake),
			__builtin_return_address(0));
	if (debug_level > 3)
		dump_stack();

	if (S_ISFIFO(fake->f_dentry->d_inode->i_mode) &&
		((fake->f_mode & (FMODE_READ|FMODE_WRITE)) !=
				 (FMODE_READ|FMODE_WRITE)))
		res = wait_event_interruptible_timeout(si->blocked_tasks,
						*real, si->delay_tmo);
	else
		res = wait_event_interruptible_timeout(si->blocked_tasks,
					si->real, si->delay_tmo);
	if (!res)
		return -EIO;
	if (res < 0)
		return -EINTR;

	if (!*real) {
		if (delayfs_preopen(fake, si))
			return -EIO;
	}

	delay_switch_current(fake->f_vfsmnt->mnt_sb);

	if (IS_ERR(*real))
		return -EIO;

	return delayfs_restart();
}

/* stubs */

static int delay_permission(struct inode *inode, int mask)
{
	return delayfs_wait_mnt(inode->i_sb);
}

static int delay_getattr(struct vfsmount *mnt, struct dentry *d, struct kstat *stat)
{
	return delayfs_wait_mnt(mnt->mnt_sb);
}

#ifdef DEBUG

static int delay_create (struct inode *dir, struct dentry *dentry,
		int mode, struct nameidata *nd)
{
	WARN_ON(1);
	return -EIO;
}

static struct dentry *delay_lookup(struct inode *dir,
			struct dentry *dentry, struct nameidata *nd)
{
	WARN_ON(1);
	return ERR_PTR(-EIO);
}

static int delay_link (struct dentry *old_dentry, struct inode *dir,
		struct dentry *dentry)
{
	WARN_ON(1);
	return -EIO;
}

static int delay_unlink(struct inode *dir, struct dentry *dentry)
{
	WARN_ON(1);
	return -EIO;
}

static int delay_symlink (struct inode *dir, struct dentry *dentry,
		const char *symname)
{
	WARN_ON(1);
	return -EIO;
}

static int delay_mkdir(struct inode *dir, struct dentry *dentry,
			int mode)
{
	WARN_ON(1);
	return -EIO;
}

static int delay_rmdir (struct inode *dir, struct dentry *dentry)
{
	WARN_ON(1);
	return -EIO;
}

static int delay_mknod (struct inode *dir, struct dentry *dentry,
			int mode, dev_t rdev)
{
	WARN_ON(1);
	return -EIO;
}

static int delay_rename (struct inode *old_dir, struct dentry *old_dentry,
		struct inode *new_dir, struct dentry *new_dentry)
{
	WARN_ON(1);
	return -EIO;
}

static void delay_truncate (struct inode *inode)
{
	WARN_ON(1);
}

static int delay_setattr(struct dentry *dentry, struct iattr *attrs)
{
	WARN_ON(1);
	return -EIO;
}

static int delay_setxattr(struct dentry *dentry, const char *name,
		const void *value, size_t size, int flags)
{
	WARN_ON(1);
	return -EIO;
}

static ssize_t delay_getxattr(struct dentry *dentry, const char *name,
			void *buffer, size_t size)
{
	WARN_ON(1);
	return -EIO;
}

static ssize_t delay_listxattr(struct dentry *dentry, char *buffer,
			size_t buffer_size)
{
	WARN_ON(1);
	return -EIO;
}

static int delay_removexattr(struct dentry *dentry, const char *name)
{
	WARN_ON(1);
	return -EIO;
}

static void delay_truncate_range(struct inode *inode, loff_t start, loff_t stop)
{
	WARN_ON(1);
}

#endif /* DEBUG */

static struct inode_operations delay_dir_iops = {
	/*
	 * It's a hack - all the lookup happens with the
	 * permission checks, thus we can safely freeeze
	 * the tasks in this call
	 */
	.permission = delay_permission,
	.getattr = delay_getattr,
#ifdef DEBUG
	.create		= delay_create,
	.lookup		= delay_lookup,
	.link		= delay_link,
	.unlink		= delay_unlink,
	.symlink	= delay_symlink,
	.mkdir		= delay_mkdir,
	.rmdir		= delay_rmdir,
	.mknod		= delay_mknod,
	.rename		= delay_rename,
	/* .readlink	- EINVAL on root and sleep on permitions */
	/* .follow_link	- must be no-op
	   .put_link	*/
	.truncate	= delay_truncate,
	.setattr	= delay_setattr,
	.setxattr	= delay_setxattr,
	.getxattr	= delay_getxattr,
	.listxattr	= delay_listxattr,
	.removexattr	= delay_removexattr,
	.truncate_range = delay_truncate_range, /* exists only in shm */
#endif /* DEBUG */
};

static long delay_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	return delayfs_wait_file(filp);
}

static loff_t delay_llseek(struct file *filp, loff_t offset, int origin)
{
	return delayfs_wait_file(filp);
}

static ssize_t delay_read(struct file *filp, char __user *buf,
			size_t size, loff_t *ppos)
{
	return delayfs_wait_file(filp);
}

static ssize_t delay_write(struct file *filp, const char __user *buf,
			size_t siz, loff_t *ppos)
{
	return delayfs_wait_file(filp);
}

static int delay_readdir(struct file *filp, void *dirent, filldir_t filldir)
{
	return delayfs_wait_file(filp);
}

static int delay_fsync(struct file *filp, struct dentry *dentry,
			int datasync)
{
	// nothing to sync and there no reason to block
	return 0;
}

static int delay_lock(struct file *filp, int cmd, struct file_lock *fl)
{
	return delayfs_wait_file(filp);
}

/* see do_sendfile, generic_file_sendfile and file_send_actor*/
static ssize_t delay_sendpage(struct file *filp, struct page *page,
			int off, size_t len, loff_t *pos, int more)
{
	return delayfs_wait_file(filp);
}

static int delay_flock(struct file *filp, int cmd, struct file_lock *fl)
{
	return delayfs_wait_file(filp);
}

static ssize_t delay_splice_write(struct pipe_inode_info *pipe,
			struct file *filp, loff_t *ppos, size_t len,
			unsigned int flags)
{
	return delayfs_wait_file(filp);
}

static ssize_t delay_splice_read(struct file *filp, loff_t *ppos,
			struct pipe_inode_info *pipe, size_t len,
			unsigned int flags)
{
	return delayfs_wait_file(filp);
}

static int delay_release(struct inode *ino, struct file *f)
{
	struct delayed_flock_info *dfi;
	struct delayfs_file_private *priv;

	priv = f->private_data;

	while (priv->dfi) {
		dfi = priv->dfi;
		priv->dfi = dfi->next;

		if (dfi->fl)
			locks_free_lock(dfi->fl);
		kfree(dfi);
	}

	if (!IS_ERR_OR_NULL(priv->real_fs_file))
		fput(priv->real_fs_file);

	if (S_ISFIFO(ino->i_mode))
		pipe_release(ino, (f->f_mode & FMODE_READ) != 0,
				  (f->f_mode & FMODE_WRITE)!= 0);
	kfree(f->private_data);

	return 0;
}

static int delay_open(struct inode *inode, struct file *file)
{
	file->private_data = kzalloc(sizeof(struct delayfs_file_private), GFP_KERNEL);
	if (!file->private_data)
		return -ENOMEM;

	if (S_ISFIFO(inode->i_mode)) {
		mutex_lock(&inode->i_mutex);
		if (!inode->i_pipe) {
			inode->i_pipe = alloc_pipe_info(inode);
			if (!inode->i_pipe) {
				mutex_unlock(&inode->i_mutex);
				kfree(file->private_data);
				eprintk("%s: failed to allocate pipe buffer\n", __func__);
				return -ENOMEM;
			}
			inode->i_private = (void *)1; /* need pipe data swap */
		}
		inode->i_pipe->readers += ((file->f_mode & FMODE_READ) != 0);
		inode->i_pipe->writers += ((file->f_mode & FMODE_WRITE) != 0);
		mutex_unlock(&inode->i_mutex);
	}
	return 0;
}

static struct file_operations delay_dir_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl = delay_ioctl,
	.compat_ioctl	= delay_ioctl,
	.mmap = delay_mmap,
	.open		= delay_open,
	.release	= delay_release,
	.llseek		= delay_llseek,
	.read		= delay_read,
	.write		= delay_write,
	.readdir	= delay_readdir,
	/* .poll	- not required. by default return DEFAULT_POLLMASK */
	/* .flush	- not required */
	.fsync		= delay_fsync, /* non-blocked */
	/* .fasync	- not required */
	.lock		= delay_lock,
	.sendpage	= delay_sendpage,
	/* .get_unmapped_area - not required. for NOMMU only? */
	/* .check_flags		FIXME problem with O_NOATIME O_DIRECT in setfl */
	.flock		= delay_flock,
	.splice_write	= delay_splice_write,
	.splice_read	= delay_splice_read,
	/* .aio_read	- aio banned. sys_io_submit return -EINVAL
	   .aio_write
	   .aio_fsync	*/
};

static void delayfs_release_dentry(struct dentry *dentry)
{
	struct file *real = dentry->d_fsdata;

	D("de:%p name:%s real:%p", dentry, dentry->d_name.name, real);
	if (real && !IS_ERR(real))
		fput(real);
}

struct dentry_operations delay_dir_dops = {
       .d_release = delayfs_release_dentry,
};

static void delayfs_show_type(struct seq_file *seq, struct super_block *sb)
{
	struct delay_sb_info *si = sb->s_fs_info;

	seq_escape(seq, si->hidden_type->name, " \t\n\\");
}

static struct super_operations delay_super_ops = {
	.show_type = delayfs_show_type,
};

static int delay_fill_sb(struct super_block *sb, void *data, int silent)
{
	struct inode *rinode;
	struct delay_sb_info *si;

	si = kzalloc(sizeof(struct delay_sb_info), GFP_KERNEL);
	if (!si)
		goto err;

	init_waitqueue_head(&si->blocked_tasks);
	spin_lock_init(&si->file_lock);

	sb->s_fs_info = si;
	sb->s_op = &delay_super_ops;

	rinode = new_inode(sb);
	if (!rinode)
		goto err_free;

	rinode->i_ino = 1;
	rinode->i_mtime = rinode->i_atime = rinode->i_ctime = CURRENT_TIME;
	rinode->i_blocks = 0;
	rinode->i_uid = rinode->i_gid = 0;
	rinode->i_mode = S_IFDIR | S_IRUGO | S_IXUGO | S_IWUSR;
	rinode->i_op = &delay_dir_iops;
	rinode->i_fop = &delay_dir_fops;
	rinode->i_nlink = 2;

	sb->s_root = d_alloc_root(rinode);
	if (!sb->s_root)
		goto err_iput;

	D("sb:%p si:%p ino:%p root:%p", sb, si, rinode, sb->s_root);
	return 0;

err_iput:
	iput(rinode);
err_free:
	kfree(si);
err:
	return -ENOMEM;
}

static int delay_get_sb(struct file_system_type *type, int flags,
		const char *dev_name, void *data, struct vfsmount *mnt)
{
	D();
	return get_sb_nodev(type, flags|MS_NOUSER, data, delay_fill_sb, mnt);
}

static void delay_kill_sb(struct super_block *s)
{
	struct delay_sb_info *si = s->s_fs_info;

	D("si:%p", si);
	BUG_ON(waitqueue_active(&si->blocked_tasks));

	while (si->bi_list) {
		struct unix_bind_info *i;

		i = si->bi_list;
		si->bi_list = i->next;

		sock_put(i->sk);
		kfree(i);
	}

	mntput(si->real);
	if (si->hidden_type)
		put_filesystem(si->hidden_type);
	free_pages((unsigned long )si->data, 1);
	kfree(si);
	kill_anon_super(s);
}

struct file_system_type delayfs_type = {
	.owner		= THIS_MODULE,
	.name		= "delayfs",
	.get_sb		= delay_get_sb,
	.kill_sb	= delay_kill_sb,
	.fs_flags	= FS_VIRTUALIZED,
};

static int create_delayed_context(cpt_context_t *ctx)
{
	int i;
	struct cpt_delayed_context *dctx;

	if (ctx->dctx != NULL)
		return 0;

	dctx = kzalloc(sizeof(*dctx), GFP_KERNEL);
	if (dctx == NULL)
		return -ENOMEM;

	for (i = 0; i < CPT_DOBJ_MAX; i++)
		INIT_LIST_HEAD(&dctx->object_array[i]);
	dctx->ve_id = ctx->ve_id;

	ctx->dctx = dctx;
	return 0;
}

#define DELAYFS_INITIAL_RETRY_TIMEOUT (16 * HZ)
static int delay_max_timeout = 120 * HZ; 

static void delayfs_nfs_handle_mount_failure(struct delay_sb_info *si)
{
	struct nfs_mount_data_dump *mount_data = si->data;

	if (si->delay_tmo < delay_max_timeout)
		si->delay_tmo <<= 1;

	if (mount_data->version == NFS_MOUNT_MIGRATED) {
		if (mount_data->timeo < delay_max_timeout)
			mount_data->timeo <<= 1;
	} else {
		struct nfs_mount_data *old_data = si->data;

		if (old_data->timeo < delay_max_timeout)
			old_data->timeo <<= 1;
	}
}

static void delayfs_nfs_restore_mount_params(struct delay_sb_info *si)
{
	nfs_change_server_params(si->real->mnt_sb->s_fs_info,
				 si->nfs_delay_tmo, si->nfs_mnt_retrans);
}

static void delayfs_prepare_for_remount_loop(struct delay_sb_info *si)
{
	if (!strcmp(si->hidden_type->name, "nfs")) {
		struct nfs_mount_data_dump *mount_data = si->data;

		if (mount_data->version == NFS_MOUNT_MIGRATED) {
			/*
			 * Save real NFS mount parameters for further replacement.
			 */
			si->nfs_mnt_soft = mount_data->flags & NFS_MOUNT_SOFT;
			si->nfs_delay_tmo = mount_data->timeo;
			si->nfs_mnt_retrans = mount_data->retrans;
			/*
			 * Hack NFS mount options to avoid hanging during remount.
			 */

			mount_data->timeo = 1;
			mount_data->retrans = 1;
		} else {
			struct nfs_mount_data *old_data = si->data;

			/*
			 * Save real NFS mount parameters for further replacement.
			 */
			si->nfs_delay_tmo = old_data->timeo;
			si->nfs_mnt_retrans = old_data->retrans;
			/*
			 * Hack NFS mount options to avoid hanging during remount.
			 */

			old_data->timeo = 1;
			old_data->retrans = 1;
		}
		/*
		 * Set DFS parameters used during remount procedure.
		 */
		si->delay_tmo = (si->nfs_mnt_soft ?
				(si->nfs_delay_tmo * si->nfs_mnt_retrans * HZ) :
				MAX_SCHEDULE_TIMEOUT);
		si->handle_mount_failure = delayfs_nfs_handle_mount_failure;
		si->restore_mount_params = delayfs_nfs_restore_mount_params;
	} else {
		si->delay_tmo = MAX_SCHEDULE_TIMEOUT;
		si->handle_mount_failure = NULL;
		si->restore_mount_params = NULL;
	}
}

static void *check_fs_supported(char *type, void *data)
{
	struct file_system_type *fs;

	fs = get_fs_type(type);
	if (!fs) {
		eprintk("DelayFS: unknown file system type '%s'\n", type);
		return ERR_PTR(-EINVAL);
	}

	if (!strcmp(fs->name, "nfs4") && !nfs_enable_v4_in_ct) {
		eprintk("DelayFS: Can't restore mount: NFSv4 is disabled.\n");
		put_filesystem(fs);
		return ERR_PTR(-ENODEV);
	}
	return fs;
}

/* first stage */

struct vfsmount *rst_mount_delayfs(char *type, int flags,
		char *name, void *data, cpt_context_t *ctx)
{
	struct vfsmount *mnt;
	struct delay_sb_info *si;
	int err;
	void *fs;

	fs = check_fs_supported(type, data);
	if (IS_ERR(fs))
		return fs;

	err = create_delayed_context(ctx);
	if (err)
		goto out;

	mnt = vfs_kern_mount(&delayfs_type, flags, name, NULL);
	err = PTR_ERR(mnt);
	if (IS_ERR(mnt))
		goto out;

	mnt->mnt_sb->s_flags &= ~MS_NOUSER;
	si = mnt->mnt_sb->s_fs_info;

	err = -ENOMEM;
	/*
	 * We need more than one page since NFS4 mount data is huge...
	 */
	si->data = (void *) __get_free_pages(GFP_KERNEL, 1);
	if (!si->data)
		goto out_put;
	memcpy(si->data, data, PAGE_SIZE << 1);

	si->hidden_type = fs;

	delayfs_prepare_for_remount_loop(si);

	return mnt;

out_put:
	kern_umount(mnt);
out:
	put_filesystem(fs);
	return ERR_PTR(err);
}

struct file *rst_delayfs_screw(struct vfsmount *mnt,
		char *name, int flags, loff_t offset, unsigned int mode)
{
	struct dentry *dentry;
	struct inode *inode = NULL;
	struct file *filp;
	int err;

	err = -EFAULT;
	if (mnt->mnt_sb->s_type != &delayfs_type)
		goto out;

	err = -ENOMEM;
	inode = new_inode(mnt->mnt_sb);
	if (!inode)
		goto out;
	inode->i_op = &delay_dir_iops;
	inode->i_fop = &delay_dir_fops;
	inode->i_mode = mode & S_IFMT;

	dentry = d_alloc_name(mnt->mnt_root, name);
	err = -ENOMEM;
	if (!dentry)
		goto out;

	dentry->d_op = &delay_dir_dops;
	d_instantiate(dentry, inode);
	inode = NULL;

	mntget(mnt);
	filp = dentry_open(dentry, mnt, flags, current_cred());
	err = PTR_ERR(filp);
	if (IS_ERR(filp))
		goto out;

	filp->f_pos = offset;
	filp->f_heavy = 1;

	D("mnt:%p file:%p de:%p ino:%p name:%s flags:%x offset:%lld",
			mnt, filp, dentry, dentry->d_inode, name, flags, offset);
	return filp;

out:
	D("mnt:%p name:%s flags:%x err:%d", mnt, name, flags, err);
	iput(inode);
	return ERR_PTR(err);
}

int mknod_by_mntref(const char __user *filename, int mode,
				unsigned dev, struct vfsmount *mnt)
{
	struct dentry * dentry;
	struct nameidata nd;
	int error = 0;

	if (S_ISDIR(mode))
		return -EPERM;

	error = rst_path_lookup_at(mnt,  mnt->mnt_root, filename, LOOKUP_PARENT |
			LOOKUP_DIVE, &nd);
	if (error)
		return error;

	dentry = lookup_create(&nd, 0);
	error = PTR_ERR(dentry);
	
	if (!IS_POSIXACL(nd.path.dentry->d_inode))
		mode &= ~current->fs->umask;
	if (!IS_ERR(dentry)) {
		switch (mode & S_IFMT) {
		case 0: case S_IFREG:
			error = vfs_create(nd.path.dentry->d_inode,dentry,mode,&nd);
			break;
		case S_IFCHR: case S_IFBLK:
			error = vfs_mknod(nd.path.dentry->d_inode,dentry,mode,
					new_decode_dev(dev));
			break;
		case S_IFIFO: case S_IFSOCK:
			error = vfs_mknod(nd.path.dentry->d_inode,dentry,mode,0);
			break;
		case S_IFDIR:
			error = -EPERM;
			break;
		default:
			error = -EINVAL;
		}
		dput(dentry);
	}
	mutex_unlock(&nd.path.dentry->d_inode->i_mutex);
	path_put(&nd.path);

	return error;

}

/* second stage */
int rebind_unix_socket(struct vfsmount *rmnt, struct unix_bind_info *bi,
	       		int flags)
{
	int err;
	struct nameidata nd;
	char *name = ((char *)bi->path) + bi->path_off;

	if (rst_path_lookup_at(rmnt,  rmnt->mnt_root, name, flags, &nd) < 0) {
		err = mknod_by_mntref(name, S_IFSOCK | (bi->i_mode & S_IALLUGO),
			       		0, rmnt);
		if (err) {
			printk("%s: mknod [%s] err %d\n", __func__, name, err);
			return err;
		}

		err = rst_path_lookup_at(rmnt,  rmnt->mnt_root, name, flags, &nd);
		if (err < 0) {
			printk("%s: lookup [%s] err %d\n", __func__, name, err);
			return err;
		}

		if (bi->uid != -1 && bi->gid != -1)
			sc_chown(bi->path, bi->uid, bi->gid);
	}

	if (!S_ISSOCK(nd.path.dentry->d_inode->i_mode)) {
		printk("%s: not a socket dentry %s\n", __func__, name);
		path_put(&nd.path);
		return -EINVAL;
	}

	err = unix_bind_path(bi->sk, nd.path.dentry, nd.path.mnt);
	if (err < 0)
		printk("%s: bind-path [%s] err %d\n", __func__, name, err);

	return err;
}

static void rebind_unix_sockets(struct vfsmount *rmnt,
		struct delay_sb_info *si)
{
	struct unix_bind_info *bi;

	while ((bi = si->bi_list) != NULL) {
		si->bi_list = bi->next;

		rebind_unix_socket(rmnt, bi, 0);

		sock_put(bi->sk);
		kfree(bi);
	}
}

static int rst_remount_delayfs(struct vfsmount *mnt)
{
	struct delay_sb_info *si = mnt->mnt_sb->s_fs_info;
	struct vfsmount *real_mnt;

	if (si->real)
		return -EBUSY;

	real_mnt = vfs_kern_mount(si->hidden_type, mnt->mnt_sb->s_flags | MS_CPTMOUNT,
			mnt->mnt_devname, si->data);

	if (IS_ERR(real_mnt))
		return PTR_ERR(real_mnt);

	D("fake: %p(%s)", mnt, mnt->mnt_sb->s_type->name);
	D("real: %p(%s)", real_mnt, real_mnt->mnt_sb->s_type->name);
	D("prnt: %p(%s)", mnt->mnt_parent, mnt->mnt_parent->mnt_sb->s_type->name);

	si->real = mntget(real_mnt);
	real_mnt->mnt_flags = mnt->mnt_flags & MNT_BEHAVIOR_FLAGS;

	replace_mount(real_mnt, mnt);

	rebind_unix_sockets(real_mnt, si);

	return 0;
}

static int make_flags(struct file *filp)
{
	int flags = O_NOFOLLOW|O_NONBLOCK|O_NOCTTY;

	switch (filp->f_mode &(FMODE_READ|FMODE_WRITE)) {
		case FMODE_READ|FMODE_WRITE:
			flags |= O_RDWR; break;
		case FMODE_WRITE:
			flags |= O_WRONLY; break;
		case FMODE_READ:
			flags |= O_RDONLY; break;
		default: break;
	}
	flags |= filp->f_flags & ~(O_ACCMODE|O_CREAT|O_TRUNC|O_EXCL|FASYNC);
	return flags;
}

static int delayfs_lookup_file(const unsigned char *fname, int open_flags,
			       int special_flags,
			       struct nameidata *nd,
			       struct vfsmount *mnt)
{
	struct file *real;
	int flag = open_to_namei_flags(open_flags);
	int err;

	real = get_empty_filp();
	if (real == NULL)
		return -ENFILE;

	real->f_flags = open_flags;

	nd->intent.open.file = real;
	nd->intent.open.flags = flag;
	nd->intent.open.create_mode = 0;

	err = rst_path_lookup_at(mnt, mnt->mnt_root, fname,
				 lookup_flags(flag) | special_flags, nd);
	if (IS_ERR(nd->intent.open.file)) {
		if (err == 0) {
			err = PTR_ERR(nd->intent.open.file);
			path_put(&nd->path);
		}
	} else if (err)
		release_open_intent(nd);
	return err;
}

static struct file *delayfs_open_real_pipe(struct file *fake,
					   int open_flag,
					   struct vfsmount *mnt,
					   struct nameidata *nd)
{
	struct file *real;
	int err;

	if (fake->f_mode & FMODE_READ) {
		err = delayfs_lookup_file(FNAME(fake), open_flag, 0, nd, mnt);
		if (err)
			return ERR_PTR(err);
		nd->intent.open.file->f_flags |= O_NONBLOCK;
		real = nameidata_to_filp(nd);
	} else {
		struct file *tmp;
		struct nameidata tmp_nd;

		err = delayfs_lookup_file(FNAME(fake), O_RDWR|O_NONBLOCK, 0,
					  &tmp_nd, mnt);
		if (err)
			return ERR_PTR(err);

		tmp_nd.intent.open.file->f_flags |= O_NONBLOCK;
		tmp = nameidata_to_filp(&tmp_nd);
		if (IS_ERR(tmp))
			return tmp;

                real = dentry_open(dget(tmp->f_dentry), mntget(tmp->f_vfsmnt), open_flag, current_cred());
                fput(tmp);
	}

	if (!IS_ERR(real)) {
		int need_pipe_swap;
		struct inode *inode = fake->f_dentry->d_inode;

		mutex_lock(&inode->i_mutex);
		need_pipe_swap = (long)inode->i_private;
		inode->i_private = (void *)0;
		mutex_unlock(&inode->i_mutex);

		if (need_pipe_swap)
			swap_pipe_info(real->f_dentry->d_inode,
					fake->f_dentry->d_inode);
	}

	return real;
}

static struct file *delayfs_open_real_file(struct file *fake,
					   struct vfsmount *mnt)
{
	struct nameidata nd;
	int err;
	int open_flags = make_flags(fake);
	int lookup_flags = 0;

	D("fake:%p(%s) flags:%d pos:%lld real_mnt:%p",
			fake, FNAME(fake), open_flags,
			(long long)fake->f_pos, mnt);

	switch (fake->f_dentry->d_inode->i_mode & S_IFMT) {
		case S_IFIFO:
			return delayfs_open_real_pipe(fake, open_flags,
						      mnt, &nd);
		case S_IFREG:
		case S_IFDIR:
			lookup_flags = LOOKUP_OPEN;
		default:
			err = delayfs_lookup_file(FNAME(fake), open_flags,
						  lookup_flags, &nd, mnt);
			break;
	}
	if (err)
		return ERR_PTR(err);
	return nameidata_to_filp(&nd);
}

static int delayfs_preopen(struct file *fake, struct delay_sb_info *si)
{
	struct file *real;
	int err;
	struct delayfs_file_private *priv = fake->private_data;

	real = delayfs_open_real_file(fake, si->real);
	BUG_ON(real == NULL);
	err = PTR_ERR(real);
	if (IS_ERR(real))
		goto out;

	D("real:%p mnt:%p de:%p ino:%p", real, real->f_vfsmnt, real->f_dentry,
			real->f_dentry->d_inode);

	real->f_flags = fake->f_flags;
	if (fake->f_pos != real->f_pos) {
		loff_t off;

		off = vfs_llseek(real, fake->f_pos, 0);
		if (off < 0) {
			eprintk("%s llseek:%d\n", __func__, (int)off);
			real->f_pos = fake->f_pos;
		}
	}

	spin_lock(&si->file_lock);
	if (!priv->real_fs_file) {
		priv->real_fs_file = real;
		/* We need this assigment for restoring fs root and pwd */
		if (fake->f_dentry->d_fsdata == NULL) {
			fake->f_dentry->d_fsdata = real;
			get_file(real);
		} else if (!IS_ERR(fake->f_dentry->d_fsdata))
			WARN_ON(real->f_dentry !=
				((struct file *)fake->f_dentry->d_fsdata)->f_dentry);
		real = NULL;
	}
	spin_unlock(&si->file_lock);

	if (real)
		fput(real);

	err = 0;
out:
	D("file:%p(%s) err:%d", fake, fake->f_dentry->d_name.name, err);

	return err;
}

static void delayfs_break(struct file *fake)
{
	struct delayfs_file_private *priv = fake->private_data;
	struct delay_sb_info *si = fake->f_vfsmnt->mnt_sb->s_fs_info;

	spin_lock(&si->file_lock);
	if (priv->real_fs_file == NULL) {
		priv->real_fs_file = ERR_PTR(-EIO);
		fake->f_dentry->d_fsdata = ERR_PTR(-EIO);
	}
	spin_unlock(&si->file_lock);
}

static int delayfs_sillyrename(struct file *fake);

static void delay_break_all(struct cpt_delayed_context *ctx)
{
	cpt_object_t *obj;
	struct file *file;
	struct vfsmount *mnt;
	struct delay_sb_info *si;
	struct delayfs_file_private *priv;

	for_each_object(obj, CPT_DOBJ_FILE) {
		file = obj->o_obj;
		priv = file->private_data;
		if (priv->real_fs_file == NULL)
			delayfs_break(file);
		else if (obj->o_flags & CPT_FILE_SILLYRENAME)
			delayfs_sillyrename(file);
	}

	for_each_object(obj, CPT_DOBJ_VFSMOUNT_REF) {
		mnt = obj->o_obj;

		si = mnt->mnt_sb->s_fs_info;
		si->state = SB_BROKEN;
		wake_up_all(&si->blocked_tasks);
	}
}

static void dctx_release_objects(struct cpt_delayed_context *ctx)
{
	cpt_object_t *obj, *nobj;

	for_each_object_safe(obj, nobj, CPT_DOBJ_VFSMOUNT_REF) {
		list_del(&obj->o_list);
		mntput(obj->o_obj);
		kfree(obj->o_image);
		kfree(obj);
	}

	synchronize_rcu(); /* wait till fget_light gets the reference */

	for_each_object_safe(obj, nobj, CPT_DOBJ_FILE) {
		list_del(&obj->o_list);
		fput(obj->o_obj);
		kfree(obj->o_image);
		kfree(obj);
	}
}

void destroy_delayed_context(struct cpt_delayed_context *dctx)
{
	delay_break_all(dctx);
	dctx_release_objects(dctx);
	kfree(dctx);
}

static int delayfs_sillyrename(struct file *fake)
{
	struct delayfs_file_private *priv = fake->private_data;
	struct file *real = priv->real_fs_file;
	int err;

	if (!real || IS_ERR(real))
		return -ENODEV;

	dget(real->f_dentry); /* see nfs_unlink */
	mutex_lock_nested(&real->f_dentry->d_parent->d_inode->i_mutex, I_MUTEX_PARENT);
	err = vfs_unlink(real->f_dentry->d_parent->d_inode, real->f_dentry);
	mutex_unlock(&real->f_dentry->d_parent->d_inode->i_mutex);
	dput(real->f_dentry);

	D("file:%p(%s) ret:%d", fake, fake->f_dentry->d_name.name, err);
	return err;
}

/* wire */

int rst_freeze_delayfs(cpt_context_t *ctx)
{
	cpt_object_t *obj, *nobj;
	struct vfsmount *mnt;
	struct delay_sb_info *si;
	/* dctx must be not NULL if any delayed object exists */
	struct cpt_delayed_context *dctx = ctx->dctx;

	for_each_object_safe(obj, nobj, CPT_OBJ_VFSMOUNT_REF) {
		if (!(obj->o_flags & CPT_VFSMOUNT_DELAYFS))
			continue;

		list_move(&obj->o_list,
				&dctx->object_array[CPT_DOBJ_VFSMOUNT_REF]);
		ctx->objcount--;
		mnt = obj->o_obj;
		si = mnt->mnt_sb->s_fs_info;
		si->state = SB_LOCKED;
	}

	for_each_object_safe(obj, nobj, CPT_OBJ_FILE)
		if (obj->o_flags & CPT_FILE_DELAYFS) {
			list_move(&obj->o_list,
					&dctx->object_array[CPT_DOBJ_FILE]);
			ctx->objcount--;
		}
	return 0;
}

static void delayfs_resume(struct cpt_delayed_context *ctx,
		struct list_head *broken_mounts)
{
	int ret;
	struct delay_sb_info *si;
	cpt_object_t *obj, *nobj;
	struct vfsmount *mnt;
	struct file *file;
	struct delayfs_file_private *priv;

	/* mount */
	for_each_object_safe(obj, nobj, CPT_DOBJ_VFSMOUNT_REF) {
		BUG_ON(!(obj->o_flags & CPT_VFSMOUNT_DELAYFS));

		mnt = obj->o_obj;
		si = mnt->mnt_sb->s_fs_info;
		ret = rst_remount_delayfs(mnt);
		if (ret) {
			if (si->handle_mount_failure)
				si->handle_mount_failure(si);
			list_move(&obj->o_list, broken_mounts);
		}
	}

	/* restore mount parameters */
	for_each_object(obj, CPT_DOBJ_VFSMOUNT_REF) {
		mnt = obj->o_obj;
		si = mnt->mnt_sb->s_fs_info;
		if (si->restore_mount_params)
			si->restore_mount_params(si);
		wake_up_all(&si->blocked_tasks);
	}

	/* preopen */
	for_each_object(obj, CPT_DOBJ_FILE) {
		BUG_ON(!(obj->o_flags & CPT_FILE_DELAYFS));

		file = obj->o_obj;
		si = file->f_vfsmnt->mnt_sb->s_fs_info;
		/* mount is broken or already reopened */
		priv = file->private_data;
		if (!si->real || priv->real_fs_file != NULL)
			continue;

		ret = delayfs_preopen(file, si);
		if (ret) {
			printk("%s: preopen %s err %d\n", __func__,
					FNAME(file), ret);
			delayfs_break(file);
		}
	}

	/* wakeup */
	for_each_object(obj, CPT_DOBJ_VFSMOUNT_REF) {
		mnt = obj->o_obj;

		D("wakeup %p", mnt);

		si = mnt->mnt_sb->s_fs_info;
		si->state = SB_FINISHED;
		wake_up_all(&si->blocked_tasks);
	}

	/**
	 * all files preopened or broken -- now noone block mmap_sem write lock
	 */

	/* switch */
	for_each_object(obj, CPT_DOBJ_VFSMOUNT_REF) {
		mnt = obj->o_obj;
		delayfs_switch_all(mnt);
	}
}

static int delay_first_timeout = 1 * HZ;

struct ctl_table delayfs_table[] = {
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "first_timeout",
		.data		= &delay_first_timeout,
		.maxlen		= sizeof(delay_first_timeout),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "max_timeout",
		.data		= &delay_max_timeout,
		.maxlen		= sizeof(delay_max_timeout),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{ .ctl_name = 0 }
};

static int delayfs_resume_fn(void *d)
{
	struct cpt_delayed_context *dctx = d;
	int retry_timeout = DELAYFS_INITIAL_RETRY_TIMEOUT;
	unsigned long abort_timeout;
	LIST_HEAD(broken_mounts);
	LIST_HEAD(live_mounts);
	int ve_id = -1;

	dctx->dfs_daemon = current;

	abort_timeout = jiffies + (unsigned long)300 * HZ;

	daemonize("dfs_resume/%d", dctx->ve_id);
	ve_printk(VE_LOG_BOTH, "DFS%d: resuming daemon started\n", dctx->ve_id);

	allow_signal(SIGKILL);

	__set_current_state(TASK_UNINTERRUPTIBLE);
	complete(&dctx->dfs_notify);
	/* Waiting for delayed context to be filled by resume process */
	schedule();

	schedule_timeout_interruptible(delay_first_timeout);

try_again:
	if (signal_pending(current)) {
		ve_printk(VE_LOG_BOTH, "DFS%d: Got kill signal\n", dctx->ve_id);
		goto out_splice;
	}

	if (abort_timeout && time_after(jiffies, abort_timeout)) {
		ve_printk(VE_LOG_BOTH, "DFS%d: Timed out\n", dctx->ve_id);
		goto out_splice;
	}

	delayfs_resume(dctx, &broken_mounts);

	list_splice_init(&dctx->object_array[CPT_DOBJ_VFSMOUNT_REF],
			&live_mounts);

	if (!list_empty(&broken_mounts)) {
		list_splice_init(&broken_mounts,
				&dctx->object_array[CPT_DOBJ_VFSMOUNT_REF]);

		ve_printk(VE_LOG_BOTH, "DFS%d: Retrying delayed mount in %d seconds\n",
					dctx->ve_id, retry_timeout / HZ);
		schedule_timeout_interruptible(retry_timeout);
		if (retry_timeout < delay_max_timeout)
			retry_timeout <<= 1;

		goto try_again;
	}
	ve_id = dctx->ve_id;
out_splice:
	list_splice(&live_mounts, &dctx->object_array[CPT_DOBJ_VFSMOUNT_REF]);
	destroy_delayed_context(dctx);
	if (ve_id >= 0)
		ve_printk(VE_LOG_BOTH, "DFS%d: Delayed mounts successfully resumed\n",
					ve_id);
	module_put_and_exit(0);
}

int rst_init_delayfs_daemon(cpt_context_t *ctx)
{
	int pid;
	struct cpt_delayed_context *dctx = ctx->dctx;

	if (dctx == NULL)
		return 0;

	__module_get(THIS_MODULE);

	init_completion(&dctx->dfs_notify);

	pid = kernel_thread(delayfs_resume_fn, dctx,
			CLONE_FS | CLONE_FILES | CLONE_VM | SIGCHLD);
	if (pid < 0) {
		eprintk_ctx("%d: Failed to start delayfs daemon (err: %d)\n",
				dctx->ve_id, pid);
		destroy_delayed_context(dctx);
		ctx->dctx = NULL;
		module_put(THIS_MODULE);
		return pid;
	}

	wait_for_completion(&dctx->dfs_notify);

	return 0;
}

int rst_delay_flock(struct file *f, struct cpt_flock_image *fli,
		cpt_context_t *ctx)
{
	int err;
	struct delayed_flock_info *dfi;
	struct file_lock *fl;
	struct delayfs_file_private *priv;

	err = -EINVAL;
	if (!cpt_object_has(fli, cpt_svid) ||
			fli->cpt_svid == CPT_NOINDEX) {
		eprintk_ctx("No SVID for flock\n");
		goto out;
	}

	err = -ENOMEM;
	dfi = kmalloc(sizeof(*dfi), GFP_KERNEL);
	if (dfi == NULL)
		goto out;

	if (!cpt_object_has(fli, cpt_lsid))
		fli->cpt_lsid = 0;

	err = -ENOMEM;
	fl = locks_alloc_lock(1);
	if (fl == NULL)
		goto out1;

	if (fli->cpt_flags & FL_FLOCK) {
		fl->fl_flags = FL_FLOCK;
		fl->fl_start = 0;
		fl->fl_end = OFFSET_MAX;
		fl->fl_pid = fli->cpt_pid;
		fl->fl_type = fli->cpt_type;
	} else {
		cpt_object_t *obj;

		fl->fl_flags = fli->cpt_flags & ~FL_SLEEP;
		fl->fl_end = fli->cpt_end;
		fl->fl_start = fli->cpt_start;
		fl->fl_type = fli->cpt_type;

		err = -EINVAL;
		obj = lookup_cpt_obj_byindex(CPT_OBJ_FILES,
				fli->cpt_owner, ctx);
		if (!obj) {
			eprintk_ctx("unknown lock owner %d\n",
					(int)fli->cpt_owner);
			goto out2;
		}
		fl->fl_owner = obj->o_obj;
		if (fl->fl_owner == NULL)
			eprintk_ctx("no lock owner\n");

		fl->fl_pid = fli->cpt_pid;
	}

	priv = f->private_data;

	dfi->fl = fl;
	dfi->svid = fli->cpt_svid;
	dfi->lsid = fli->cpt_lsid;
	dfi->next = priv->dfi;

	priv->dfi = dfi;
	return 0;

out2:
	locks_free_lock(fl);
out1:
	kfree(dfi);
out:
	return err;
}

void rst_put_delayed_sockets(cpt_context_t *ctx)
{
	cpt_object_t *obj;

	for_each_object(obj, CPT_OBJ_VFSMOUNT_REF) {
		struct vfsmount *mnt = obj->o_obj;
		struct delay_sb_info *si;

		if (mnt->mnt_sb->s_op != &delay_super_ops)
			continue;

		si = mnt->mnt_sb->s_fs_info;
		while (si->bi_list) {
			struct unix_bind_info *i;

			i = si->bi_list;
			si->bi_list = i->next;

			sock_put(i->sk);
		}
	}
}

int rst_delay_unix_bind(struct sock *sk, struct cpt_sock_image *v,
		cpt_context_t *ctx)
{
	int err;
	cpt_object_t *mntobj;
	struct vfsmount *mnt;
	struct super_block *sb;
	struct unix_bind_info *dbi;
	struct delay_sb_info *sbi;

	BUG_ON(v->cpt_sockflags & CPT_SOCK_DELETED);

	mntobj = lookup_cpt_obj_bypos(CPT_OBJ_VFSMOUNT_REF,
			v->cpt_vfsmount_ref, ctx);
	if (mntobj == NULL) {
		eprintk_ctx("can't find vfsmount for unix socket\n");
		return -EINVAL;
	}

	mnt = mntobj->o_obj;
	sb = mnt->mnt_sb;
	BUG_ON(sb->s_op != &delay_super_ops);

	if (v->cpt_laddrlen - 2 <= mntobj->o_lock) {
		eprintk_ctx("unix socket with too sort name (%d %s)\n",
				mntobj->o_lock, (char *)v->cpt_laddr);
		return -EINVAL;
	}

	err = unix_attach_addr(sk, (struct sockaddr_un *)v->cpt_laddr,
			v->cpt_laddrlen);
	if (err) {
		eprintk_ctx("can't attach unix address %d\n", err);
		return err;
	}

	dbi = kzalloc(sizeof(*dbi), GFP_KERNEL);
	if (dbi == NULL)
		return -ENOMEM;

	sock_hold(sk);
	dbi->sk = sk;
	strcpy(dbi->path, ((char *)v->cpt_laddr) + 2);
	dbi->path_off = mntobj->o_lock;

	if (cpt_object_has(v, cpt_i_mode))
		dbi->i_mode = v->cpt_i_mode;
	dbi->uid = v->cpt_peer_uid;
	dbi->gid = v->cpt_peer_gid;
	if (cpt_object_has(v, cpt_i_uid) && cpt_object_has(v, cpt_i_gid)) {
		dbi->uid = v->cpt_i_uid;
		dbi->gid = v->cpt_i_gid;
	}

	sbi = sb->s_fs_info;
	dbi->next = sbi->bi_list;
	sbi->bi_list = dbi;

	return 0;
}
