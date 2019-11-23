/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#include "fuse_i.h"

#include <linux/init.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/ve_proto.h>
#include <linux/seq_file.h>

#define FUSE_CTL_SUPER_MAGIC 0x65735543

/*
 * This is non-NULL when the single instance of the control filesystem
 * exists.  Protected by fuse_mutex
 */
#ifdef CONFIG_VE
#define fuse_control_sb	(get_exec_env()->_fuse_control_sb)
#else
static struct super_block *fuse_control_sb;
#endif

static struct fuse_conn *fuse_ctl_file_conn_get(struct file *file)
{
	struct fuse_conn *fc;
	mutex_lock(&fuse_mutex);
	fc = file->f_path.dentry->d_inode->i_private;
	if (fc)
		fc = fuse_conn_get(fc);
	mutex_unlock(&fuse_mutex);
	return fc;
}

static ssize_t fuse_conn_abort_write(struct file *file, const char __user *buf,
				     size_t count, loff_t *ppos)
{
	struct fuse_conn *fc = fuse_ctl_file_conn_get(file);
	if (fc) {
		fuse_abort_conn(fc);
		fuse_conn_put(fc);
	}
	return count;
}

static ssize_t fuse_conn_waiting_read(struct file *file, char __user *buf,
				      size_t len, loff_t *ppos)
{
	char tmp[32];
	size_t size;

	if (!*ppos) {
		long value;
		struct fuse_conn *fc = fuse_ctl_file_conn_get(file);
		if (!fc)
			return 0;

		value = atomic_read(&fc->num_waiting);
		file->private_data = (void *)value;
		fuse_conn_put(fc);
	}
	size = sprintf(tmp, "%ld\n", (long)file->private_data);
	return simple_read_from_buffer(buf, len, ppos, tmp, size);
}

static ssize_t fuse_conn_limit_read(struct file *file, char __user *buf,
				    size_t len, loff_t *ppos, unsigned val)
{
	char tmp[32];
	size_t size = sprintf(tmp, "%u\n", val);

	return simple_read_from_buffer(buf, len, ppos, tmp, size);
}

static ssize_t fuse_conn_limit_write(struct file *file, const char __user *buf,
				     size_t count, loff_t *ppos, unsigned *val,
				     unsigned global_limit)
{
	unsigned long t;
	char tmp[32];
	unsigned limit = (1 << 16) - 1;
	int err;

	if (*ppos || count >= sizeof(tmp) - 1)
		return -EINVAL;

	if (copy_from_user(tmp, buf, count))
		return -EINVAL;

	tmp[count] = '\0';

	err = strict_strtoul(tmp, 0, &t);
	if (err)
		return err;

	if (!capable(CAP_SYS_ADMIN))
		limit = min(limit, global_limit);

	if (t > limit)
		return -EINVAL;

	*val = t;

	return count;
}

static ssize_t fuse_conn_max_background_read(struct file *file,
					     char __user *buf, size_t len,
					     loff_t *ppos)
{
	struct fuse_conn *fc;
	unsigned val;

	fc = fuse_ctl_file_conn_get(file);
	if (!fc)
		return 0;

	val = fc->max_background;
	fuse_conn_put(fc);

	return fuse_conn_limit_read(file, buf, len, ppos, val);
}

static ssize_t fuse_conn_max_background_write(struct file *file,
					      const char __user *buf,
					      size_t count, loff_t *ppos)
{
	unsigned val;
	ssize_t ret;

	ret = fuse_conn_limit_write(file, buf, count, ppos, &val,
				    max_user_bgreq);
	if (ret > 0) {
		struct fuse_conn *fc = fuse_ctl_file_conn_get(file);
		if (fc) {
			fc->max_background = val;
			fuse_conn_put(fc);
		}
	}

	return ret;
}

static ssize_t fuse_conn_congestion_threshold_read(struct file *file,
						   char __user *buf, size_t len,
						   loff_t *ppos)
{
	struct fuse_conn *fc;
	unsigned val;

	fc = fuse_ctl_file_conn_get(file);
	if (!fc)
		return 0;

	val = fc->congestion_threshold;
	fuse_conn_put(fc);

	return fuse_conn_limit_read(file, buf, len, ppos, val);
}

static ssize_t fuse_conn_congestion_threshold_write(struct file *file,
						    const char __user *buf,
						    size_t count, loff_t *ppos)
{
	unsigned val;
	ssize_t ret;

	ret = fuse_conn_limit_write(file, buf, count, ppos, &val,
				    max_user_congthresh);
	if (ret > 0) {
		struct fuse_conn *fc = fuse_ctl_file_conn_get(file);
		if (fc) {
			fc->congestion_threshold = val;
			fuse_conn_put(fc);
		}
	}

	return ret;
}

static const struct file_operations fuse_ctl_abort_ops = {
	.open = nonseekable_open,
	.write = fuse_conn_abort_write,
};

static const struct file_operations fuse_ctl_waiting_ops = {
	.open = nonseekable_open,
	.read = fuse_conn_waiting_read,
};

static const struct file_operations fuse_conn_max_background_ops = {
	.open = nonseekable_open,
	.read = fuse_conn_max_background_read,
	.write = fuse_conn_max_background_write,
};

static const struct file_operations fuse_conn_congestion_threshold_ops = {
	.open = nonseekable_open,
	.read = fuse_conn_congestion_threshold_read,
	.write = fuse_conn_congestion_threshold_write,
};

struct fuse_conn_priv {
	struct fuse_conn *conn;
	struct list_head *req_list;
};

enum {
	FUSE_PENDING_REQ = 1,
	FUSE_PROCESSING_REQ,
	FUSE_IO_REQ,
};

static void *fuse_req_start(struct seq_file *m, loff_t *p)
{
	struct fuse_conn_priv *fcp = m->private;

	spin_lock(&fcp->conn->lock);
	return seq_list_start(fcp->req_list, *p);
}

static void *fuse_req_next(struct seq_file *m, void *v, loff_t *p)
{
	struct fuse_conn_priv *fcp = m->private;
	return seq_list_next(v, fcp->req_list, p);
}

static void fuse_req_stop(struct seq_file *m, void *v)
{
	struct fuse_conn_priv *fcp = m->private;
	spin_unlock(&fcp->conn->lock);
}

static int fuse_req_show(struct seq_file *f, void *v)
{
	struct fuse_req *req;

	req = list_entry((struct list_head *)v, struct fuse_req, list);
	seq_printf(f, "state: %-2d flags: %c%c%c%c%c%c%c "
			"in: op %-4d uniq 0x%016Lx node 0x%016Lx "
			"out: err %-6d uniq 0x%016Lx\n",
			req->state,
			req->isreply ? 'r' : '-',
			req->force ? 'f' : '-',
			req->aborted ? 'a' : '-',
			req->background ? 'b' : '-',
			req->interrupted ? 'i' : '-',
			req->locked ? 'l' : '-',
			req->waiting ? 'w': '-',
			req->in.h.opcode,
			req->in.h.unique,
			req->in.h.nodeid,
			req->out.h.error,
			req->out.h.unique);

	return 0;
}

static const struct seq_operations fuse_conn_req_ops = {
	.start = fuse_req_start,
	.next = fuse_req_next,
	.stop = fuse_req_stop,
	.show = fuse_req_show,
};

static int fuse_conn_seq_open(struct file *filp, int list_id)
{
	struct fuse_conn *conn;
	struct fuse_conn_priv *fcp;

	conn = fuse_ctl_file_conn_get(filp);
	if (!conn)
		return -ESTALE;

	fcp = __seq_open_private(filp, &fuse_conn_req_ops,
			sizeof(struct fuse_conn_priv));
	if (fcp == NULL) {
		fuse_conn_put(conn);
		return -ENOMEM;
	}

	fcp->conn = conn;
	switch (list_id) {
	case FUSE_PROCESSING_REQ:
		fcp->req_list = &conn->processing;
		break;
	case FUSE_PENDING_REQ:
		fcp->req_list = &conn->pending;
		break;
	case FUSE_IO_REQ:
		fcp->req_list = &conn->io;
		break;
	default:
		BUG();
	}

	return 0;
}

static int fuse_conn_release(struct inode *inode, struct file *filp)
{
	struct fuse_conn_priv *fcp = ((struct seq_file *)filp->private_data)->private;

	if (fcp)
		fuse_conn_put(fcp->conn);

	return seq_release_private(inode, filp);
}

static int fuse_conn_pending_open(struct inode *inode, struct file *filp)
{
	return fuse_conn_seq_open(filp, FUSE_PENDING_REQ);
}

static const struct file_operations fuse_conn_pending_req = {
	.open = fuse_conn_pending_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = fuse_conn_release,
};

static int fuse_conn_processing_open(struct inode *inode, struct file *filp)
{
	return fuse_conn_seq_open(filp, FUSE_PROCESSING_REQ);
}

static const struct file_operations fuse_conn_processing_req = {
	.open = fuse_conn_processing_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = fuse_conn_release,
};

static int fuse_conn_io_open(struct inode *inode, struct file *filp)
{
	return fuse_conn_seq_open(filp, FUSE_IO_REQ);
}

static const struct file_operations fuse_conn_io_req = {
	.open = fuse_conn_io_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = fuse_conn_release,
};

static int fuse_files_show(struct seq_file *f, void *v)
{
	struct fuse_file *ff;

	ff = list_entry(v, struct fuse_file, fl);
	seq_printf(f, "kh 0x%016Lx fh 0x%016Lx node 0x%016Lx flags 0x%08x name ",
			ff->kh, ff->fh, ff->nodeid, ff->open_flags);
	if (ff->ff_dentry)
		seq_dentry(f, ff->ff_dentry, "");
	else
		seq_putc(f, '-');
	seq_putc(f, '\n');

	return 0;
}

static const struct seq_operations fuse_conn_files_seq_ops = {
	.start = fuse_req_start,
	.next = fuse_req_next,
	.stop = fuse_req_stop,
	.show = fuse_files_show,
};

static int fuse_conn_files_open(struct inode *inode, struct file *filp)
{
	struct fuse_conn *conn;
	struct fuse_conn_priv *fcp;

	conn = fuse_ctl_file_conn_get(filp);
	if (!conn)
		return -ESTALE;

	fcp = __seq_open_private(filp, &fuse_conn_files_seq_ops,
			sizeof(struct fuse_conn_priv));
	if (fcp == NULL) {
		fuse_conn_put(conn);
		return -ENOMEM;
	}

	fcp->conn = conn;
	fcp->req_list = &conn->conn_files;
	return 0;
}

static const struct file_operations fuse_conn_files_ops = {
	.open = fuse_conn_files_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = fuse_conn_release,
};

static int fuse_conn_show(struct seq_file *sf, void *v)
{
	struct fuse_conn *fc = sf->private;
	seq_printf(sf, "Connected: %d\n", fc->connected);
	seq_printf(sf, "Initialized: %d\n", fc->initialized);
	seq_printf(sf, "Blocked: %d\n", fc->blocked);
	seq_printf(sf, "WQ active: %d\n", waitqueue_active(&fc->waitq));
	seq_printf(sf, "Blocked_wq active: %d\n", waitqueue_active(&fc->blocked_waitq));
	seq_printf(sf, "num_background: %d\n", fc->num_background);
	seq_printf(sf, "num_waiting: %d\n", atomic_read(&fc->num_waiting));
	return 0;
}

static int fuse_conn_info_open(struct inode *inode, struct file *filp)
{
	int ret;
	struct fuse_conn *conn;

	conn = fuse_ctl_file_conn_get(filp);
	if (!conn)
		return -ESTALE;

	ret = single_open(filp, fuse_conn_show, conn);
	if (ret)
		fuse_conn_put(conn);

	return ret;
}

static int fuse_conn_info_release(struct inode *inode, struct file *filp)
{
	struct fuse_conn *conn = ((struct seq_file *)filp->private_data)->private;
	fuse_conn_put(conn);
	return single_release(inode, filp);
}

static const struct file_operations fuse_conn_info_ops = {
	.open = fuse_conn_info_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = fuse_conn_info_release,
};

static struct dentry *fuse_ctl_add_dentry(struct dentry *parent,
					  struct fuse_conn *fc,
					  const char *name,
					  int mode, int nlink,
					  const struct inode_operations *iop,
					  const struct file_operations *fop)
{
	struct dentry *dentry;
	struct inode *inode;

	BUG_ON(fc->ctl_ndents >= FUSE_CTL_NUM_DENTRIES);
	dentry = d_alloc_name(parent, name);
	if (!dentry)
		return NULL;

	fc->ctl_dentry[fc->ctl_ndents++] = dentry;
	inode = new_inode(fuse_control_sb);
	if (!inode)
		return NULL;

	inode->i_mode = mode;
	inode->i_uid = fc->user_id;
	inode->i_gid = fc->group_id;
	inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
	/* setting ->i_op to NULL is not allowed */
	if (iop)
		inode->i_op = iop;
	inode->i_fop = fop;
	inode->i_nlink = nlink;
	inode->i_private = fc;
	d_add(dentry, inode);
	return dentry;
}

/*
 * Add a connection to the control filesystem (if it exists).  Caller
 * must hold fuse_mutex
 */
int fuse_ctl_add_conn(struct fuse_conn *fc)
{
	struct dentry *parent;
	char name[32];

	if (!fuse_control_sb)
		return 0;

	parent = fuse_control_sb->s_root;
	inc_nlink(parent->d_inode);
	sprintf(name, "%u", fc->dev);
	parent = fuse_ctl_add_dentry(parent, fc, name, S_IFDIR | 0500, 2,
				     &simple_dir_inode_operations,
				     &simple_dir_operations);
	if (!parent)
		goto err;

	if (!fuse_ctl_add_dentry(parent, fc, "waiting", S_IFREG | 0400, 1,
				 NULL, &fuse_ctl_waiting_ops) ||
	    !fuse_ctl_add_dentry(parent, fc, "abort", S_IFREG | 0200, 1,
				 NULL, &fuse_ctl_abort_ops) ||
	    !fuse_ctl_add_dentry(parent, fc, "max_background", S_IFREG | 0600,
				 1, NULL, &fuse_conn_max_background_ops) ||
	    !fuse_ctl_add_dentry(parent, fc, "congestion_threshold",
				 S_IFREG | 0600, 1, NULL,
				 &fuse_conn_congestion_threshold_ops) ||
	    !fuse_ctl_add_dentry(parent, fc, "pending_req",
		    		S_IFREG | 0600, 1, NULL,
				&fuse_conn_pending_req) ||
	    !fuse_ctl_add_dentry(parent, fc, "processing_req",
		    		S_IFREG | 0600, 1, NULL,
				&fuse_conn_processing_req) ||
	    !fuse_ctl_add_dentry(parent, fc, "io_req",
		    		S_IFREG | 0600, 1, NULL,
				&fuse_conn_io_req) ||
	    !fuse_ctl_add_dentry(parent, fc, "open_files",
		    		S_IFREG | 0600, 1, NULL,
				&fuse_conn_files_ops) ||
	    !fuse_ctl_add_dentry(parent, fc, "conn_info",
			    	S_IFREG | 0600, 1, NULL,
				&fuse_conn_info_ops)
	    )
		goto err;

	return 0;

 err:
	fuse_ctl_remove_conn(fc);
	return -ENOMEM;
}

/*
 * Remove a connection from the control filesystem (if it exists).
 * Caller must hold fuse_mutex
 */
void fuse_ctl_remove_conn(struct fuse_conn *fc)
{
	int i;

	if (!fuse_control_sb)
		return;

	for (i = fc->ctl_ndents - 1; i >= 0; i--) {
		struct dentry *dentry = fc->ctl_dentry[i];
		dentry->d_inode->i_private = NULL;
		d_drop(dentry);
		dput(dentry);
	}
	drop_nlink(fuse_control_sb->s_root->d_inode);
}

static int fuse_ctl_fill_super(struct super_block *sb, void *data, int silent)
{
	struct tree_descr empty_descr = {""};
	struct fuse_conn *fc;
	int err;

	err = simple_fill_super(sb, FUSE_CTL_SUPER_MAGIC, &empty_descr);
	if (err)
		return err;

	mutex_lock(&fuse_mutex);
	BUG_ON(fuse_control_sb);
	fuse_control_sb = sb;
	list_for_each_entry(fc, &fuse_conn_list, entry) {
		err = fuse_ctl_add_conn(fc);
		if (err) {
			fuse_control_sb = NULL;
			mutex_unlock(&fuse_mutex);
			return err;
		}
	}
	mutex_unlock(&fuse_mutex);

	return 0;
}

static int fuse_ctl_get_sb(struct file_system_type *fs_type, int flags,
			const char *dev_name, void *raw_data,
			struct vfsmount *mnt)
{
	return get_sb_single(fs_type, flags, raw_data,
				fuse_ctl_fill_super, mnt);
}

static void fuse_ctl_kill_sb(struct super_block *sb)
{
	struct fuse_conn *fc;

	mutex_lock(&fuse_mutex);
	fuse_control_sb = NULL;
	list_for_each_entry(fc, &fuse_conn_list, entry)
		fc->ctl_ndents = 0;
	mutex_unlock(&fuse_mutex);

	kill_litter_super(sb);
}

static struct file_system_type fuse_ctl_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "fusectl",
	.get_sb		= fuse_ctl_get_sb,
	.kill_sb	= fuse_ctl_kill_sb,
};

#ifdef CONFIG_VE
static int fuse_ctl_start(void *data)
{
	struct ve_struct *ve;

	ve = (struct ve_struct *)data;
	if (ve->fuse_ctl_fs_type != NULL)
		return -EBUSY;

	return register_ve_fs_type(ve, &fuse_ctl_fs_type,
			&ve->fuse_ctl_fs_type, NULL);
}

static void fuse_ctl_stop(void *data)
{
	struct ve_struct *ve;

	ve = (struct ve_struct *)data;
	if (ve->fuse_ctl_fs_type == NULL)
		return;

	unregister_ve_fs_type(ve->fuse_ctl_fs_type, NULL);
	/* fuse_ctl_fs_type is freed in real_put_ve -> free_ve_filesystems */
}

static struct ve_hook fuse_ctl_ve_hook = {
	.init		= fuse_ctl_start,
	.fini		= fuse_ctl_stop,
	.owner		= THIS_MODULE,
	.priority	= HOOK_PRIO_FS,
};
#endif

int __init fuse_ctl_init(void)
{
	int err;
	
	err = register_filesystem(&fuse_ctl_fs_type);
#ifdef CONFIG_VE
	if (err == 0)
		ve_hook_register(VE_SS_CHAIN, &fuse_ctl_ve_hook);
#endif
	return err;
}

void fuse_ctl_cleanup(void)
{
#ifdef CONFIG_VE
	ve_hook_unregister(&fuse_ctl_ve_hook);
#endif
	unregister_filesystem(&fuse_ctl_fs_type);
}
