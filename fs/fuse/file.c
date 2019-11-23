/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#include "fuse_i.h"

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/swap.h>
#include <linux/falloc.h>
#include <linux/bio.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/virtinfo.h>

static const struct file_operations fuse_direct_io_file_operations;
static void fuse_sync_writes(struct inode *inode);

static void fuse_account_request(struct fuse_conn *fc, size_t count)
{
	struct user_beancounter *ub = get_exec_ub_top();

	ub_percpu_inc(ub, fuse_requests);
	ub_percpu_add(ub, fuse_bytes, count);
	virtinfo_notifier_call_irq(VITYPE_IO, VIRTINFO_IO_FUSE_REQ, NULL);
}

static int fuse_send_open(struct fuse_conn *fc, u64 nodeid, struct file *file,
			  int opcode, struct fuse_open_out *outargp)
{
	struct fuse_open_in inarg;
	struct fuse_req *req;
	int err;

	req = fuse_get_req_nopages(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	memset(&inarg, 0, sizeof(inarg));
	inarg.flags = file->f_flags & ~(O_CREAT | O_EXCL | O_NOCTTY);
	if (!fc->atomic_o_trunc)
		inarg.flags &= ~O_TRUNC;
	req->in.h.opcode = opcode;
	req->in.h.nodeid = nodeid;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->out.numargs = 1;
	req->out.args[0].size = sizeof(*outargp);
	req->out.args[0].value = outargp;
	fuse_request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);

	return err;
}

struct fuse_file *fuse_file_alloc(struct fuse_conn *fc)
{
	struct fuse_file *ff;

	ff = kmalloc(sizeof(struct fuse_file), GFP_KERNEL);
	if (unlikely(!ff))
		return NULL;

	ff->ff_state = 0;

	ff->fc = fc;
	ff->reserved_req = fuse_request_alloc(0);
	if (unlikely(!ff->reserved_req)) {
		kfree(ff);
		return NULL;
	}

	INIT_LIST_HEAD(&ff->write_entry);
	INIT_LIST_HEAD(&ff->rw_entry);
	atomic_set(&ff->count, 0);
	RB_CLEAR_NODE(&ff->polled_node);
	init_waitqueue_head(&ff->poll_wait);

	spin_lock(&fc->lock);
	ff->kh = ++fc->khctr;
	ff->ff_dentry = NULL;
	list_add_tail(&ff->fl, &fc->conn_files);
	spin_unlock(&fc->lock);

	return ff;
}

static void fuse_file_list_del(struct fuse_file *ff)
{
	spin_lock(&ff->fc->lock);
	list_del_init(&ff->fl);
	spin_unlock(&ff->fc->lock);
}

void fuse_file_free(struct fuse_file *ff)
{
	fuse_file_list_del(ff);
	fuse_request_free(ff->reserved_req);
	kfree(ff);
}

struct fuse_file *fuse_file_get(struct fuse_file *ff)
{
	atomic_inc(&ff->count);
	return ff;
}

static void fuse_release_async(struct work_struct *work)
{
	struct fuse_req *req;
	struct fuse_conn *fc;
	struct path path;

	req = container_of(work, struct fuse_req, misc.release.work);
	path = req->misc.release.path;
	fc = get_fuse_conn(path.dentry->d_inode);

	fuse_put_request(fc, req);
	path_put(&path);
}

static void fuse_release_end(struct fuse_conn *fc, struct fuse_req *req)
{
	if (fc->destroy_req) {
		/*
		 * If this is a fuseblk mount, then it's possible that
		 * releasing the path will result in releasing the
		 * super block and sending the DESTROY request.  If
		 * the server is single threaded, this would hang.
		 * For this reason do the path_put() in a separate
		 * thread.
		 */
		atomic_inc(&req->count);
		INIT_WORK(&req->misc.release.work, fuse_release_async);
		schedule_work(&req->misc.release.work);
	} else {
		path_put(&req->misc.release.path);
	}
}

static void fuse_file_put(struct fuse_file *ff, bool sync)
{
	if (atomic_dec_and_test(&ff->count)) {
		struct fuse_req *req = ff->reserved_req;

		if (sync) {
			/* Must force. Otherwise request could be interrupted,
			 * but file association in user space remains.
			 */
			req->force = 1;
			req->background = 0;
			fuse_request_send(ff->fc, req);
			fuse_file_list_del(ff);
			path_put(&req->misc.release.path);
			fuse_put_request(ff->fc, req);
		} else {
			fuse_file_list_del(ff);
			req->end = fuse_release_end;
			req->background = 1;
			fuse_request_send_background(ff->fc, req);
		}

		kfree(ff);
	}
}

static void __fuse_file_put(struct fuse_file *ff)
{
	if (atomic_dec_and_test(&ff->count))
		BUG();
}

int fuse_do_open(struct fuse_conn *fc, u64 nodeid, struct file *file,
		 bool isdir)
{
	struct fuse_open_out outarg;
	struct fuse_file *ff;
	int err;
	int opcode = isdir ? FUSE_OPENDIR : FUSE_OPEN;

	ff = fuse_file_alloc(fc);
	if (!ff)
		return -ENOMEM;

	err = fuse_send_open(fc, nodeid, file, opcode, &outarg);
	if (err) {
		fuse_file_free(ff);
		return err;
	}

	if (isdir)
		outarg.open_flags &= ~FOPEN_DIRECT_IO;

	ff->fh = outarg.fh;
	ff->nodeid = nodeid;
	ff->open_flags = outarg.open_flags;
	file->private_data = fuse_file_get(ff);

	return 0;
}
EXPORT_SYMBOL_GPL(fuse_do_open);

static void fuse_link_file(struct file *file, bool write)
{
	struct inode *inode = file->f_dentry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_file *ff = file->private_data;

	struct list_head *entry = write ? &ff->write_entry : &ff->rw_entry;
	struct list_head *list  = write ? &fi->write_files : &fi->rw_files;

	spin_lock(&fc->lock);
	if (list_empty(entry))
		list_add(entry, list);
	spin_unlock(&fc->lock);
}

static void fuse_link_write_file(struct file *file)
{
	fuse_link_file(file, true);
}

static void fuse_link_rw_file(struct file *file)
{
	fuse_link_file(file, false);
}

void fuse_finish_open(struct inode *inode, struct file *file)
{
	struct fuse_file *ff = file->private_data;

	ff->ff_dentry = file->f_dentry;

	if (ff->open_flags & FOPEN_DIRECT_IO)
		file->f_op = &fuse_direct_io_file_operations;
	if (!(ff->open_flags & FOPEN_KEEP_CACHE))
		invalidate_inode_pages2(inode->i_mapping);
	if (ff->open_flags & FOPEN_NONSEEKABLE)
		nonseekable_open(inode, file);

 	/* file might be required for fallocate or writeback cache */
	if (S_ISREG(inode->i_mode) && (file->f_mode & FMODE_WRITE))
		fuse_link_write_file(file);

	fuse_link_rw_file(file);
}

int fuse_open_common(struct inode *inode, struct file *file, bool isdir)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	int err;

	if ((file->f_flags & O_DIRECT) && !(fc->flags & FUSE_ODIRECT))
		return -EINVAL;

	err = generic_file_open(inode, file);
	if (err)
		return err;

	err = fuse_do_open(fc, get_node_id(inode), file, isdir);
	if (err)
		return err;

	if ((fc->flags & FUSE_WBCACHE) && !isdir) {
		struct fuse_inode *fi = get_fuse_inode(inode);
		u64 size;

		mutex_lock(&inode->i_mutex);
		atomic_inc(&fi->num_openers);

		if (atomic_read(&fi->num_openers) == 1) {
			err = fuse_getattr_size(inode, file, &size);
			if (err) {
				atomic_dec(&fi->num_openers);
				mutex_unlock(&inode->i_mutex);
				fuse_release_common(file, FUSE_RELEASE);
				return err;
			}

			spin_lock(&fc->lock);
			i_size_write(inode, size);
			spin_unlock(&fc->lock);
		}

		mutex_unlock(&inode->i_mutex);
	}

	fuse_finish_open(inode, file);

	return 0;
}

static void fuse_prepare_release(struct fuse_file *ff, int flags, int opcode)
{
	struct fuse_conn *fc = ff->fc;
	struct fuse_req *req = ff->reserved_req;
	struct fuse_release_in *inarg = &req->misc.release.in;

	spin_lock(&fc->lock);
	list_del(&ff->write_entry);
	list_del(&ff->rw_entry);
	if (!RB_EMPTY_NODE(&ff->polled_node))
		rb_erase(&ff->polled_node, &fc->polled_files);
	spin_unlock(&fc->lock);

	wake_up_interruptible_sync(&ff->poll_wait);

	inarg->fh = ff->fh;
	inarg->flags = flags;
	req->in.h.opcode = opcode;
	req->in.h.nodeid = ff->nodeid;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(struct fuse_release_in);
	req->in.args[0].value = inarg;
}

void fuse_release_common(struct file *file, int opcode)
{
	struct fuse_file *ff;
	struct fuse_req *req;

	ff = file->private_data;
	if (unlikely(!ff))
		return;

	req = ff->reserved_req;
	fuse_prepare_release(ff, file->f_flags, opcode);

	/* Hold vfsmount and dentry until release is finished */
	path_get(&file->f_path);
	req->misc.release.path = file->f_path;

	/*
	 * No more in-flight asynchronous READ or WRITE requests if
	 * fuse file release is synchronous
	 */
	if (ff->fc->close_wait)
		BUG_ON(atomic_read(&ff->count) != 1);

	/*
	 * Normally this will send the RELEASE request, however if
	 * some asynchronous READ or WRITE requests are outstanding,
	 * the sending will be delayed.
	 *
	 * Make the release synchronous if this is a fuseblk mount,
	 * synchronous RELEASE is allowed (and desirable) in this case
	 * because the server can be trusted not to screw up.
	 */
	fuse_file_put(ff, ff->fc->destroy_req != NULL ||
			  ff->fc->close_wait);
}

static int fuse_open(struct inode *inode, struct file *file)
{
	return fuse_open_common(inode, file, false);
}

static int fuse_release(struct inode *inode, struct file *file)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_inode *fi = get_fuse_inode(inode);

	if (ff->fc->flags & FUSE_WBCACHE) {
		if (file->f_mode & FMODE_WRITE) {
			filemap_write_and_wait(file->f_mapping);

			/* Must remove file from write list. Otherwise it is possible this
			 * file will get more writeback from another files rerouted via write_files
			 */
			spin_lock(&ff->fc->lock);
			list_del_init(&ff->write_entry);
			spin_unlock(&ff->fc->lock);

			/* A writeback from another fuse file might come after
			 * filemap_write_and_wait() above
			 */
			if (!ff->fc->close_wait)
				filemap_write_and_wait(file->f_mapping);
		} else
			BUG_ON(!list_empty(&ff->write_entry));

		/* This can livelock. Inode can be open via another file
		 * and that file can generate continuous writeback.
		 * I think i_mutex could be taken around this.
		 * 
		 * For now we replace this with waiting on ff->count,
		 * it is safe, because we essentially wait only for writeback (and readahead)
		 * enqueued on this file and it is not going to get new one: it is closing.
		 */
		if (!ff->fc->close_wait)
			wait_event(fi->page_waitq, list_empty_careful(&fi->writepages));
		else
			wait_event(fi->page_waitq, atomic_read(&ff->count) == 1);

		/* Wait for threads just released ff to leave their critical sections.
		 * Taking spinlock is the first thing fuse_release_common does, so that
		 * this is unneseccary, but it is still good to emphasize right here,
		 * that we need this.
		 */
		spin_unlock_wait(&ff->fc->lock);

		/* since now we can trust userspace attr.size */
		atomic_dec(&fi->num_openers);
	} else if (ff->fc->close_wait)
		wait_event(fi->page_waitq, atomic_read(&ff->count) == 1);

	fuse_release_common(file, FUSE_RELEASE);

	/* return value is ignored by VFS */
	return 0;
}

void fuse_sync_release(struct fuse_file *ff, int flags)
{
	WARN_ON(atomic_read(&ff->count) > 1);
	fuse_file_list_del(ff);
	fuse_prepare_release(ff, flags, FUSE_RELEASE);
	ff->reserved_req->force = 1;
	ff->reserved_req->background = 0;
	fuse_request_send(ff->fc, ff->reserved_req);
	fuse_put_request(ff->fc, ff->reserved_req);
	kfree(ff);
}
EXPORT_SYMBOL_GPL(fuse_sync_release);

/*
 * Scramble the ID space with XTEA, so that the value of the files_struct
 * pointer is not exposed to userspace.
 */
u64 fuse_lock_owner_id(struct fuse_conn *fc, fl_owner_t id)
{
	u32 *k = fc->scramble_key;
	u64 v = (unsigned long) id;
	u32 v0 = v;
	u32 v1 = v >> 32;
	u32 sum = 0;
	int i;

	for (i = 0; i < 32; i++) {
		v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]);
		sum += 0x9E3779B9;
		v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[sum>>11 & 3]);
	}

	return (u64) v0 + ((u64) v1 << 32);
}

/*
 * Check if page is under writeback
 *
 * This is currently done by walking the list of writepage requests
 * for the inode, which can be pretty inefficient.
 */
static bool fuse_page_is_writeback(struct inode *inode, pgoff_t index)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_req *req;
	bool found = false;

	spin_lock(&fc->lock);
	list_for_each_entry(req, &fi->writepages, writepages_entry) {
		pgoff_t curr_index;

		BUG_ON(req->inode != inode);
		curr_index = req->misc.write.in.offset >> PAGE_CACHE_SHIFT;
		if (curr_index <= index &&
		    index < curr_index + req->num_pages) {
			found = true;
			break;
		}
	}
	spin_unlock(&fc->lock);

	return found;
}

static bool fuse_range_is_writeback(struct inode *inode, pgoff_t idx_from, pgoff_t idx_to)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_req *req;
	bool found = false;

	spin_lock(&fc->lock);
	list_for_each_entry(req, &fi->writepages, writepages_entry) {
		pgoff_t curr_index;

		BUG_ON(req->inode != inode);
		curr_index = req->misc.write.in.offset >> PAGE_CACHE_SHIFT;
		if (!(idx_from >= curr_index + req->num_pages || idx_to < curr_index)) {
			found = true;
			break;
		}
	}
	spin_unlock(&fc->lock);

	return found;
}

/*
 * Wait for page writeback to be completed.
 *
 * Since fuse doesn't rely on the VM writeback tracking, this has to
 * use some other means.
 */
static int fuse_wait_on_page_writeback(struct inode *inode, pgoff_t index)
{
	struct fuse_inode *fi = get_fuse_inode(inode);

	wait_event(fi->page_waitq, !fuse_page_is_writeback(inode, index));
	return 0;
}

/*
 * Can be woken up by FUSE_NOTIFY_INVAL_FILES
 */
static int fuse_wait_on_page_writeback_or_invalidate(struct inode *inode,
						     struct file *file,
						     pgoff_t index)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_file *ff = file->private_data;

	wait_event(fi->page_waitq, !fuse_page_is_writeback(inode, index) ||
		   test_bit(FUSE_S_FAIL_IMMEDIATELY, &ff->ff_state));
	return 0;
}

static void fuse_wait_on_writeback(struct inode *inode, pgoff_t start, size_t bytes)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	pgoff_t idx_from, idx_to;

	idx_from = start >> PAGE_CACHE_SHIFT;
	idx_to = (start + bytes - 1) >> PAGE_CACHE_SHIFT;

	wait_event(fi->page_waitq, !fuse_range_is_writeback(inode, idx_from, idx_to));
}

static int fuse_flush(struct file *file, fl_owner_t id)
{
	struct inode *inode = file->f_path.dentry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_file *ff = file->private_data;
	struct fuse_req *req;
	struct fuse_flush_in inarg;
	int err;

	if (is_bad_inode(inode))
		return -EIO;

	if (!(file->f_mode & FMODE_WRITE))
		return 0;

	if (fc->flags & FUSE_WBCACHE) {
		err = filemap_write_and_wait(file->f_mapping);
		if (err)
			return err;

		mutex_lock(&inode->i_mutex);
		fuse_sync_writes(inode);
		mutex_unlock(&inode->i_mutex);

		if (test_and_clear_bit(AS_ENOSPC, &file->f_mapping->flags))
			err = -ENOSPC;
		if (test_and_clear_bit(AS_EIO, &file->f_mapping->flags))
			err = -EIO;
		if (err)
			return err;
	}

	if (fc->no_flush)
		return 0;

	req = fuse_get_req_nofail_nopages(fc, file);
	memset(&inarg, 0, sizeof(inarg));
	inarg.fh = ff->fh;
	inarg.lock_owner = fuse_lock_owner_id(fc, id);
	req->in.h.opcode = FUSE_FLUSH;
	req->in.h.nodeid = get_node_id(inode);
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->force = 1;
	fuse_request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (err == -ENOSYS) {
		fc->no_flush = 1;
		err = 0;
	}
	return err;
}

/*
 * Wait for all pending writepages on the inode to finish.
 *
 * This is currently done by blocking further writes with FUSE_NOWRITE
 * and waiting for all sent writes to complete.
 *
 * This must be called under i_mutex, otherwise the FUSE_NOWRITE usage
 * could conflict with truncation.
 */
static void fuse_sync_writes(struct inode *inode)
{
	fuse_set_nowrite(inode);
	fuse_release_nowrite(inode);
}

int fuse_fsync_common(struct file *file, struct dentry *de, int datasync,
		      int isdir)
{
	struct inode *inode = de->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_file *ff = file->private_data;
	struct fuse_req *req;
	struct fuse_fsync_in inarg;
	int err;

	if (is_bad_inode(inode))
		return -EIO;

	if ((!isdir && fc->no_fsync) || (isdir && fc->no_fsyncdir))
		return 0;

	/*
	 * Start writeback against all dirty pages of the inode, then
	 * wait for all outstanding writes, before sending the FSYNC
	 * request.
	 */
	err = write_inode_now(inode, 0);
	if (err)
		return err;

	fuse_sync_writes(inode);

	/* Due to implementation of fuse writeback filemap_write_and_wait_range()
	 * does not catch errors. We have to do this directly after fuse_sync_writes()
	 */
	if (test_and_clear_bit(AS_ENOSPC, &file->f_mapping->flags))
		err = -ENOSPC;
	if (test_and_clear_bit(AS_EIO, &file->f_mapping->flags))
		err = -EIO;
	if (err)
		return err;

	req = fuse_get_req_nopages(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	memset(&inarg, 0, sizeof(inarg));
	inarg.fh = ff->fh;
	inarg.fsync_flags = datasync ? 1 : 0;
	req->in.h.opcode = isdir ? FUSE_FSYNCDIR : FUSE_FSYNC;
	req->in.h.nodeid = get_node_id(inode);
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	fuse_request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (err == -ENOSYS) {
		if (isdir)
			fc->no_fsyncdir = 1;
		else
			fc->no_fsync = 1;
		err = 0;
	}
	return err;
}

static int fuse_fsync(struct file *file, struct dentry *de, int datasync)
{
	return fuse_fsync_common(file, de, datasync, 0);
}

void fuse_read_fill(struct fuse_req *req, struct file *file, loff_t pos,
		    size_t count, int opcode)
{
	struct fuse_read_in *inarg = &req->misc.read.in;
	struct fuse_file *ff = file->private_data;

	inarg->fh = ff->fh;
	inarg->offset = pos;
	inarg->size = count;
	inarg->flags = file->f_flags;
	req->in.h.opcode = opcode;
	req->in.h.nodeid = ff->nodeid;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(struct fuse_read_in);
	req->in.args[0].value = inarg;
	req->out.argvar = 1;
	req->out.numargs = 1;
	req->out.args[0].size = count;

	if (opcode == FUSE_READ)
		req->inode = file->f_dentry->d_inode;
}

static void fuse_release_user_pages(struct fuse_req *req, int write)
{
	unsigned i;

	for (i = 0; i < req->num_pages; i++) {
		struct page *page = req->pages[i];
		if (write)
			set_page_dirty_lock(page);
		put_page(page);
	}
}

/**
 * In case of short read, the caller sets 'pos' to the position of
 * actual end of fuse request in IO request. Otherwise, if bytes_requested
 * == bytes_transferred or rw == WRITE, the caller sets 'pos' to -1.
 *
 * An example:
 * User requested DIO read of 64K. It was splitted into two 32K fuse requests,
 * both submitted asynchronously. The first of them was ACKed by userspace as
 * fully completed (req->out.args[0].size == 32K) resulting in pos == -1. The
 * second request was ACKed as short, e.g. only 1K was read, resulting in
 * pos == 33K.
 *
 * Thus, when all fuse requests are completed, the minimal non-negative 'pos'
 * will be equal to the length of the longest contiguous fragment of
 * transferred data starting from the beginning of IO request.
 */
static void fuse_aio_complete(struct fuse_io_priv *io, int err, ssize_t pos)
{
	int left;

	spin_lock(&io->lock);
	if (err)
		io->err = io->err ? : err;
	else if (pos >= 0 && (io->bytes < 0 || pos < io->bytes))
		io->bytes = pos;

	left = --io->reqs;
	spin_unlock(&io->lock);

	if (!left) {
		long res;

		if (io->err)
			res = io->err;
		else if (io->bytes >= 0 && io->write)
			res = -EIO;
		else {
			res = io->bytes < 0 ? io->size : io->bytes;

			if (!is_sync_kiocb(io->iocb)) {
				struct path *path = &io->iocb->ki_filp->f_path;
				struct inode *inode = path->dentry->d_inode;
				struct fuse_conn *fc = get_fuse_conn(inode);
				struct fuse_inode *fi = get_fuse_inode(inode);

				spin_lock(&fc->lock);
				fi->attr_version = ++fc->attr_version;
				spin_unlock(&fc->lock);
			}
		}

		if (res < 0)
			printk("fuse_aio_complete(io=%p, err=%d, pos=%ld"
			       "): io->err=%d io->bytes=%ld io->size=%ld "
			       "is_sync=%d res=%ld ki_opcode=%d ki_pos=%llu\n",
			       io, err, pos, io->err, io->bytes,
			       io->size, is_sync_kiocb(io->iocb), res,
			       io->iocb->ki_opcode, io->iocb->ki_pos);
		aio_complete(io->iocb, res, 0);
		kfree(io);
	}
}

static void fuse_aio_complete_req(struct fuse_conn *fc, struct fuse_req *req)
{
	struct fuse_io_priv *io = req->io;
	ssize_t pos = -1;

	if (!req->bvec)
		fuse_release_user_pages(req, !io->write);

	if (io->write) {
		if (req->misc.write.in.size != req->misc.write.out.size)
			pos = req->misc.write.in.offset - io->offset +
				req->misc.write.out.size;
	} else {
		if (req->misc.read.in.size != req->out.args[0].size)
			pos = req->misc.read.in.offset - io->offset +
				req->out.args[0].size;
	}

	if (req->out.h.error)
		printk("fuse_aio_complete_req: request (rw=%s fh=0x%llx "
		       "pos=%lld size=%d) completed with err=%d\n",
		       !io->write ? "READ"                   : "WRITE",
		       !io->write ? req->misc.read.in.fh     : req->misc.write.in.fh,
		       !io->write ? req->misc.read.in.offset : req->misc.write.in.offset,
		       !io->write ? req->misc.read.in.size   : req->misc.write.in.size,
		       req->out.h.error);

	fuse_aio_complete(io, req->out.h.error, pos);
}

static size_t fuse_async_req_send(struct fuse_conn *fc, struct fuse_req *req,
		size_t num_bytes, struct fuse_io_priv *io)
{
	spin_lock(&io->lock);
	io->size += num_bytes;
	io->reqs++;
	spin_unlock(&io->lock);

	req->io = io;
	req->end = fuse_aio_complete_req;

	__fuse_get_request(req);
	fuse_request_send_background(fc, req);

	return num_bytes;
}

static size_t fuse_send_read(struct fuse_req *req, struct fuse_io_priv *io,
			     loff_t pos, size_t count, fl_owner_t owner)
{
	struct file *file = io->file;
	struct fuse_file *ff = file->private_data;
	struct fuse_conn *fc = ff->fc;

	fuse_read_fill(req, file, pos, count, FUSE_READ);
	fuse_account_request(fc, count);
	if (owner != NULL) {
		struct fuse_read_in *inarg = &req->misc.read.in;

		inarg->read_flags |= FUSE_READ_LOCKOWNER;
		inarg->lock_owner = fuse_lock_owner_id(fc, owner);
	}

	if (io->async)
		return fuse_async_req_send(fc, req, count, io);

	fuse_request_check_and_send(fc, req, ff);
	return req->out.args[0].size;
}

static void fuse_read_update_size(struct inode *inode, loff_t size,
				  u64 attr_ver)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);

	spin_lock(&fc->lock);
	if (attr_ver == fi->attr_version && size < inode->i_size &&
	    !test_bit(FUSE_I_SIZE_UNSTABLE, &fi->state)) {
		fi->attr_version = ++fc->attr_version;
		i_size_write(inode, size);
	}
	spin_unlock(&fc->lock);
}

static void fuse_readpages_short(struct fuse_req *req, u64 attr_ver)
{
	int i;
	size_t num_read = req->out.args[0].size;
	struct inode *inode = req->pages[0]->mapping->host;
	struct fuse_conn *fc = get_fuse_conn(inode);

	if (fc->flags & FUSE_WBCACHE) {
		/*
		 * A hole in a file. Some data after the hole are in page cache.
		 */
		size_t off = num_read & (PAGE_CACHE_SIZE - 1);

		for (i = num_read >> PAGE_CACHE_SHIFT; i < req->num_pages; i++) {
			struct page *page = req->pages[i];
			void *mapaddr = kmap_atomic(page, KM_USER0);

			memset(mapaddr + off, 0, PAGE_CACHE_SIZE - off);

			kunmap_atomic(mapaddr, KM_USER0);
			off = 0;
		}
	} else {
		/*
		 * Short read means EOF.  If file size is larger, truncate it
		 */
		loff_t pos = page_offset(req->pages[0]) + num_read;
		fuse_read_update_size(inode, pos, attr_ver);
	}
}

static int fuse_readpage(struct file *file, struct page *page)
{
	struct fuse_io_priv io = { .async = 0, .file = file };
	struct inode *inode = page->mapping->host;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	size_t num_read;
	loff_t pos = page_offset(page);
	size_t count = PAGE_CACHE_SIZE;
	u64 attr_ver;
	int err;
	bool killed = false;

	err = -EIO;
	if (is_bad_inode(inode))
		goto out;

	/*
	 * Page writeback can extend beyond the lifetime of the
	 * page-cache page, so make sure we read a properly synced
	 * page.
	 *
	 * But we can't wait if FUSE_NOTIFY_INVAL_FILES is in progress.
	 */
	fuse_wait_on_page_writeback_or_invalidate(inode, file, page->index);

	req = fuse_get_req(fc, 1);
	err = PTR_ERR(req);
	if (IS_ERR(req))
		goto out;

	attr_ver = fuse_get_attr_version(fc);

	req->out.page_zeroing = 1;
	req->out.argpages = 1;
	req->num_pages = 1;
	req->pages[0] = page;
	req->page_descs[0].length = count;
	req->page_cache = 1;
	num_read = fuse_send_read(req, &io, pos, count, NULL);
	killed = req->killed;
	err = killed ? -EIO : req->out.h.error;

	if (!err) {
		if (num_read < count)
			fuse_readpages_short(req, attr_ver);

		SetPageUptodate(page);
	}

	fuse_put_request(fc, req);

	fuse_invalidate_attr(inode); /* atime changed */
 out:
	if (!killed)
		unlock_page(page);
	return err;
}

void fuse_release_ff(struct inode *inode, struct fuse_file *ff)
{
	if (ff) {
		if (ff->fc->close_wait) {
			spin_lock(&ff->fc->lock);
			__fuse_file_put(ff);
			wake_up(&get_fuse_inode(inode)->page_waitq);
			spin_unlock(&ff->fc->lock);
		} else {
			fuse_file_put(ff, false);
		}
	}
}

static void fuse_readpages_end(struct fuse_conn *fc, struct fuse_req *req)
{
	int i;
	size_t count = req->misc.read.in.size;
	size_t num_read = req->out.args[0].size;
	struct inode *inode = req->inode;

	/* fused might process given request before lost-lease happened */
	if (req->killed && !req->out.h.error)
		req->out.h.error = -EIO;

	if (req->killed)
		goto killed;

	if (!req->out.h.error && num_read < count)
		fuse_readpages_short(req, req->misc.read.attr_ver);

	for (i = 0; i < req->num_pages; i++) {
		struct page *page = req->pages[i];
		if (!req->out.h.error)
			SetPageUptodate(page);
		else
			SetPageError(page);
		unlock_page(page);
		page_cache_release(page);
	}

killed:
	fuse_invalidate_attr(inode); /* atime changed */

	if (req->ff)
		fuse_release_ff(inode, req->ff);
}

static void fuse_send_readpages(struct fuse_req *req, struct file *file)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_conn *fc = ff->fc;
	loff_t pos = page_offset(req->pages[0]);
	size_t count = req->num_pages << PAGE_CACHE_SHIFT;

	req->out.argpages = 1;
	req->out.page_zeroing = 1;
	req->out.page_replace = 1;
	req->page_cache = 1;
	fuse_read_fill(req, file, pos, count, FUSE_READ);
	fuse_account_request(fc, count);
	req->misc.read.attr_ver = fuse_get_attr_version(fc);
	if (fc->async_read) {
		req->ff = fuse_file_get(ff);
		req->end = fuse_readpages_end;
		fuse_request_send_background(fc, req);
	} else {
		fuse_request_send(fc, req);
		fuse_readpages_end(fc, req);
		fuse_put_request(fc, req);
	}
}

struct fuse_fill_data {
	struct fuse_req *req;
	union {
		struct file *file;
		struct fuse_file *ff;
	};
	struct inode *inode;
	unsigned nr_pages;
};

static int fuse_readpages_fill(void *_data, struct page *page)
{
	struct fuse_fill_data *data = _data;
	struct fuse_req *req = data->req;
	struct inode *inode = data->inode;
	struct file *file = data->file;
	struct fuse_conn *fc = get_fuse_conn(inode);

	/* we can't wait if FUSE_NOTIFY_INVAL_FILES is in progress */
	fuse_wait_on_page_writeback_or_invalidate(inode, file, page->index);

	if (req->num_pages &&
	    (req->num_pages == FUSE_MAX_PAGES_PER_REQ ||
	     (req->num_pages + 1) * PAGE_CACHE_SIZE > fc->max_read ||
	     req->pages[req->num_pages - 1]->index + 1 != page->index)) {
		int nr_alloc = min_t(unsigned, data->nr_pages,
				     FUSE_MAX_PAGES_PER_REQ);
		fuse_send_readpages(req, data->file);
		if (fc->async_read)
			req = fuse_get_req_for_background(fc, nr_alloc);
		else
			req = fuse_get_req(fc, nr_alloc);

		data->req = req;
		if (IS_ERR(req)) {
			unlock_page(page);
			return PTR_ERR(req);
		}
	}

	if (WARN_ON(req->num_pages >= req->max_pages)) {
		fuse_put_request(fc, req);
		return -EIO;
	}
	page_cache_get(page);
	req->pages[req->num_pages] = page;
	req->page_descs[req->num_pages].length = PAGE_SIZE;
	req->num_pages++;
	data->nr_pages--;
	return 0;
}

static int fuse_readpages(struct file *file, struct address_space *mapping,
			  struct list_head *pages, unsigned nr_pages)
{
	struct inode *inode = mapping->host;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_fill_data data;
	int err;
	int nr_alloc = min_t(unsigned, nr_pages, FUSE_MAX_PAGES_PER_REQ);

	err = -EIO;
	if (is_bad_inode(inode))
		goto out;

	data.file = file;
	data.inode = inode;
	if (fc->async_read)
		data.req = fuse_get_req_for_background(fc, nr_alloc);
	else
		data.req = fuse_get_req(fc, nr_alloc);
	data.nr_pages = nr_pages;
	err = PTR_ERR(data.req);
	if (IS_ERR(data.req))
		goto out;

	err = read_cache_pages(mapping, pages, fuse_readpages_fill, &data);
	if (!err) {
		if (data.req->num_pages)
			fuse_send_readpages(data.req, file);
		else
			fuse_put_request(fc, data.req);
	}
out:
	return err;
}

static ssize_t fuse_file_aio_read(struct kiocb *iocb, const struct iovec *iov,
				  unsigned long nr_segs, loff_t pos)
{
	struct inode *inode = iocb->ki_filp->f_mapping->host;
	struct fuse_conn *fc = get_fuse_conn(inode);

	/*
	 * In auto invalidate mode, always update attributes on read.
	 * Otherwise, only update if we attempt to read past EOF (to ensure
	 * i_size is up to date).
	 */
	if (fc->auto_inval_data ||
	    (pos + iov_length(iov, nr_segs) > i_size_read(inode))) {
		int err;
		err = fuse_update_attributes(inode, NULL, iocb->ki_filp, NULL);
		if (err)
			return err;
	}

	return generic_file_aio_read(iocb, iov, nr_segs, pos);
}

static void fuse_write_fill(struct fuse_req *req, struct fuse_file *ff,
			    loff_t pos, size_t count)
{
	struct fuse_write_in *inarg = &req->misc.write.in;
	struct fuse_write_out *outarg = &req->misc.write.out;

	inarg->fh = ff->fh;
	inarg->offset = pos;
	inarg->size = count;
	req->in.h.opcode = FUSE_WRITE;
	req->in.h.nodeid = ff->nodeid;
	req->in.numargs = 2;
	if (ff->fc->minor < 9)
		req->in.args[0].size = FUSE_COMPAT_WRITE_IN_SIZE;
	else
		req->in.args[0].size = sizeof(struct fuse_write_in);
	req->in.args[0].value = inarg;
	req->in.args[1].size = count;
	req->out.numargs = 1;
	req->out.args[0].size = sizeof(struct fuse_write_out);
	req->out.args[0].value = outarg;
}

static size_t fuse_send_write(struct fuse_req *req, struct fuse_io_priv *io,
			      loff_t pos, size_t count, fl_owner_t owner)
{
	struct file *file = io->file;
	struct fuse_file *ff = file->private_data;
	struct fuse_conn *fc = ff->fc;
	struct fuse_write_in *inarg = &req->misc.write.in;

	fuse_write_fill(req, ff, pos, count);
	fuse_account_request(fc, count);
	inarg->flags = file->f_flags;
	if (owner != NULL) {
		inarg->write_flags |= FUSE_WRITE_LOCKOWNER;
		inarg->lock_owner = fuse_lock_owner_id(fc, owner);
	}

	if (io->async)
		return fuse_async_req_send(fc, req, count, io);

	fuse_request_send(fc, req);
	return req->misc.write.out.size;
}

static inline bool fuse_file_fail_immediately(struct file *file)
{
	struct fuse_file *ff = file->private_data;

	return test_bit(FUSE_S_FAIL_IMMEDIATELY, &ff->ff_state);
}

/*
 * Determine the number of bytes of data the page contains
 */
static inline unsigned fuse_page_length(struct page *page)
{
	loff_t i_size = i_size_read(page->mapping->host);

	if (i_size > 0) {
		pgoff_t page_index = page->index;
		pgoff_t end_index = (i_size - 1) >> PAGE_CACHE_SHIFT;
		if (page_index < end_index)
			return PAGE_CACHE_SIZE;
		if (page_index == end_index)
			return ((i_size - 1) & ~PAGE_CACHE_MASK) + 1;
	}
	return 0;
}

static int fuse_prepare_write(struct fuse_conn *fc, struct file *file,
		struct page *page, loff_t pos, unsigned len)
{
	struct fuse_io_priv io = { .async = 0, .file = file };
	struct fuse_req *req;
	unsigned num_read = 0;
	unsigned page_len;
	int err;

	if (fuse_file_fail_immediately(file)) {
		unlock_page(page);
		page_cache_release(page);
		return -EIO;
	}

	if (PageUptodate(page) || (len == PAGE_CACHE_SIZE))
		return 0;

	page_len = fuse_page_length(page);
	if (!page_len) {
		zero_user(page, 0, PAGE_CACHE_SIZE);
		return 0;
	}

	/*
	 * Page writeback can extend beyond the liftime of the
	 * page-cache page, so make sure we read a properly synced
	 * page.
	 */
	fuse_wait_on_page_writeback(page->mapping->host, page->index);

	req = fuse_get_req(fc, 1);
	err = PTR_ERR(req);
	if (IS_ERR(req))
		goto out;

	/*
	 * FIXME
	 * we pick up the whole page from userspace, but only two ranges
	 * [0 .. pos] & [pos + len .. PAGE_CACHE_SIZE] is enough
	 *
	 * NB: implementing what suggested above, do not forget to handle
	 * copied != len in fuse_write_end() properly!
	 */

	req->out.page_zeroing = 1;
	req->out.argpages = 1;
	req->num_pages = 1;
	req->pages[0] = page;
	req->page_descs[0].offset = 0;
	req->page_descs[0].length = PAGE_SIZE;
	req->page_cache = 1;
	num_read = fuse_send_read(req, &io, page_offset(page), page_len, NULL);
	err = req->out.h.error;
	fuse_put_request(fc, req);
out:
	if (err) {
		unlock_page(page);
		page_cache_release(page);
	} else if (num_read != PAGE_CACHE_SIZE) {
		zero_user_segment(page, num_read, PAGE_CACHE_SIZE);
	}

	return err;
}

static int fuse_write_begin(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned flags,
			struct page **pagep, void **fsdata)
{
	pgoff_t index = pos >> PAGE_CACHE_SHIFT;
	struct fuse_conn *fc = get_fuse_conn(file->f_dentry->d_inode);

	BUG_ON(!(fc->flags & FUSE_WBCACHE));

	*pagep = grab_cache_page_write_begin(mapping, index, flags);
	if (!*pagep)
		return -ENOMEM;

	return fuse_prepare_write(fc, file, *pagep, pos, len);
}

static void fuse_write_update_size(struct inode *inode, loff_t pos)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);

	spin_lock(&fc->lock);
	fi->attr_version = ++fc->attr_version;
	if (pos > inode->i_size)
		i_size_write(inode, pos);
	spin_unlock(&fc->lock);
}

static int fuse_commit_write(struct file *file, struct page *page,
			       unsigned from, unsigned to)
{
	struct inode *inode = page->mapping->host;
	loff_t pos = ((loff_t)page->index << PAGE_CACHE_SHIFT) + to;

	if (!PageUptodate(page))
		SetPageUptodate(page);

	fuse_write_update_size(inode, pos);
	set_page_dirty(page);
	return 0;
}

static int fuse_write_end(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned copied,
			struct page *page, void *fsdata)
{
	unsigned from = pos & (PAGE_CACHE_SIZE - 1);

	fuse_commit_write(file, page, from, from+copied);

	unlock_page(page);
	page_cache_release(page);

	return copied;
}

static size_t fuse_send_write_pages(struct fuse_req *req, struct file *file,
				    struct inode *inode, loff_t pos,
				    size_t count)
{
	size_t res;
	unsigned offset;
	unsigned i;
	struct fuse_io_priv io = { .async = 0, .file = file };

	for (i = 0; i < req->num_pages; i++)
		fuse_wait_on_page_writeback(inode, req->pages[i]->index);

	res = fuse_send_write(req, &io, pos, count, NULL);

	offset = req->page_descs[0].offset;
	count = res;
	for (i = 0; i < req->num_pages; i++) {
		struct page *page = req->pages[i];

		if (!req->out.h.error && !offset && count >= PAGE_CACHE_SIZE)
			SetPageUptodate(page);

		if (count > PAGE_CACHE_SIZE - offset)
			count -= PAGE_CACHE_SIZE - offset;
		else
			count = 0;
		offset = 0;

		unlock_page(page);
		page_cache_release(page);
	}

	return res;
}

static ssize_t fuse_fill_write_pages(struct fuse_req *req,
			       struct address_space *mapping,
			       struct iov_iter *ii, loff_t pos)
{
	struct fuse_conn *fc = get_fuse_conn(mapping->host);
	unsigned offset = pos & (PAGE_CACHE_SIZE - 1);
	size_t count = 0;
	int err;

	req->in.argpages = 1;
	req->page_descs[0].offset = offset;

	do {
		size_t tmp;
		struct page *page;
		pgoff_t index = pos >> PAGE_CACHE_SHIFT;
		size_t bytes = min_t(size_t, PAGE_CACHE_SIZE - offset,
				     iov_iter_count(ii));

		bytes = min_t(size_t, bytes, fc->max_write - count);

 again:
		err = -EFAULT;
		if (iov_iter_fault_in_readable(ii, bytes))
			break;

		err = -ENOMEM;
		page = grab_cache_page_write_begin(mapping, index, 0);
		if (!page)
			break;

		if (mapping_writably_mapped(mapping))
			flush_dcache_page(page);

		pagefault_disable();
		tmp = iov_iter_copy_from_user_atomic(page, ii, offset, bytes);
		pagefault_enable();
		flush_dcache_page(page);

		mark_page_accessed(page);

		iov_iter_advance(ii, tmp);
		if (!tmp) {
			unlock_page(page);
			page_cache_release(page);
			bytes = min(bytes, iov_iter_single_seg_count(ii));
			goto again;
		}

		err = 0;
		req->pages[req->num_pages] = page;
		req->page_descs[req->num_pages].length = tmp;
		req->num_pages++;

		count += tmp;
		pos += tmp;
		offset += tmp;
		if (offset == PAGE_CACHE_SIZE)
			offset = 0;

		if (!fc->big_writes)
			break;
	} while (iov_iter_count(ii) && count < fc->max_write &&
		 req->num_pages < req->max_pages && offset == 0);

	return count > 0 ? count : err;
}

static inline unsigned fuse_wr_pages(loff_t pos, size_t len)
{
	return min_t(unsigned,
		     ((pos + len - 1) >> PAGE_CACHE_SHIFT) -
		     (pos >> PAGE_CACHE_SHIFT) + 1,
		     FUSE_MAX_PAGES_PER_REQ);
}

static ssize_t fuse_perform_write(struct file *file,
				  struct address_space *mapping,
				  struct iov_iter *ii, loff_t pos)
{
	struct inode *inode = mapping->host;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	int err = 0;
	ssize_t res = 0;

	if (is_bad_inode(inode))
		return -EIO;

	if (inode->i_size < pos + iov_iter_count(ii))
		set_bit(FUSE_I_SIZE_UNSTABLE, &fi->state);

	do {
		struct fuse_req *req;
		ssize_t count;
		unsigned nr_pages = fuse_wr_pages(pos, iov_iter_count(ii));

		req = fuse_get_req(fc, nr_pages);
		if (IS_ERR(req)) {
			err = PTR_ERR(req);
			break;
		}

		count = fuse_fill_write_pages(req, mapping, ii, pos);
		if (count <= 0) {
			err = count;
		} else {
			size_t num_written;

			num_written = fuse_send_write_pages(req, file, inode,
							    pos, count);
			err = req->out.h.error;
			if (!err) {
				res += num_written;
				pos += num_written;

				/* break out of the loop on short write */
				if (num_written != count)
					err = -EIO;
			}
		}
		fuse_put_request(fc, req);
	} while (!err && iov_iter_count(ii));

	if (res > 0)
		fuse_write_update_size(inode, pos);

	clear_bit(FUSE_I_SIZE_UNSTABLE, &fi->state);
	fuse_invalidate_attr(inode);

	return res > 0 ? res : err;
}

static ssize_t fuse_file_aio_write(struct kiocb *iocb, const struct iovec *iov,
				   unsigned long nr_segs, loff_t pos)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	size_t count = 0;
	size_t ocount = 0;
	ssize_t written = 0;
	ssize_t written_buffered = 0;
	struct inode *inode = mapping->host;
	ssize_t err;
	struct iov_iter i;
	loff_t endbyte = 0;

	if (get_fuse_conn(file->f_dentry->d_inode)->flags & FUSE_WBCACHE)
		return generic_file_aio_write(iocb, iov, nr_segs, pos);

	WARN_ON(iocb->ki_pos != pos);

	ocount = 0;
	err = generic_segment_checks(iov, &nr_segs, &ocount, VERIFY_READ);
	if (err)
		return err;

	count = ocount;
	sb_start_write(inode->i_sb);
	mutex_lock(&inode->i_mutex);

	/* We can write back this queue in page reclaim */
	current->backing_dev_info = mapping->backing_dev_info;

	err = generic_write_checks(file, &pos, &count, S_ISBLK(inode->i_mode));
	if (err)
		goto out;

	if (count == 0)
		goto out;

	err = file_remove_suid(file);
	if (err)
		goto out;

	file_update_time(file);

	if (file->f_flags & O_DIRECT) {
		written = generic_file_direct_write(iocb, iov, &nr_segs,
						    pos, &iocb->ki_pos,
						    count, ocount);
		if (written < 0 || written == count)
			goto out;

		pos += written;
		count -= written;

		iov_iter_init(&i, iov, nr_segs, count, written);
		written_buffered = fuse_perform_write(file, mapping, &i, pos);
		if (written_buffered < 0) {
			err = written_buffered;
			goto out;
		}
		endbyte = pos + written_buffered - 1;

		err = filemap_write_and_wait_range(file->f_mapping, pos,
						   endbyte);
		if (err)
			goto out;

		invalidate_mapping_pages(file->f_mapping,
					 pos >> PAGE_CACHE_SHIFT,
					 endbyte >> PAGE_CACHE_SHIFT);

		written += written_buffered;
		iocb->ki_pos = pos + written_buffered;
	} else {
		iov_iter_init(&i, iov, nr_segs, count, 0);
		written = fuse_perform_write(file, mapping, &i, pos);
		if (written >= 0)
			iocb->ki_pos = pos + written;
	}
out:
	current->backing_dev_info = NULL;
	mutex_unlock(&inode->i_mutex);
	sb_end_write(inode->i_sb);

	return written ? written : err;
}

static inline void fuse_page_descs_length_init(struct fuse_req *req,
		unsigned index, unsigned nr_pages)
{
	int i;

	for (i = index; i < index + nr_pages; i++)
		req->page_descs[i].length = PAGE_SIZE -
			req->page_descs[i].offset;
}

static inline unsigned long fuse_get_user_addr(const struct iov_iter *ii)
{
	struct iovec *iov;

	BUG_ON(!iov_iter_has_iovec(ii));
	iov = (struct iovec *)ii->data;

	return (unsigned long)iov->iov_base + ii->iov_offset;
}

static inline size_t fuse_get_frag_size(const struct iov_iter *ii,
					size_t max_size)
{
	return min(iov_iter_single_seg_count(ii), max_size);
}

static int fuse_get_user_pages(struct fuse_req *req, struct iov_iter *ii,
			       size_t *nbytesp, int write)
{
	size_t nbytes = 0;  /* # bytes already packed in req */

	/* Special case for kernel I/O: can copy directly into the buffer */
	if (segment_eq(get_fs(), KERNEL_DS)) {
		unsigned long user_addr = fuse_get_user_addr(ii);
		size_t frag_size = fuse_get_frag_size(ii, *nbytesp);

		if (write)
			req->in.args[1].value = (void *) user_addr;
		else
			req->out.args[0].value = (void *) user_addr;

		iov_iter_advance(ii, frag_size);
		*nbytesp = frag_size;
		return 0;
	}

	while (nbytes < *nbytesp && req->num_pages < req->max_pages) {
		unsigned npages;
		unsigned long user_addr = fuse_get_user_addr(ii);
		unsigned offset = user_addr & ~PAGE_MASK;
		size_t frag_size = fuse_get_frag_size(ii, *nbytesp - nbytes);
		int ret;

		unsigned n = req->max_pages - req->num_pages;
		frag_size = min_t(size_t, frag_size, n << PAGE_SHIFT);

		npages = (frag_size + offset + PAGE_SIZE - 1) >> PAGE_SHIFT;
		npages = clamp(npages, 1U, n);

		ret = get_user_pages_fast(user_addr, npages, !write,
					  &req->pages[req->num_pages]);
		if (ret < 0)
			return ret;

		npages = ret;
		frag_size = min_t(size_t, frag_size,
				  (npages << PAGE_SHIFT) - offset);
		iov_iter_advance(ii, frag_size);

		req->page_descs[req->num_pages].offset = offset;
		fuse_page_descs_length_init(req, req->num_pages, npages);

		req->num_pages += npages;
		req->page_descs[req->num_pages - 1].length -=
			(npages << PAGE_SHIFT) - offset - frag_size;

		nbytes += frag_size;
	}

	if (write)
		req->in.argpages = 1;
	else
		req->out.argpages = 1;

	*nbytesp = nbytes;

	return 0;
}

static inline int fuse_iter_npages(const struct iov_iter *ii_p)
{
	struct iov_iter ii = *ii_p;
	int npages = 0;

	while (iov_iter_count(&ii) && npages < FUSE_MAX_PAGES_PER_REQ) {
		unsigned long user_addr = fuse_get_user_addr(&ii);
		unsigned offset = user_addr & ~PAGE_MASK;
		size_t frag_size = iov_iter_single_seg_count(&ii);

		npages += (frag_size + offset + PAGE_SIZE - 1) >> PAGE_SHIFT;
		iov_iter_advance(&ii, frag_size);
	}

	return min(npages, FUSE_MAX_PAGES_PER_REQ);
}

ssize_t fuse_direct_io(struct fuse_io_priv *io, const struct iovec *iov,
		       unsigned long nr_segs, size_t count, loff_t *ppos,
		       int flags)
{
	int write = flags & FUSE_DIO_WRITE;
	int cuse = flags & FUSE_DIO_CUSE;
	struct file *file = io->file;
	struct fuse_file *ff = file->private_data;
	struct fuse_conn *fc = ff->fc;
	size_t nmax = write ? fc->max_write : fc->max_read;
	loff_t pos = *ppos;
	ssize_t res = 0;
	struct fuse_req *req;
	struct iov_iter ii;

	virtinfo_notifier_call(VITYPE_IO, VIRTINFO_IO_PREPARE, NULL);

	iov_iter_init(&ii, iov, nr_segs, count, 0);

	if (io->async)
		req = fuse_get_req_for_background(fc, fuse_iter_npages(&ii));
	else
		req = fuse_get_req(fc, fuse_iter_npages(&ii));
	if (IS_ERR(req))
		return PTR_ERR(req);

	while (count) {
		size_t nres;
		fl_owner_t owner = current->files;
		size_t nbytes = min(count, nmax);
		int err = fuse_get_user_pages(req, &ii, &nbytes, write);
		if (err) {
			res = err;
			break;
		}

		if (!cuse)
			fuse_wait_on_writeback(file->f_mapping->host, pos, nbytes);

		if (write) {
			nres = fuse_send_write(req, io, pos, nbytes, owner);
			task_io_account_write(nbytes);
		} else {
			nres = fuse_send_read(req, io, pos, nbytes, owner);
			task_io_account_read(nbytes);
		}

		if (!io->async)
			fuse_release_user_pages(req, !write);
		if (req->out.h.error) {
			if (!res)
				res = req->out.h.error;
			break;
		} else if (nres > nbytes) {
			res = -EIO;
			break;
		}
		count -= nres;
		res += nres;
		pos += nres;
		if (nres != nbytes)
			break;
		if (count) {
			fuse_put_request(fc, req);
			if (io->async)
				req = fuse_get_req_for_background(fc,
					fuse_iter_npages(&ii));
			else
				req = fuse_get_req(fc, fuse_iter_npages(&ii));
			if (IS_ERR(req))
				break;
		}
	}
	if (!IS_ERR(req))
		fuse_put_request(fc, req);
	if (res > 0)
		*ppos = pos;

	return res;
}
EXPORT_SYMBOL_GPL(fuse_direct_io);

static ssize_t __fuse_direct_read(struct fuse_io_priv *io,
				  const struct iovec *iov,
				  unsigned long nr_segs, loff_t *ppos,
				  size_t count)
{
	ssize_t res;
	struct file *file = io->file;
	struct inode *inode = file->f_path.dentry->d_inode;

	if (is_bad_inode(inode))
		return -EIO;

	res = fuse_direct_io(io, iov, nr_segs, count, ppos, 0);

	fuse_invalidate_attr(inode);

	return res;
}

static ssize_t fuse_direct_read(struct file *file, char __user *buf,
				     size_t count, loff_t *ppos)
{
	struct fuse_io_priv io = { .async = 0, .file = file };
	struct iovec iov = { .iov_base = buf, .iov_len = count };
	return __fuse_direct_read(&io, &iov, 1, ppos, count);
}

static ssize_t __fuse_direct_write(struct fuse_io_priv *io,
				   const struct iovec *iov,
				   unsigned long nr_segs, loff_t *ppos)
{
	struct file *file = io->file;
	struct inode *inode = file->f_path.dentry->d_inode;
	size_t count = iov_length(iov, nr_segs);
	ssize_t res;

	res = generic_write_checks(file, ppos, &count, 0);
	if (!res)
		res = fuse_direct_io(io, iov, nr_segs, count, ppos,
				     FUSE_DIO_WRITE);

	fuse_invalidate_attr(inode);

	return res;
}

static ssize_t fuse_direct_write(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	struct iovec iov = { .iov_base = (void __user *)buf, .iov_len = count };
	struct inode *inode = file->f_path.dentry->d_inode;
	ssize_t res;
	struct fuse_io_priv io = { .async = 0, .file = file };

	if (is_bad_inode(inode))
		return -EIO;

	/* Don't allow parallel writes to the same file */
	mutex_lock(&inode->i_mutex);
	res = __fuse_direct_write(&io, &iov, 1, ppos);
	if (res > 0)
		fuse_write_update_size(inode, *ppos);
	mutex_unlock(&inode->i_mutex);

	return res;
}

static void fuse_writepage_free(struct fuse_conn *fc, struct fuse_req *req)
{
	int i;

	for (i = 0; i < req->num_pages; i++)
		__free_page(req->pages[i]);

	if (!(fc->flags & FUSE_WBCACHE) && !fc->close_wait)
		fuse_file_put(req->ff, false);
}

static void fuse_writepage_finish(struct fuse_conn *fc, struct fuse_req *req)
{
	struct inode *inode = req->inode;
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct backing_dev_info *bdi = inode->i_mapping->backing_dev_info;
	int i;

	list_del(&req->writepages_entry);
	if ((fc->flags & FUSE_WBCACHE) || fc->close_wait)
		__fuse_file_put(req->ff);
	for (i = 0; i < req->num_pages; i++) {
		dec_bdi_stat(bdi, BDI_WRITEBACK);
		dec_zone_page_state(req->pages[0], NR_WRITEBACK_TEMP);
	}
	bdi_writeout_inc(bdi);
	wake_up(&fi->page_waitq);
}

/* Called under fc->lock, may release and reacquire it */
static void fuse_send_writepage(struct fuse_conn *fc, struct fuse_req *req)
__releases(&fc->lock)
__acquires(&fc->lock)
{
	struct fuse_inode *fi = get_fuse_inode(req->inode);
	loff_t size = i_size_read(req->inode);
	struct fuse_write_in *inarg = &req->misc.write.in;
	__u64 data_size = req->num_pages * PAGE_CACHE_SIZE;

	if (!fc->connected)
		goto out_free;

	if (inarg->offset + data_size <= size) {
		inarg->size = data_size;
	} else if (inarg->offset < size) {
		inarg->size = size - inarg->offset;
	} else {
		/* Got truncated off completely */
		goto out_free;
	}

	req->in.args[1].size = inarg->size;
	fi->writectr++;
	fuse_request_send_background_locked(fc, req);
	return;

 out_free:
	fuse_writepage_finish(fc, req);
	spin_unlock(&fc->lock);
	fuse_writepage_free(fc, req);
	fuse_put_request(fc, req);
	spin_lock(&fc->lock);
}

/*
 * If fi->writectr is positive (no truncate or fsync going on) send
 * all queued writepage requests.
 *
 * Called with fc->lock
 */
void fuse_flush_writepages(struct inode *inode)
__releases(&fc->lock)
__acquires(&fc->lock)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_req *req;

	while (fi->writectr >= 0 && !list_empty(&fi->queued_writes)) {
		req = list_entry(fi->queued_writes.next, struct fuse_req, list);
		list_del_init(&req->list);
		fuse_send_writepage(fc, req);
	}
}

static void fuse_writepage_end(struct fuse_conn *fc, struct fuse_req *req)
{
	struct inode *inode = req->inode;
	struct fuse_inode *fi = get_fuse_inode(inode);

	mapping_set_error(inode->i_mapping, req->out.h.error);
	spin_lock(&fc->lock);
	fi->writectr--;
	fuse_writepage_finish(fc, req);
	spin_unlock(&fc->lock);
	fuse_writepage_free(fc, req);
}

static struct fuse_file *fuse_write_file(struct fuse_conn *fc, struct fuse_inode *fi)
{
	struct fuse_file *ff = NULL;

	spin_lock(&fc->lock);
	if (!list_empty(&fi->write_files)) {
		ff = list_entry(fi->write_files.next, struct fuse_file, write_entry);
		fuse_file_get(ff);
	}
	spin_unlock(&fc->lock);

	return ff;
}

static int fuse_writepage_locked(struct page *page, struct writeback_control *wbc)
{
	struct address_space *mapping = page->mapping;
	struct inode *inode = mapping->host;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_req *req;
	struct fuse_file *ff;
	struct page *tmp_page;

	while (fuse_page_is_writeback(inode, page->index)) {
		if (wbc->sync_mode != WB_SYNC_ALL) {
			redirty_page_for_writepage(wbc, page);
			return 0;
		}
		fuse_wait_on_page_writeback(inode, page->index);
	}

	if (test_set_page_writeback(page))
		BUG();

	req = fuse_request_alloc_nofs(1);
	if (!req)
		goto err;

	req->background = 1; /* writeback always goes to bg_queue */
	tmp_page = alloc_page(GFP_NOFS | __GFP_HIGHMEM);
	if (!tmp_page)
		goto err_free;

	ff = fuse_write_file(fc, fi);
	if (!ff)
		goto err_nofile;

	req->ff = ff;
	fuse_write_fill(req, ff, page_offset(page), 0);
	fuse_account_request(fc, PAGE_CACHE_SIZE);

	copy_highpage(tmp_page, page);
	req->misc.write.in.write_flags |= FUSE_WRITE_CACHE;
	req->in.argpages = 1;
	req->num_pages = 1;
	req->pages[0] = tmp_page;
	req->page_descs[0].offset = 0;
	req->page_descs[0].length = PAGE_SIZE;
	req->end = fuse_writepage_end;
	req->inode = inode;

	inc_bdi_stat(mapping->backing_dev_info, BDI_WRITEBACK);
	inc_zone_page_state(tmp_page, NR_WRITEBACK_TEMP);

	spin_lock(&fc->lock);
	list_add(&req->writepages_entry, &fi->writepages);
	list_add_tail(&req->list, &fi->queued_writes);
	fuse_flush_writepages(inode);
	spin_unlock(&fc->lock);

	end_page_writeback(page);

	return 0;

err_nofile:
	printk("FUSE: page dirtied on dead file\n");
	__free_page(tmp_page);
err_free:
	fuse_request_free(req);
err:
	end_page_writeback(page);
	return -ENOMEM;
}

static int fuse_writepage(struct page *page, struct writeback_control *wbc)
{
	int err;

	err = fuse_writepage_locked(page, wbc);
	unlock_page(page);

	return err;
}

static void fuse_end_writeback(int npages, struct page ** orig_pages)
{
	int i;

	for (i = 0; i < npages; i++)
		end_page_writeback(orig_pages[i]);
}

static int fuse_send_writepages(struct fuse_fill_data *data)
{
	int i, all_ok = 1;
	struct fuse_req *req = data->req;
	struct inode *inode = data->inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	loff_t off = -1;
	int npages = req->num_pages;
	struct page * orig_pages[npages];

	/* we can acquire ff here because we do have locked pages here! */
	if (!data->ff)
		data->ff = fuse_write_file(fc, fi);

	if (!data->ff) {
		printk("FUSE: pages dirtied on dead file\n");
		fuse_end_writeback(npages, req->pages);
		return -EIO;
	}

	if (test_bit(FUSE_S_FAIL_IMMEDIATELY, &data->ff->ff_state)) {
		for (i = 0; i < npages; i++) {
			struct page *page = req->pages[i];
			req->pages[i] = NULL;
			SetPageError(page);
			end_page_writeback(page);
		}
		fuse_release_ff(inode, data->ff);
		data->ff = NULL;
		fuse_put_request(fc, req);
		return 0;
	}

	for (i = 0; i < npages; i++) {
		struct page *page = req->pages[i];
		struct address_space *mapping = page->mapping;
		struct page *tmp_page;

		tmp_page = alloc_page(GFP_NOFS | __GFP_HIGHMEM);
		if (tmp_page) {
			copy_highpage(tmp_page, page);
			inc_bdi_stat(mapping->backing_dev_info, BDI_WRITEBACK);
			inc_zone_page_state(tmp_page, NR_WRITEBACK_TEMP);
		} else
			all_ok = 0;
		orig_pages[i] = page;
		req->pages[i] = tmp_page;
		if (i == 0)
			off = page_offset(page);
	}

	if (!all_ok) {
		/* Undo everything, release temporary pages. We could do this in main
		 * loop, but why to mess up main loop for a case which never happens
		 * in this life.
		 */
		for (i = 0; i < npages; i++) {
			struct page * page = orig_pages[i];
			struct page *tmp_page = req->pages[i];
			if (tmp_page) {
				dec_bdi_stat(page->mapping->backing_dev_info, BDI_WRITEBACK);
				dec_zone_page_state(tmp_page, NR_WRITEBACK_TEMP);
				__free_page(tmp_page);
				req->pages[i] = NULL;
			}
		}
		fuse_end_writeback(npages, orig_pages);
		fuse_release_ff(inode, data->ff);
		data->ff = NULL;
		return -ENOMEM;
	}

	req->ff = fuse_file_get(data->ff);
	fuse_write_fill(req, data->ff, off, 0);
	fuse_account_request(fc, npages << PAGE_CACHE_SHIFT);

	req->misc.write.in.write_flags |= FUSE_WRITE_CACHE;
	req->in.argpages = 1;
	req->background = 1; /* writeback always goes to bg_queue */
	fuse_page_descs_length_init(req, 0, req->num_pages);
	req->page_descs[0].offset = 0;
	req->end = fuse_writepage_end;
	req->inode = data->inode;

	spin_lock(&fc->lock);
	list_add(&req->writepages_entry, &fi->writepages);
	list_add_tail(&req->list, &fi->queued_writes);
	fuse_flush_writepages(data->inode);
	spin_unlock(&fc->lock);

	fuse_end_writeback(npages, orig_pages);

	fuse_release_ff(inode, data->ff);
	data->ff = NULL;
	return 0;
}

/*
 * Returns true if and only if fuse connection is blocked and there is
 * no file invalidation in progress.
 */
static inline bool fuse_blocked_for_wb(struct inode *inode)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	bool blocked = true;

	if (!fc->blocked)
		return false;

	spin_lock(&fc->lock);
	if (!list_empty(&fi->rw_files)) {
		struct fuse_file *ff = list_entry(fi->rw_files.next,
						  struct fuse_file, rw_entry);
		if (test_bit(FUSE_S_FAIL_IMMEDIATELY, &ff->ff_state))
			blocked = false;
	}
	spin_unlock(&fc->lock);

	return blocked;
}

static int fuse_writepages_fill(struct page *page,
		struct writeback_control *wbc, void *_data)
{
	struct fuse_fill_data *data = _data;
	struct fuse_req *req = data->req;
	struct inode *inode = data->inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	int check_for_blocked = 0;

	while (fuse_page_is_writeback(inode, page->index)) {
		if (wbc->sync_mode != WB_SYNC_ALL) {
			redirty_page_for_writepage(wbc, page);
			unlock_page(page);
			return 0;
		}
		fuse_wait_on_page_writeback(inode, page->index);
	}

	if (req->num_pages &&
	    (req->num_pages == FUSE_MAX_PAGES_PER_REQ ||
	     (req->num_pages + 1) * PAGE_CACHE_SIZE > fc->max_write ||
	     req->pages[req->num_pages - 1]->index + 1 != page->index)) {
		int err;

		if (wbc->nonblocking && fc->blocked) {
			BUG_ON(wbc->sync_mode == WB_SYNC_ALL);
			redirty_page_for_writepage(wbc, page);
			unlock_page(page);
			return 0;
		}

		err = fuse_send_writepages(data);
		if (err) {
			unlock_page(page);
			return err;
		}

		data->req = req = fuse_request_alloc_nofs(FUSE_MAX_PAGES_PER_REQ);
		if (req == NULL) {
			unlock_page(page);
			return -ENOMEM;
		}

		check_for_blocked = 1;
	}

	req->pages[req->num_pages] = page;
	req->num_pages++;

	if (test_set_page_writeback(page))
		BUG();

	unlock_page(page);

	if (!wbc->nonblocking && check_for_blocked)
		wait_event(fc->blocked_waitq, !fuse_blocked_for_wb(inode));

	return 0;
}

static int fuse_dummy_writepage(struct page *page,
				struct writeback_control *wbc,
				void *data)
{
	unlock_page(page);
	return 0;
}

static int fuse_writepages(struct address_space *mapping, struct writeback_control *wbc)
{
	struct inode *inode = mapping->host;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_fill_data data;
	int err;

	if (!(fc->flags & FUSE_WBCACHE))
		return generic_writepages(mapping, wbc);

	err = -EIO;
	if (is_bad_inode(inode))
		goto out;

	if (wbc->nonblocking) {
		if (fc->blocked)
			return 0;
	}

	/*
	 * We use fuse_blocked_for_wb() instead of just fc->blocked to avoid
	 * deadlock when we are called from fuse_invalidate_files() in case
	 * of single-threaded fused.
	 */
	if (wbc->sync_mode != WB_SYNC_NONE)
		wait_event(fc->blocked_waitq, !fuse_blocked_for_wb(inode));

	/* More than optimization: writeback pages to /dev/null; fused would
	 * drop our FUSE_WRITE requests anyway, but it will be blocked while
	 * sending NOTIFY_INVAL_FILES until we return!
	 *
	 * NB: We can't wait till fuse_send_writepages() because
	 * fuse_writepages_fill() would possibly deadlock on
	 * fuse_page_is_writeback().
	 */
 	data.ff = fuse_write_file(fc, get_fuse_inode(inode));
	if (data.ff && test_bit(FUSE_S_FAIL_IMMEDIATELY, &data.ff->ff_state)) {
		err = write_cache_pages(mapping, wbc, fuse_dummy_writepage,
					mapping);
		fuse_release_ff(inode, data.ff);
		data.ff = NULL;
		goto out_put;
	}
	if (data.ff) {
		fuse_release_ff(inode, data.ff);
		data.ff = NULL;
	}

	data.inode = inode;
	data.req = fuse_request_alloc_nofs(FUSE_MAX_PAGES_PER_REQ);
	err = -ENOMEM;
	if (!data.req)
		goto out_put;

	err = write_cache_pages(mapping, wbc, fuse_writepages_fill, &data);
	if (data.req) {
		if (!err && data.req->num_pages) {
			err = fuse_send_writepages(&data);
			if (err)
				fuse_put_request(fc, data.req);
		} else
			fuse_put_request(fc, data.req);
	}
out_put:
	BUG_ON(data.ff);
out:
	return err;
}

static int fuse_launder_page(struct page *page)
{
	int err = 0;
	if (clear_page_dirty_for_io(page)) {
		struct inode *inode = page->mapping->host;
		struct writeback_control wbc = {
			.sync_mode = WB_SYNC_ALL,
		};
		err = fuse_writepage_locked(page, &wbc);
		if (!err)
			fuse_wait_on_page_writeback(inode, page->index);
	}
	return err;
}

/*
 * Write back dirty pages now, because there may not be any suitable
 * open files later
 */
static void fuse_vma_close(struct vm_area_struct *vma)
{
	struct file *file = vma->vm_file;
	struct fuse_file *ff = file->private_data;

	if (!(ff->fc->flags & FUSE_WBCACHE))
		filemap_write_and_wait(file->f_mapping);
}

/*
 * Wait for writeback against this page to complete before allowing it
 * to be marked dirty again, and hence written back again, possibly
 * before the previous writepage completed.
 *
 * Block here, instead of in ->writepage(), so that the userspace fs
 * can only block processes actually operating on the filesystem.
 *
 * Otherwise unprivileged userspace fs would be able to block
 * unrelated:
 *
 * - page migration
 * - sync(2)
 * - try_to_free_pages() with order > PAGE_ALLOC_COSTLY_ORDER
 */
static int fuse_page_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct page *page = vmf->page;
	/*
	 * Don't use page->mapping as it may become NULL from a
	 * concurrent truncate.
	 */
	struct inode *inode = vma->vm_file->f_mapping->host;

	if (fuse_file_fail_immediately(vma->vm_file))
		return -EIO;

	fuse_wait_on_page_writeback(inode, page->index);
	return 0;
}

static const struct vm_operations_struct fuse_file_vm_ops = {
	.close		= fuse_vma_close,
	.fault		= filemap_fault,
	.page_mkwrite	= fuse_page_mkwrite,
};

static int fuse_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	if ((vma->vm_flags & VM_SHARED) && (vma->vm_flags & VM_MAYWRITE))
		/*
		 * file may be written through mmap, so chain it onto the
		 * inodes's write_file list
		 */
		fuse_link_write_file(file);

	file_accessed(file);
	vma->vm_ops = &fuse_file_vm_ops;
	return 0;
}

static int fuse_direct_mmap(struct file *file, struct vm_area_struct *vma)
{
	/* Can't provide the coherency needed for MAP_SHARED */
	if (vma->vm_flags & VM_MAYSHARE)
		return -ENODEV;

	invalidate_inode_pages2(file->f_mapping);

	return generic_file_mmap(file, vma);
}

static int convert_fuse_file_lock(const struct fuse_file_lock *ffl,
				  struct file_lock *fl)
{
	switch (ffl->type) {
	case F_UNLCK:
		break;

	case F_RDLCK:
	case F_WRLCK:
		if (ffl->start > OFFSET_MAX || ffl->end > OFFSET_MAX ||
		    ffl->end < ffl->start)
			return -EIO;

		fl->fl_start = ffl->start;
		fl->fl_end = ffl->end;
		fl->fl_pid = ffl->pid;
		break;

	default:
		return -EIO;
	}
	fl->fl_type = ffl->type;
	return 0;
}

static void fuse_lk_fill(struct fuse_req *req, struct file *file,
			 const struct file_lock *fl, int opcode, pid_t pid,
			 int flock)
{
	struct inode *inode = file->f_path.dentry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_file *ff = file->private_data;
	struct fuse_lk_in *arg = &req->misc.lk_in;

	arg->fh = ff->fh;
	arg->owner = fuse_lock_owner_id(fc, fl->fl_owner);
	arg->lk.start = fl->fl_start;
	arg->lk.end = fl->fl_end;
	arg->lk.type = fl->fl_type;
	arg->lk.pid = pid;
	if (flock)
		arg->lk_flags |= FUSE_LK_FLOCK;
	req->in.h.opcode = opcode;
	req->in.h.nodeid = get_node_id(inode);
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(*arg);
	req->in.args[0].value = arg;
}

static int fuse_getlk(struct file *file, struct file_lock *fl)
{
	struct inode *inode = file->f_path.dentry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	struct fuse_lk_out outarg;
	int err;

	req = fuse_get_req_nopages(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	fuse_lk_fill(req, file, fl, FUSE_GETLK, 0, 0);
	req->out.numargs = 1;
	req->out.args[0].size = sizeof(outarg);
	req->out.args[0].value = &outarg;
	fuse_request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (!err)
		err = convert_fuse_file_lock(&outarg.lk, fl);

	return err;
}

static int fuse_setlk(struct file *file, struct file_lock *fl, int flock)
{
	struct inode *inode = file->f_path.dentry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	int opcode = (fl->fl_flags & FL_SLEEP) ? FUSE_SETLKW : FUSE_SETLK;
	pid_t pid = fl->fl_type != F_UNLCK ? current->tgid : 0;
	int err;

	if (fl->fl_lmops && fl->fl_lmops->fl_grant) {
		/* NLM needs asynchronous locks, which we don't support yet */
		return -ENOLCK;
	}

	/* Unlock on close is handled by the flush method */
	if (fl->fl_flags & FL_CLOSE)
		return 0;

	req = fuse_get_req_nopages(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	fuse_lk_fill(req, file, fl, opcode, pid, flock);
	fuse_request_send(fc, req);
	err = req->out.h.error;
	/* locking is restartable */
	if (err == -EINTR)
		err = -ERESTARTSYS;
	fuse_put_request(fc, req);
	return err;
}

static int fuse_file_lock(struct file *file, int cmd, struct file_lock *fl)
{
	struct inode *inode = file->f_path.dentry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	int err;

	if (cmd == F_CANCELLK) {
		err = 0;
	} else if (cmd == F_GETLK) {
		if (fc->no_lock) {
			posix_test_lock(file, fl);
			err = 0;
		} else
			err = fuse_getlk(file, fl);
	} else {
		if (fc->no_lock)
			err = posix_lock_file(file, fl, NULL);
		else
			err = fuse_setlk(file, fl, 0);
	}
	return err;
}

static int fuse_file_flock(struct file *file, int cmd, struct file_lock *fl)
{
	struct inode *inode = file->f_path.dentry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	int err;

	if (fc->no_lock) {
		err = flock_lock_file_wait(file, fl);
	} else {
		/* emulate flock with POSIX locks */
		fl->fl_owner = (fl_owner_t) file;
		err = fuse_setlk(file, fl, 1);
	}

	return err;
}

static sector_t fuse_bmap(struct address_space *mapping, sector_t block)
{
	struct inode *inode = mapping->host;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	struct fuse_bmap_in inarg;
	struct fuse_bmap_out outarg;
	int err;

	if (!inode->i_sb->s_bdev || fc->no_bmap)
		return 0;

	req = fuse_get_req_nopages(fc);
	if (IS_ERR(req))
		return 0;

	memset(&inarg, 0, sizeof(inarg));
	inarg.block = block;
	inarg.blocksize = inode->i_sb->s_blocksize;
	req->in.h.opcode = FUSE_BMAP;
	req->in.h.nodeid = get_node_id(inode);
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->out.numargs = 1;
	req->out.args[0].size = sizeof(outarg);
	req->out.args[0].value = &outarg;
	fuse_request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (err == -ENOSYS)
		fc->no_bmap = 1;

	return err ? 0 : outarg.block;
}

static loff_t fuse_file_llseek(struct file *file, loff_t offset, int origin)
{
	loff_t retval;
	struct inode *inode = file->f_path.dentry->d_inode;

	mutex_lock(&inode->i_mutex);
	switch (origin) {
	case SEEK_END:
		retval = fuse_update_attributes(inode, NULL, file, NULL);
		if (retval)
			goto exit;
		offset += i_size_read(inode);
		break;
	case SEEK_CUR:
		offset += file->f_pos;
	}
	retval = -EINVAL;
	if (offset >= 0 && offset <= inode->i_sb->s_maxbytes) {
		if (offset != file->f_pos) {
			file->f_pos = offset;
			file->f_version = 0;
		}
		retval = offset;
	}
exit:
	mutex_unlock(&inode->i_mutex);
	return retval;
}

static int fuse_ioctl_copy_user(struct page **pages, struct iovec *iov,
			unsigned int nr_segs, size_t bytes, bool to_user)
{
	struct iov_iter ii;
	int page_idx = 0;

	if (!bytes)
		return 0;

	iov_iter_init(&ii, iov, nr_segs, bytes, 0);

	while (iov_iter_count(&ii)) {
		struct page *page = pages[page_idx++];
		size_t todo = min_t(size_t, PAGE_SIZE, iov_iter_count(&ii));
		void *kaddr, *map;

		kaddr = map = kmap(page);

		while (todo) {
			struct iovec *iiov = (struct iovec *)ii.data;
			char __user *uaddr = iiov->iov_base + ii.iov_offset;
			size_t iov_len = iiov->iov_len - ii.iov_offset;
			size_t copy = min(todo, iov_len);
			size_t left;

			if (!to_user)
				left = copy_from_user(kaddr, uaddr, copy);
			else
				left = copy_to_user(uaddr, kaddr, copy);

			if (unlikely(left))
				return -EFAULT;

			iov_iter_advance(&ii, copy);
			todo -= copy;
			kaddr += copy;
		}

		kunmap(page);
	}

	return 0;
}

/*
 * For ioctls, there is no generic way to determine how much memory
 * needs to be read and/or written.  Furthermore, ioctls are allowed
 * to dereference the passed pointer, so the parameter requires deep
 * copying but FUSE has no idea whatsoever about what to copy in or
 * out.
 *
 * This is solved by allowing FUSE server to retry ioctl with
 * necessary in/out iovecs.  Let's assume the ioctl implementation
 * needs to read in the following structure.
 *
 * struct a {
 *	char	*buf;
 *	size_t	buflen;
 * }
 *
 * On the first callout to FUSE server, inarg->in_size and
 * inarg->out_size will be NULL; then, the server completes the ioctl
 * with FUSE_IOCTL_RETRY set in out->flags, out->in_iovs set to 1 and
 * the actual iov array to
 *
 * { { .iov_base = inarg.arg,	.iov_len = sizeof(struct a) } }
 *
 * which tells FUSE to copy in the requested area and retry the ioctl.
 * On the second round, the server has access to the structure and
 * from that it can tell what to look for next, so on the invocation,
 * it sets FUSE_IOCTL_RETRY, out->in_iovs to 2 and iov array to
 *
 * { { .iov_base = inarg.arg,	.iov_len = sizeof(struct a)	},
 *   { .iov_base = a.buf,	.iov_len = a.buflen		} }
 *
 * FUSE will copy both struct a and the pointed buffer from the
 * process doing the ioctl and retry ioctl with both struct a and the
 * buffer.
 *
 * This time, FUSE server has everything it needs and completes ioctl
 * without FUSE_IOCTL_RETRY which finishes the ioctl call.
 *
 * Copying data out works the same way.
 *
 * Note that if FUSE_IOCTL_UNRESTRICTED is clear, the kernel
 * automatically initializes in and out iovs by decoding @cmd with
 * _IOC_* macros and the server is not allowed to request RETRY.  This
 * limits ioctl data transfers to well-formed ioctls and is the forced
 * behavior for all FUSE servers.
 */
long fuse_do_ioctl(struct file *file, unsigned int cmd, unsigned long arg,
		   unsigned int flags)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_conn *fc = ff->fc;
	struct fuse_ioctl_in inarg = {
		.fh = ff->fh,
		.cmd = cmd,
		.arg = arg,
		.flags = flags
	};
	struct fuse_ioctl_out outarg;
	struct fuse_req *req = NULL;
	struct page **pages = NULL;
	struct page *iov_page = NULL;
	struct iovec *in_iov = NULL, *out_iov = NULL;
	unsigned int in_iovs = 0, out_iovs = 0, num_pages = 0, max_pages;
	size_t in_size, out_size, transferred;
	int err;

	/* assume all the iovs returned by client always fits in a page */
	BUILD_BUG_ON(sizeof(struct iovec) * FUSE_IOCTL_MAX_IOV > PAGE_SIZE);

	err = -ENOMEM;
	pages = kzalloc(sizeof(pages[0]) * FUSE_MAX_PAGES_PER_REQ, GFP_KERNEL);
	iov_page = alloc_page(GFP_KERNEL);
	if (!pages || !iov_page)
		goto out;

	/*
	 * If restricted, initialize IO parameters as encoded in @cmd.
	 * RETRY from server is not allowed.
	 */
	if (!(flags & FUSE_IOCTL_UNRESTRICTED)) {
		struct iovec *iov = page_address(iov_page);

		iov->iov_base = (void __user *)arg;
		iov->iov_len = _IOC_SIZE(cmd);

		if (_IOC_DIR(cmd) & _IOC_WRITE) {
			in_iov = iov;
			in_iovs = 1;
		}

		if (_IOC_DIR(cmd) & _IOC_READ) {
			out_iov = iov;
			out_iovs = 1;
		}
	}

 retry:
	inarg.in_size = in_size = iov_length(in_iov, in_iovs);
	inarg.out_size = out_size = iov_length(out_iov, out_iovs);

	/*
	 * Out data can be used either for actual out data or iovs,
	 * make sure there always is at least one page.
	 */
	out_size = max_t(size_t, out_size, PAGE_SIZE);
	max_pages = DIV_ROUND_UP(max(in_size, out_size), PAGE_SIZE);

	/* make sure there are enough buffer pages and init request with them */
	err = -ENOMEM;
	if (max_pages > FUSE_MAX_PAGES_PER_REQ)
		goto out;
	while (num_pages < max_pages) {
		pages[num_pages] = alloc_page(GFP_KERNEL | __GFP_HIGHMEM);
		if (!pages[num_pages])
			goto out;
		num_pages++;
	}

	req = fuse_get_req(fc, num_pages);
	if (IS_ERR(req)) {
		err = PTR_ERR(req);
		req = NULL;
		goto out;
	}
	memcpy(req->pages, pages, sizeof(req->pages[0]) * num_pages);
	req->num_pages = num_pages;
	fuse_page_descs_length_init(req, 0, req->num_pages);

	/* okay, let's send it to the client */
	req->in.h.opcode = FUSE_IOCTL;
	req->in.h.nodeid = ff->nodeid;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	if (in_size) {
		req->in.numargs++;
		req->in.args[1].size = in_size;
		req->in.argpages = 1;

		err = fuse_ioctl_copy_user(pages, in_iov, in_iovs, in_size,
					   false);
		if (err)
			goto out;
	}

	req->out.numargs = 2;
	req->out.args[0].size = sizeof(outarg);
	req->out.args[0].value = &outarg;
	req->out.args[1].size = out_size;
	req->out.argpages = 1;
	req->out.argvar = 1;

	fuse_request_send(fc, req);
	err = req->out.h.error;
	transferred = req->out.args[1].size;
	fuse_put_request(fc, req);
	req = NULL;
	if (err)
		goto out;

	/* did it ask for retry? */
	if (outarg.flags & FUSE_IOCTL_RETRY) {
		char *vaddr;

		/* no retry if in restricted mode */
		err = -EIO;
		if (!(flags & FUSE_IOCTL_UNRESTRICTED))
			goto out;

		in_iovs = outarg.in_iovs;
		out_iovs = outarg.out_iovs;

		/*
		 * Make sure things are in boundary, separate checks
		 * are to protect against overflow.
		 */
		err = -ENOMEM;
		if (in_iovs > FUSE_IOCTL_MAX_IOV ||
		    out_iovs > FUSE_IOCTL_MAX_IOV ||
		    in_iovs + out_iovs > FUSE_IOCTL_MAX_IOV)
			goto out;

		err = -EIO;
		if ((in_iovs + out_iovs) * sizeof(struct iovec) != transferred)
			goto out;

		/* okay, copy in iovs and retry */
		vaddr = kmap_atomic(pages[0], KM_USER0);
		memcpy(page_address(iov_page), vaddr, transferred);
		kunmap_atomic(vaddr, KM_USER0);

		in_iov = page_address(iov_page);
		out_iov = in_iov + in_iovs;

		goto retry;
	}

	err = -EIO;
	if (transferred > inarg.out_size)
		goto out;

	err = fuse_ioctl_copy_user(pages, out_iov, out_iovs, transferred, true);
 out:
	if (req)
		fuse_put_request(fc, req);
	if (iov_page)
		__free_page(iov_page);
	while (num_pages)
		__free_page(pages[--num_pages]);
	kfree(pages);

	return err ? err : outarg.result;
}
EXPORT_SYMBOL_GPL(fuse_do_ioctl);

static long fuse_file_ioctl_common(struct file *file, unsigned int cmd,
				   unsigned long arg, unsigned int flags)
{
	struct inode *inode = file->f_dentry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);

	if (!fuse_allow_current_process(fc))
		return -EACCES;

	if (is_bad_inode(inode))
		return -EIO;

	return fuse_do_ioctl(file, cmd, arg, flags);
}

static long fuse_file_ioctl(struct file *file, unsigned int cmd,
			    unsigned long arg)
{
	return fuse_file_ioctl_common(file, cmd, arg, 0);
}

static long fuse_file_compat_ioctl(struct file *file, unsigned int cmd,
				   unsigned long arg)
{
	return fuse_file_ioctl_common(file, cmd, arg, FUSE_IOCTL_COMPAT);
}

/*
 * All files which have been polled are linked to RB tree
 * fuse_conn->polled_files which is indexed by kh.  Walk the tree and
 * find the matching one.
 */
static struct rb_node **fuse_find_polled_node(struct fuse_conn *fc, u64 kh,
					      struct rb_node **parent_out)
{
	struct rb_node **link = &fc->polled_files.rb_node;
	struct rb_node *last = NULL;

	while (*link) {
		struct fuse_file *ff;

		last = *link;
		ff = rb_entry(last, struct fuse_file, polled_node);

		if (kh < ff->kh)
			link = &last->rb_left;
		else if (kh > ff->kh)
			link = &last->rb_right;
		else
			return link;
	}

	if (parent_out)
		*parent_out = last;
	return link;
}

/*
 * The file is about to be polled.  Make sure it's on the polled_files
 * RB tree.  Note that files once added to the polled_files tree are
 * not removed before the file is released.  This is because a file
 * polled once is likely to be polled again.
 */
static void fuse_register_polled_file(struct fuse_conn *fc,
				      struct fuse_file *ff)
{
	spin_lock(&fc->lock);
	if (RB_EMPTY_NODE(&ff->polled_node)) {
		struct rb_node **link, *parent;

		link = fuse_find_polled_node(fc, ff->kh, &parent);
		BUG_ON(*link);
		rb_link_node(&ff->polled_node, parent, link);
		rb_insert_color(&ff->polled_node, &fc->polled_files);
	}
	spin_unlock(&fc->lock);
}

unsigned fuse_file_poll(struct file *file, poll_table *wait)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_conn *fc = ff->fc;
	struct fuse_poll_in inarg = { .fh = ff->fh, .kh = ff->kh };
	struct fuse_poll_out outarg;
	struct fuse_req *req;
	int err;

	if (fc->no_poll)
		return DEFAULT_POLLMASK;

	poll_wait(file, &ff->poll_wait, wait);

	/*
	 * Ask for notification iff there's someone waiting for it.
	 * The client may ignore the flag and always notify.
	 */
	if (waitqueue_active(&ff->poll_wait)) {
		inarg.flags |= FUSE_POLL_SCHEDULE_NOTIFY;
		fuse_register_polled_file(fc, ff);
	}

	req = fuse_get_req_nopages(fc);
	if (IS_ERR(req))
		return POLLERR;

	req->in.h.opcode = FUSE_POLL;
	req->in.h.nodeid = ff->nodeid;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->out.numargs = 1;
	req->out.args[0].size = sizeof(outarg);
	req->out.args[0].value = &outarg;
	fuse_request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);

	if (!err)
		return outarg.revents;
	if (err == -ENOSYS) {
		fc->no_poll = 1;
		return DEFAULT_POLLMASK;
	}
	return POLLERR;
}
EXPORT_SYMBOL_GPL(fuse_file_poll);

/*
 * This is called from fuse_handle_notify() on FUSE_NOTIFY_POLL and
 * wakes up the poll waiters.
 */
int fuse_notify_poll_wakeup(struct fuse_conn *fc,
			    struct fuse_notify_poll_wakeup_out *outarg)
{
	u64 kh = outarg->kh;
	struct rb_node **link;

	spin_lock(&fc->lock);

	link = fuse_find_polled_node(fc, kh, NULL);
	if (*link) {
		struct fuse_file *ff;

		ff = rb_entry(*link, struct fuse_file, polled_node);
		wake_up_interruptible_sync(&ff->poll_wait);
	}

	spin_unlock(&fc->lock);
	return 0;
}

static struct fuse_io_priv *fuse_io_priv_create(struct kiocb *iocb,
		loff_t off, int rw, bool async)
{
	struct fuse_io_priv *io;

	io = kmalloc(sizeof(struct fuse_io_priv), GFP_KERNEL);
	if (!io)
		return NULL;

	spin_lock_init(&io->lock);
	io->reqs = 1;
	io->bytes = -1;
	io->size = 0;
	io->offset = off;
	io->write = (rw == WRITE);
	io->err = 0;
	io->file = iocb->ki_filp;
	io->async = async;
	io->iocb = iocb;

	return io;
}

static ssize_t fuse_direct_IO_bvec(int rw, struct kiocb *iocb,
		struct bio_vec *bvec, loff_t offset, unsigned long bvec_len)
{
	struct fuse_io_priv *io;
	struct fuse_req *req;
	struct file *file = iocb->ki_filp;
	struct fuse_file *ff = file->private_data;
	struct fuse_conn *fc = ff->fc;
	size_t nmax = (rw == WRITE ? fc->max_write : fc->max_read);
	size_t filled, nres;
	loff_t pos = iocb->ki_pos;
	int i;

	if (nmax > FUSE_MAX_PAGES_PER_REQ << PAGE_SHIFT)
		nmax = FUSE_MAX_PAGES_PER_REQ << PAGE_SHIFT;

	virtinfo_notifier_call(VITYPE_IO, VIRTINFO_IO_PREPARE, NULL);

	io = fuse_io_priv_create(iocb, pos, rw, true);
	if (!io)
		return -ENOMEM;

	req = NULL;
	filled = 0;
	i = 0;

	while (1) {
		if (!req) {
			req = fuse_get_req_for_background(fc, 0);
			if (IS_ERR(req))
				break;

			if (rw == WRITE)
				req->in.argbvec = 1;
			else
				req->out.argbvec = 1;

			filled = 0;
			req->bvec = bvec;
		}

		if (filled + bvec->bv_len <= nmax) {
			filled += bvec->bv_len;
			req->num_bvecs++;
			bvec++;
			i++;

			if (i < bvec_len)
				continue;
		}

		BUG_ON(!filled);

		if (rw == WRITE)
			nres = fuse_send_write(req, io, pos,
					filled, NULL);
		else
			nres = fuse_send_read(req, io, pos,
					filled, NULL);

		BUG_ON(nres != filled);
		fuse_put_request(fc, req);

		if (i == bvec_len)
			break;

		pos += filled;
		req = NULL;
		filled = 0;
	}

	fuse_aio_complete(io, !IS_ERR(req) ? 0 : PTR_ERR(req), -1);
	return -EIOCBQUEUED;
}

static void fuse_do_truncate(struct file *file)
{
	struct inode *inode = file->f_mapping->host;
	struct iattr attr;
	int err;

	attr.ia_valid = ATTR_SIZE;
	attr.ia_size = i_size_read(inode);

	attr.ia_file = file;
	attr.ia_valid |= ATTR_FILE;

	err = fuse_do_setattr(inode, &attr, file);
	if (err)
		printk("failed to truncate to %lld with error %d\n",
		       i_size_read(inode), err);
}

static inline loff_t fuse_round_up(loff_t off)
{
	return round_up(off, FUSE_MAX_PAGES_PER_REQ << PAGE_SHIFT);
}

static ssize_t
fuse_direct_IO(int rw, struct kiocb *iocb, const struct iovec *iov,
			loff_t offset, unsigned long nr_segs)
{
	ssize_t ret = 0;
	struct file *file = iocb->ki_filp;
	struct fuse_file *ff = file->private_data;
	bool async_dio = ff->fc->async_dio | (ff->fc->flags & FUSE_WBCACHE);
	loff_t pos = 0;
	struct inode *inode;
	loff_t i_size;
	size_t count = iov_length(iov, nr_segs);
	struct fuse_io_priv *io;

	pos = offset;
	inode = file->f_mapping->host;
	i_size = i_size_read(inode);

	/* optimization for short read */
	if (async_dio && rw != WRITE && offset + count > i_size) {
		loff_t new_count;

		if (offset >= i_size)
			return 0;

		new_count = i_size - offset;
		if (!(ff->fc->flags & FUSE_WBCACHE))
			new_count = fuse_round_up(new_count);

		count = min_t(loff_t, count, new_count);
	}

	/*
	 * By default, we want to optimize all I/Os with async request
	 * submission to the client filesystem if supported.
	 */
	io = fuse_io_priv_create(iocb, offset, rw, async_dio);
	if (!io)
		return -ENOMEM;

	/*
	 * We cannot asynchronously extend the size of a file. We have no method
	 * to wait on real async I/O requests, so we must submit this request
	 * synchronously.
	 */
	if (!is_sync_kiocb(iocb) && (offset + count > i_size) && rw == WRITE)
		io->async = false;

	if (rw == WRITE)
		ret = __fuse_direct_write(io, iov, nr_segs, &pos);
	else
		ret = __fuse_direct_read(io, iov, nr_segs, &pos, count);

	if (io->async) {
		if (ret != count) {
			struct fuse_file *ff = file->private_data;
			printk("fuse_direct_IO: failed to %s %ld bytes "
			       "(offset=%llu ret=%ld i_size=%llu ino=%lu "
			       "fh=%llu\n", rw == WRITE ? "write" : "read",
			       count, offset, ret, i_size, inode->i_ino,
			       ff->fh);
		}
		fuse_aio_complete(io, ret < 0 ? ret : 0, -1);

		/* we have a non-extending, async request, so return */
		if (!is_sync_kiocb(iocb))
			return -EIOCBQUEUED;

		ret = wait_on_sync_kiocb(iocb);
	} else {
		kfree(io);
	}

	if (rw == WRITE) {
		if (ret > 0)
			fuse_write_update_size(inode, pos);
		else if (ret < 0 && offset + count > i_size)
			fuse_do_truncate(file);
	}

	return ret;
}

static void fuse_punch_hole(struct inode *inode, loff_t lstart, loff_t lend)
{
	unsigned int partial_start = lstart & (PAGE_CACHE_SIZE - 1);
	unsigned int partial_end = (lend + 1) & (PAGE_CACHE_SIZE - 1);
	pgoff_t end_index = (lend + 1) >> PAGE_CACHE_SHIFT;
	loff_t end_offset = end_index << PAGE_CACHE_SHIFT;

	if (end_offset > lstart) {
		truncate_pagecache_range(inode, lstart, end_offset - 1);
		partial_start = 0;
	}

	/*
	 * Zero out trailing partial page, because truncate_pagecache_range()
	 * doesn't do it.
	 */
	if (partial_end) {
		struct page *page = find_lock_page(inode->i_mapping, end_index);
		if (page) {
			zero_user_segment(page, partial_start, partial_end);
			unlock_page(page);
			page_cache_release(page);
		}
	}
}

static ssize_t fuse_direct_IO_page(int rw, struct kiocb *iocb,
	struct page *page, loff_t offset)
{
	struct iovec iov;
	mm_segment_t oldfs;
	ssize_t ret;

	iov.iov_base = kmap(page);
	iov.iov_len = PAGE_SIZE;

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	ret = fuse_direct_IO(rw, iocb, &iov, offset, 1);
	if (ret != -EIOCBQUEUED && ret != PAGE_SIZE)
		printk("fuse_direct_IO_page: io failed with err=%ld "
		       "(rw=%s fh=0x%llx pos=%lld)\n",
		       ret, rw == WRITE ? "WRITE" : "READ",
		       ((struct fuse_file *)iocb->ki_filp->private_data)->fh,
		       offset);

	set_fs(oldfs);
	kunmap(page);
	return ret;
}

long fuse_file_fallocate(struct inode *inode, struct fuse_file *ff, int mode,
			 loff_t offset, loff_t length)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_conn *fc = ff->fc;
	struct fuse_req *req;
	struct fuse_fallocate_in inarg = {
		.fh = ff->fh,
		.offset = offset,
		.length = length,
		.mode = mode
	};
	int err;
	bool lock_inode = !(mode & FALLOC_FL_KEEP_SIZE) ||
			   (mode & FALLOC_FL_PUNCH_HOLE);

	if (fc->no_fallocate)
		return -EOPNOTSUPP;

	if (lock_inode) {
		mutex_lock(&inode->i_mutex);
		if (mode & FALLOC_FL_PUNCH_HOLE) {
			loff_t endbyte = offset + length - 1;
			err = filemap_write_and_wait_range(inode->i_mapping,
							   offset, endbyte);
			if (err)
				goto out;

			fuse_sync_writes(inode);
		}
	}

	if (!(mode & FALLOC_FL_KEEP_SIZE))
		set_bit(FUSE_I_SIZE_UNSTABLE, &fi->state);

	req = fuse_get_req_nopages(fc);
	if (IS_ERR(req)) {
		err = PTR_ERR(req);
		goto out;
	}

	req->in.h.opcode = FUSE_FALLOCATE;
	req->in.h.nodeid = ff->nodeid;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	fuse_request_send(fc, req);
	err = req->out.h.error;
	if (err == -ENOSYS) {
		fc->no_fallocate = 1;
		err = -EOPNOTSUPP;
	}
	fuse_put_request(fc, req);

	if (err)
		goto out;

	/* we could have extended the file */
	if (!(mode & FALLOC_FL_KEEP_SIZE))
		fuse_write_update_size(inode, offset + length);

	if (mode & FALLOC_FL_PUNCH_HOLE)
		fuse_punch_hole(inode, offset, offset + length - 1);

	fuse_invalidate_attr(inode);

out:
	if (!(mode & FALLOC_FL_KEEP_SIZE))
		clear_bit(FUSE_I_SIZE_UNSTABLE, &fi->state);

	if (lock_inode)
		mutex_unlock(&inode->i_mutex);

	return err;
}
EXPORT_SYMBOL_GPL(fuse_file_fallocate);

static const struct file_operations fuse_file_operations = {
	.llseek		= fuse_file_llseek,
	.read		= do_sync_read,
	.aio_read	= fuse_file_aio_read,
	.write		= do_sync_write,
	.aio_write	= fuse_file_aio_write,
	.mmap		= fuse_file_mmap,
	.open		= fuse_open,
	.flush		= fuse_flush,
	.release	= fuse_release,
	.fsync		= fuse_fsync,
	.lock		= fuse_file_lock,
	.flock		= fuse_file_flock,
	.splice_read	= generic_file_splice_read,
	.unlocked_ioctl	= fuse_file_ioctl,
	.compat_ioctl	= fuse_file_compat_ioctl,
	.poll		= fuse_file_poll,
	.read_iter	= generic_file_read_iter,
	.write_iter	= generic_file_write_iter,
};

static const struct file_operations fuse_direct_io_file_operations = {
	.llseek		= fuse_file_llseek,
	.read		= fuse_direct_read,
	.write		= fuse_direct_write,
	.mmap		= fuse_direct_mmap,
	.open		= fuse_open,
	.flush		= fuse_flush,
	.release	= fuse_release,
	.fsync		= fuse_fsync,
	.lock		= fuse_file_lock,
	.flock		= fuse_file_flock,
	.unlocked_ioctl	= fuse_file_ioctl,
	.compat_ioctl	= fuse_file_compat_ioctl,
	.poll		= fuse_file_poll,
	/* no splice_read */
};

static const struct address_space_operations fuse_file_aops  = {
	.readpage	= fuse_readpage,
	.writepage	= fuse_writepage,
	.writepages	= fuse_writepages,
	.launder_page	= fuse_launder_page,
	.write_begin	= fuse_write_begin,
	.write_end	= fuse_write_end,
	.readpages	= fuse_readpages,
	.set_page_dirty	= __set_page_dirty_nobuffers,
	.bmap		= fuse_bmap,
	.direct_IO	= fuse_direct_IO,
	.direct_IO_bvec	= fuse_direct_IO_bvec,
	.direct_IO_page	= fuse_direct_IO_page,
};

void fuse_init_file_inode(struct inode *inode)
{
	inode->i_fop = &fuse_file_operations;
	inode->i_data.a_ops = &fuse_file_aops;
}
