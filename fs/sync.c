/*
 * High-level sync()-related operations
 */

#include <linux/kernel.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/writeback.h>
#include <linux/syscalls.h>
#include <linux/linkage.h>
#include <linux/pid_namespace.h>
#include <linux/pagemap.h>
#include <linux/quotaops.h>
#include <linux/buffer_head.h>
#include <linux/kthread.h>
#include <linux/mnt_namespace.h>
#include <linux/mount.h>
#include <linux/backing-dev.h>
#include "internal.h"

#include <bc/beancounter.h>
#include <bc/io_acct.h>

#define VALID_FLAGS (SYNC_FILE_RANGE_WAIT_BEFORE|SYNC_FILE_RANGE_WRITE| \
			SYNC_FILE_RANGE_WAIT_AFTER)

/*
 * Do the filesystem syncing work. For simple filesystems
 * writeback_inodes_sb(sb) just dirties buffers with inodes so we have to
 * submit IO for these buffers via __sync_blockdev(). This also speeds up the
 * wait == 1 case since in that case write_inode() functions do
 * sync_dirty_buffer() and thus effectively write one block at a time.
 */
int __sync_filesystem(struct super_block *sb,
		struct user_beancounter *ub, int wait)
{
	/* Avoid doing twice syncing and cache pruning for quota sync */
	if (!wait) {
		writeout_quota_sb(sb, -1);
		writeback_inodes_sb_ub(sb, ub);
	} else {
		sync_quota_sb(sb, -1);
		sync_inodes_sb_ub(sb, ub);
	}
	if (sb->s_op->sync_fs)
		sb->s_op->sync_fs(sb, wait);
	return __sync_blockdev(sb->s_bdev, wait);
}
EXPORT_SYMBOL(__sync_filesystem);

/*
 * Write out and wait upon all dirty data associated with this
 * superblock.  Filesystem data as well as the underlying block
 * device.  Takes the superblock lock.
 */
static int sync_filesystem_ub(struct super_block *sb, struct user_beancounter *ub)
{
	int ret;

	/*
	 * We need to be protected against the filesystem going from
	 * r/o to r/w or vice versa.
	 */
	WARN_ON(!rwsem_is_locked(&sb->s_umount));

	/*
	 * No point in syncing out anything if the filesystem is read-only.
	 */
	if (sb->s_flags & MS_RDONLY)
		return 0;

	ret = __sync_filesystem(sb, ub, 0);
	if (ret < 0)
		return ret;
	return __sync_filesystem(sb, ub, 1);
}

int sync_filesystem(struct super_block *sb)
{
	return sync_filesystem_ub(sb, NULL);
}
EXPORT_SYMBOL_GPL(sync_filesystem);

struct sync_sb {
	struct list_head list;
	struct super_block *sb;
};

static void sync_release_filesystems(struct list_head *sync_list)
{
	struct sync_sb *ss, *tmp;

	list_for_each_entry_safe(ss, tmp, sync_list, list) {
		list_del(&ss->list);
		put_super(ss->sb);
		kfree(ss);
	}
}

static int sync_filesystem_collected(struct list_head *sync_list, struct super_block *sb)
{
	struct sync_sb *ss;

	list_for_each_entry(ss, sync_list, list)
		if (ss->sb == sb)
			return 1;
	return 0;
}

static int sync_collect_filesystems(struct ve_struct *ve, struct list_head *sync_list)
{
	struct vfsmount *root = ve->root_path.mnt;
	struct vfsmount *mnt;
	struct sync_sb *ss;
	int ret = 0;

	BUG_ON(!list_empty(sync_list));

	down_read(&namespace_sem);
	for (mnt = root; mnt; mnt = next_mnt(mnt, root)) {
		if (sync_filesystem_collected(sync_list, mnt->mnt_sb))
			continue;

		ss = kmalloc(sizeof(*ss), GFP_KERNEL);
		if (ss == NULL) {
			ret = -ENOMEM;
			break;
		}
		ss->sb = mnt->mnt_sb;
		/*
		 * We hold mount point and thus can be sure, that superblock is
		 * alive. And it means, that we can safely increase it's usage
		 * counter.
		 */
		spin_lock(&sb_lock);
		ss->sb->s_count++;
		spin_unlock(&sb_lock);
		list_add_tail(&ss->list, sync_list);
	}
	up_read(&namespace_sem);
	return ret;
}

static void sync_filesystems_ve(struct ve_struct *ve, struct user_beancounter *ub, int wait)
{
	struct super_block *sb;
	LIST_HEAD(sync_list);
	struct sync_sb *ss;

	mutex_lock(&ve->sync_mutex);		/* Could be down_interruptible */

	/*
	 * We don't need to care about allocating failure here. At least we
	 * don't need to skip sync on such error.
	 * Let's sync what we collected already instead.
	 */
	sync_collect_filesystems(ve, &sync_list);

	list_for_each_entry(ss, &sync_list, list) {
		sb = ss->sb;
		down_read(&sb->s_umount);
		if (!(sb->s_flags & MS_RDONLY) && sb->s_root && sb->s_bdi)
			__sync_filesystem(sb, ub, wait);
		up_read(&sb->s_umount);
	}

	sync_release_filesystems(&sync_list);

	mutex_unlock(&ve->sync_mutex);
}

/*
 * Sync all the data for all the filesystems (called by sys_sync() and
 * emergency sync)
 *
 * This operation is careful to avoid the livelock which could easily happen
 * if two or more filesystems are being continuously dirtied.  s_need_sync
 * is used only here.  We set it against all filesystems and then clear it as
 * we sync them.  So redirtied filesystems are skipped.
 *
 * But if process A is currently running sync_filesystems and then process B
 * calls sync_filesystems as well, process B will set all the s_need_sync
 * flags again, which will cause process A to resync everything.  Fix that with
 * a local mutex.
 */
static void sync_filesystems_ve0(struct user_beancounter *ub, int wait)
{
	struct super_block *sb;
	static DEFINE_MUTEX(mutex);

	mutex_lock(&mutex);		/* Could be down_interruptible */
	spin_lock(&sb_lock);
	list_for_each_entry(sb, &super_blocks, s_list)
		sb->s_need_sync = 1;

restart:
	list_for_each_entry(sb, &super_blocks, s_list) {
		if (!sb->s_need_sync)
			continue;
		sb->s_need_sync = 0;
		sb->s_count++;
		spin_unlock(&sb_lock);

		down_read(&sb->s_umount);
		/*
		 * If the file system is frozen we can't proceed because we
		 * could potentially block on frozen file system. This would
		 * lead to a deadlock, because we're holding s_umount which
		 * has to be taken in order to  thaw the file system as well.
		 * Frozen file system should be clean anyway so just skip it.
		 */
		if ((!sb_has_new_freeze(sb) && sb->s_frozen != SB_UNFROZEN) ||
		    (sb->s_writers.frozen != SB_UNFROZEN))
			goto skip;

		if (!(sb->s_flags & MS_RDONLY) && sb->s_root && sb->s_bdi)
			__sync_filesystem(sb, ub, wait);

skip:
		up_read(&sb->s_umount);

		/* restart only when sb is no longer on the list */
		spin_lock(&sb_lock);
		if (__put_super_and_need_restart(sb))
			goto restart;
	}
	spin_unlock(&sb_lock);
	mutex_unlock(&mutex);
}

static void sync_filesystems(struct user_beancounter *ub, int wait)
{
	if (!ub || (ub == get_ub0()))
		sync_filesystems_ve0(ub, wait);
	else
		sync_filesystems_ve(get_exec_env(), ub, wait);
}

static int __ve_fsync_behavior(struct ve_struct *ve)
{
	if (ve->fsync_enable == 2)
		return get_ve0()->fsync_enable;
	else if (ve->fsync_enable)
		return FSYNC_FILTERED; /* sync forced by ve is always filtered */
	else
		return 0;
}

int ve_fsync_behavior(void)
{
	struct ve_struct *ve;

	ve = get_exec_env();
	if (ve_is_super(ve))
		return FSYNC_ALWAYS;
	else
		return __ve_fsync_behavior(ve);
}

/*
 * sync everything.  Start out by waking pdflush, because that writes back
 * all queues in parallel.
 */
SYSCALL_DEFINE0(sync)
{
	struct user_beancounter *ub, *sync_ub = NULL;
	struct ve_struct *ve;

	ub = get_exec_ub_top();
	ve = get_exec_env();
	ub_percpu_inc(ub, sync);

	if (!ve_is_super(ve)) {
		int fsb;

		/*
		 * init can't sync during VE stop. Rationale:
		 *  - NFS with -o hard will block forever as network is down
		 *  - no useful job is performed as VE0 will call umount/sync
		 *    by his own later
		 *  Den
		 */
		if (current == get_env_init(ve))
			goto skip;

		fsb = __ve_fsync_behavior(ve);
		if (fsb == FSYNC_NEVER)
			goto skip;

		if (fsb == FSYNC_FILTERED)
			sync_ub = get_io_ub();
	}

	wakeup_flusher_threads(sync_ub, 0);
	sync_filesystems(sync_ub, 0);
	sync_filesystems(sync_ub, 1);
	if (unlikely(laptop_mode) && !sync_ub)
		laptop_sync_completion();
skip:
	ub_percpu_inc(ub, sync_done);
	return 0;
}

static int __do_sync_work(void *dummy)
{
	/*
	 * Sync twice to reduce the possibility we skipped some inodes / pages
	 * because they were temporarily locked
	 */
	sync_filesystems(NULL, 0);
	sync_filesystems(NULL, 0);
	printk("Emergency Sync complete\n");
	return 0;
}

static void do_sync_work(struct work_struct *work)
{
	kthread_run(__do_sync_work, NULL, "sync_work_thread");
	kfree(work);
}

void emergency_sync(void)
{
	struct work_struct *work;

	work = kmalloc(sizeof(*work), GFP_ATOMIC);
	if (work) {
		INIT_WORK(work, do_sync_work);
		schedule_work(work);
	}
}

/*
 * Generic function to fsync a file.
 *
 * filp may be NULL if called via the msync of a vma.
 */
int file_fsync(struct file *filp, struct dentry *dentry, int datasync)
{
	struct inode * inode = dentry->d_inode;
	struct super_block * sb;
	int ret, err;

	/* sync the inode to buffers */
	ret = write_inode_now(inode, 0);

	/* sync the superblock to buffers */
	sb = inode->i_sb;
	if (sb->s_dirt && sb->s_op->write_super)
		sb->s_op->write_super(sb);

	/* .. finally sync the buffers to disk */
	err = sync_blockdev(sb->s_bdev);
	if (!ret)
		ret = err;
	return ret;
}
EXPORT_SYMBOL(file_fsync);

/*
 * sync a single super
 */
SYSCALL_DEFINE1(syncfs, int, fd)
{
	struct file *file;
	struct super_block *sb;
	int ret = 0;
	int fput_needed;
	struct user_beancounter *ub, *sync_ub = NULL;
	struct ve_struct *ve;

	ub = get_exec_ub_top();
	ve = get_exec_env();
	ub_percpu_inc(ub, sync);

	if (!ve_is_super(ve)) {
		int fsb;

		/*
		 * init can't sync during VE stop. Rationale:
		 *  - NFS with -o hard will block forever as network is down
		 *  - no useful job is performed as VE0 will call umount/sync
		 *    by his own later
		 *  Den
		 */
		if (current == get_env_init(ve))
			goto skip;

		fsb = __ve_fsync_behavior(ve);
		if (fsb == FSYNC_NEVER)
			goto skip;

		if (fsb == FSYNC_FILTERED)
			sync_ub = get_io_ub();
	}

	file = fget_light(fd, &fput_needed);
	if (!file) {
		ret = -EBADF;
		goto skip;
	}

	sb = file->f_dentry->d_sb;

	down_read(&sb->s_umount);
	/*
	 * If the file system is frozen we can't proceed because we
	 * could potentially block on frozen file system. This would
	 * lead to a deadlock, because we're holding s_umount which
	 * has to be taken in order to  thaw the file system as well
	 * Frozen file system should be clean anyway so just skip it.
	 */
	if ((sb_has_new_freeze(sb) && sb->s_writers.frozen == SB_UNFROZEN) ||
	    (!sb_has_new_freeze(sb) && sb->s_frozen == SB_UNFROZEN))
		if (sb->s_root)
			ret = sync_filesystem_ub(sb, sync_ub);

	up_read(&sb->s_umount);

	fput_light(file, fput_needed);
skip:
	ub_percpu_inc(ub, sync_done);
	return ret;
}

/**
 * vfs_fsync_range - helper to sync a range of data & metadata to disk
 * @file:		file to sync
 * @dentry:		dentry of @file
 * @start:		offset in bytes of the beginning of data range to sync
 * @end:		offset in bytes of the end of data range (inclusive)
 * @datasync:		perform only datasync
 *
 * Write back data in range @start..@end and metadata for @file to disk.  If
 * @datasync is set only metadata needed to access modified file data is
 * written.
 *
 * In case this function is called from nfsd @file may be %NULL and
 * only @dentry is set.  This can only happen when the filesystem
 * implements the export_operations API.
 */
int vfs_fsync_range(struct file *file, struct dentry *dentry, loff_t start,
		    loff_t end, int datasync)
{
	const struct file_operations *fop;
	struct address_space *mapping;
	int err, ret;
	struct inode *inode = file->f_mapping->host;
	struct user_beancounter *ub;

	/*
	 * Get mapping and operations from the file in case we have
	 * as file, or get the default values for them in case we
	 * don't have a struct file available.  Damn nfsd..
	 */
	if (file) {
		mapping = file->f_mapping;
		fop = file->f_op;
	} else {
		mapping = dentry->d_inode->i_mapping;
		fop = dentry->d_inode->i_fop;
	}

	if (!fop || !fop->fsync) {
		ret = -EINVAL;
		goto out;
	}

	ub = get_exec_ub_top();
	if (datasync)
		ub_percpu_inc(ub, fdsync);
	else
		ub_percpu_inc(ub, fsync);

	ret = filemap_write_and_wait_range(mapping, start, end);

	if (!datasync && (inode->i_state & I_DIRTY_TIME)) {
		spin_lock(&inode_lock);
		inode->i_state &= ~I_DIRTY_TIME;
		spin_unlock(&inode_lock);
		mark_inode_dirty_sync(inode);
	}

	/*
	 * We need to protect against concurrent writers, which could cause
	 * livelocks in fsync_buffers_list().
	 */
	mutex_lock(&mapping->host->i_mutex);
	err = fop->fsync(file, dentry, datasync);
	if (!ret || (err && ret == -EIO))
		ret = err;
	mutex_unlock(&mapping->host->i_mutex);

	if (datasync)
		ub_percpu_inc(ub, fdsync_done);
	else
		ub_percpu_inc(ub, fsync_done);
out:
	return ret;
}
EXPORT_SYMBOL(vfs_fsync_range);

/**
 * vfs_fsync - perform a fsync or fdatasync on a file
 * @file:		file to sync
 * @dentry:		dentry of @file
 * @datasync:		only perform a fdatasync operation
 *
 * Write back data and metadata for @file to disk.  If @datasync is
 * set only metadata needed to access modified file data is written.
 *
 * In case this function is called from nfsd @file may be %NULL and
 * only @dentry is set.  This can only happen when the filesystem
 * implements the export_operations API.
 */
int vfs_fsync(struct file *file, struct dentry *dentry, int datasync)
{
	return vfs_fsync_range(file, dentry, 0, LLONG_MAX, datasync);
}
EXPORT_SYMBOL(vfs_fsync);

static int do_fsync(unsigned int fd, int datasync)
{
	struct file *file;
	int ret = -EBADF;

	if (ve_fsync_behavior() == FSYNC_NEVER)
		return 0;

	file = fget(fd);
	if (file) {
		sb_start_write(file->f_mapping->host->i_sb);
		ret = vfs_fsync(file, file->f_path.dentry, datasync);
		sb_end_write(file->f_mapping->host->i_sb);
		fput(file);
	}
	return ret;
}

SYSCALL_DEFINE1(fsync, unsigned int, fd)
{
	return do_fsync(fd, 0);
}

SYSCALL_DEFINE1(fdatasync, unsigned int, fd)
{
	return do_fsync(fd, 1);
}

/**
 * generic_write_sync - perform syncing after a write if file / inode is sync
 * @file:	file to which the write happened
 * @pos:	offset where the write started
 * @count:	length of the write
 *
 * This is just a simple wrapper about our general syncing function.
 */
int generic_write_sync(struct file *file, loff_t pos, loff_t count)
{
	if (!(file->f_flags & O_SYNC) && !IS_SYNC(file->f_mapping->host))
		return 0;
	return vfs_fsync_range(file, file->f_path.dentry, pos,
			       pos + count - 1, 1);
}
EXPORT_SYMBOL(generic_write_sync);

/*
 * sys_sync_file_range() permits finely controlled syncing over a segment of
 * a file in the range offset .. (offset+nbytes-1) inclusive.  If nbytes is
 * zero then sys_sync_file_range() will operate from offset out to EOF.
 *
 * The flag bits are:
 *
 * SYNC_FILE_RANGE_WAIT_BEFORE: wait upon writeout of all pages in the range
 * before performing the write.
 *
 * SYNC_FILE_RANGE_WRITE: initiate writeout of all those dirty pages in the
 * range which are not presently under writeback. Note that this may block for
 * significant periods due to exhaustion of disk request structures.
 *
 * SYNC_FILE_RANGE_WAIT_AFTER: wait upon writeout of all pages in the range
 * after performing the write.
 *
 * Useful combinations of the flag bits are:
 *
 * SYNC_FILE_RANGE_WAIT_BEFORE|SYNC_FILE_RANGE_WRITE: ensures that all pages
 * in the range which were dirty on entry to sys_sync_file_range() are placed
 * under writeout.  This is a start-write-for-data-integrity operation.
 *
 * SYNC_FILE_RANGE_WRITE: start writeout of all dirty pages in the range which
 * are not presently under writeout.  This is an asynchronous flush-to-disk
 * operation.  Not suitable for data integrity operations.
 *
 * SYNC_FILE_RANGE_WAIT_BEFORE (or SYNC_FILE_RANGE_WAIT_AFTER): wait for
 * completion of writeout of all pages in the range.  This will be used after an
 * earlier SYNC_FILE_RANGE_WAIT_BEFORE|SYNC_FILE_RANGE_WRITE operation to wait
 * for that operation to complete and to return the result.
 *
 * SYNC_FILE_RANGE_WAIT_BEFORE|SYNC_FILE_RANGE_WRITE|SYNC_FILE_RANGE_WAIT_AFTER:
 * a traditional sync() operation.  This is a write-for-data-integrity operation
 * which will ensure that all pages in the range which were dirty on entry to
 * sys_sync_file_range() are committed to disk.
 *
 *
 * SYNC_FILE_RANGE_WAIT_BEFORE and SYNC_FILE_RANGE_WAIT_AFTER will detect any
 * I/O errors or ENOSPC conditions and will return those to the caller, after
 * clearing the EIO and ENOSPC flags in the address_space.
 *
 * It should be noted that none of these operations write out the file's
 * metadata.  So unless the application is strictly performing overwrites of
 * already-instantiated disk blocks, there are no guarantees here that the data
 * will be available after a crash.
 */
SYSCALL_DEFINE(sync_file_range)(int fd, loff_t offset, loff_t nbytes,
				unsigned int flags)
{
	int ret;
	struct file *file;
	loff_t endbyte;			/* inclusive */
	int fput_needed;
	umode_t i_mode;

	ret = -EINVAL;
	if (flags & ~VALID_FLAGS)
		goto out;

	endbyte = offset + nbytes;

	if ((s64)offset < 0)
		goto out;
	if ((s64)endbyte < 0)
		goto out;
	if (endbyte < offset)
		goto out;

	if (sizeof(pgoff_t) == 4) {
		if (offset >= (0x100000000ULL << PAGE_CACHE_SHIFT)) {
			/*
			 * The range starts outside a 32 bit machine's
			 * pagecache addressing capabilities.  Let it "succeed"
			 */
			ret = 0;
			goto out;
		}
		if (endbyte >= (0x100000000ULL << PAGE_CACHE_SHIFT)) {
			/*
			 * Out to EOF
			 */
			nbytes = 0;
		}
	}

	if (nbytes == 0)
		endbyte = LLONG_MAX;
	else
		endbyte--;		/* inclusive */

	ret = -EBADF;
	file = fget_light(fd, &fput_needed);
	if (!file)
		goto out;

	i_mode = file->f_path.dentry->d_inode->i_mode;
	ret = -ESPIPE;
	if (!S_ISREG(i_mode) && !S_ISBLK(i_mode) && !S_ISDIR(i_mode) &&
			!S_ISLNK(i_mode))
		goto out_put;
	sb_start_write(file->f_mapping->host->i_sb);
	ret = do_sync_mapping_range(file->f_mapping, offset, endbyte, flags);
	sb_end_write(file->f_mapping->host->i_sb);
out_put:
	fput_light(file, fput_needed);
out:
	return ret;
}
#ifdef CONFIG_HAVE_SYSCALL_WRAPPERS
asmlinkage long SyS_sync_file_range(long fd, loff_t offset, loff_t nbytes,
				    long flags)
{
	return SYSC_sync_file_range((int) fd, offset, nbytes,
				    (unsigned int) flags);
}
SYSCALL_ALIAS(sys_sync_file_range, SyS_sync_file_range);
#endif

/* It would be nice if people remember that not all the world's an i386
   when they introduce new system calls */
SYSCALL_DEFINE(sync_file_range2)(int fd, unsigned int flags,
				 loff_t offset, loff_t nbytes)
{
	return sys_sync_file_range(fd, offset, nbytes, flags);
}
#ifdef CONFIG_HAVE_SYSCALL_WRAPPERS
asmlinkage long SyS_sync_file_range2(long fd, long flags,
				     loff_t offset, loff_t nbytes)
{
	return SYSC_sync_file_range2((int) fd, (unsigned int) flags,
				     offset, nbytes);
}
SYSCALL_ALIAS(sys_sync_file_range2, SyS_sync_file_range2);
#endif

/*
 * `endbyte' is inclusive
 */
int do_sync_mapping_range(struct address_space *mapping, loff_t offset,
			  loff_t endbyte, unsigned int flags)
{
	int ret;
	struct user_beancounter *ub;

	if (!mapping) {
		ret = -EINVAL;
		goto out_noacct;
	}

	ub = get_exec_ub_top();
	ub_percpu_inc(ub, frsync);

	ret = 0;
	if (flags & SYNC_FILE_RANGE_WAIT_BEFORE) {
		ret = wait_on_page_writeback_range(mapping,
					offset >> PAGE_CACHE_SHIFT,
					endbyte >> PAGE_CACHE_SHIFT);
		if (ret < 0)
			goto out;
	}

	if (flags & SYNC_FILE_RANGE_WRITE) {
		ret = __filemap_fdatawrite_range(mapping, offset, endbyte,
						WB_SYNC_ALL);
		if (ret < 0)
			goto out;
	}

	if (flags & SYNC_FILE_RANGE_WAIT_AFTER) {
		ret = wait_on_page_writeback_range(mapping,
					offset >> PAGE_CACHE_SHIFT,
					endbyte >> PAGE_CACHE_SHIFT);
	}
out:
	ub_percpu_inc(ub, frsync_done);
out_noacct:
	return ret;
}
EXPORT_SYMBOL_GPL(do_sync_mapping_range);
