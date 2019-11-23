/*
 *  linux/fs/namespace.c
 *
 * (C) Copyright Al Viro 2000, 2001
 *	Released under GPL v2.
 *
 * Based on code from fs/super.c, copyright Linus Torvalds and others.
 * Heavily rewritten.
 */

#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/smp_lock.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/acct.h>
#include <linux/capability.h>
#include <linux/cpumask.h>
#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/seq_file.h>
#include <linux/mnt_namespace.h>
#include <linux/namei.h>
#include <linux/nsproxy.h>
#include <linux/security.h>
#include <linux/mount.h>
#include <linux/ramfs.h>
#include <linux/log2.h>
#include <linux/idr.h>
#include <linux/fs_struct.h>
#include <linux/fsnotify_backend.h>
#include <linux/ve_proto.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include "pnode.h"
#include "internal.h"

#define HASH_SHIFT ilog2(PAGE_SIZE / sizeof(struct list_head))
#define HASH_SIZE (1UL << HASH_SHIFT)

/* spinlock for vfsmount related operations, inplace of dcache_lock */
__cacheline_aligned_in_smp DEFINE_SPINLOCK(vfsmount_lock);
EXPORT_SYMBOL(vfsmount_lock);

static int event;
static DEFINE_IDA(mnt_id_ida);
static DEFINE_IDA(mnt_group_ida);
static int mnt_id_start = 0;
static int mnt_group_start = 1;

static struct list_head *mount_hashtable __read_mostly;
static struct kmem_cache *mnt_cache __read_mostly;
struct rw_semaphore namespace_sem;
EXPORT_SYMBOL(namespace_sem);

unsigned int sysctl_ve_mount_nr = 4096;

/* /sys/fs */
struct kobject *fs_kobj;
EXPORT_SYMBOL_GPL(fs_kobj);

static LIST_HEAD(mounts_readers);
static DEFINE_SPINLOCK(mounts_lock);

void register_mounts_reader(struct proc_mounts *p)
{
	spin_lock(&mounts_lock);
	list_add(&p->reader, &mounts_readers);
	spin_unlock(&mounts_lock);
}

void unregister_mounts_reader(struct proc_mounts *p)
{
	spin_lock(&mounts_lock);
	list_del(&p->reader);
	spin_unlock(&mounts_lock);
}

static void advance_mounts_readers(struct list_head *iter)
{
	struct proc_mounts *p;

	spin_lock(&mounts_lock);
	list_for_each_entry(p, &mounts_readers, reader) {
		if (p->iter == iter) {
			p->iter = p->iter->next;
			p->iter_advanced = 1;
		}
	}
	spin_unlock(&mounts_lock);
}

static inline unsigned long hash(struct vfsmount *mnt, struct dentry *dentry)
{
	unsigned long tmp = ((unsigned long)mnt / L1_CACHE_BYTES);
	tmp += ((unsigned long)dentry / L1_CACHE_BYTES);
	tmp = tmp + (tmp >> HASH_SHIFT);
	return tmp & (HASH_SIZE - 1);
}

#define MNT_WRITER_UNDERFLOW_LIMIT -(1<<16)

/* allocation is serialized by namespace_sem */
static int mnt_alloc_id(struct vfsmount *mnt)
{
	int res;

retry:
	ida_pre_get(&mnt_id_ida, GFP_KERNEL);
	spin_lock(&vfsmount_lock);
	res = ida_get_new_above(&mnt_id_ida, mnt_id_start, &mnt->mnt_id);
	if (!res)
		mnt_id_start = mnt->mnt_id + 1;
	spin_unlock(&vfsmount_lock);
	if (res == -EAGAIN)
		goto retry;

	return res;
}

static void mnt_free_id(struct vfsmount *mnt)
{
	int id = mnt->mnt_id;
	spin_lock(&vfsmount_lock);
	ida_remove(&mnt_id_ida, id);
	if (mnt_id_start > id)
		mnt_id_start = id;
	spin_unlock(&vfsmount_lock);
}

/*
 * Allocate a new peer group ID
 *
 * mnt_group_ida is protected by namespace_sem
 */
int mnt_alloc_group_id(struct vfsmount *mnt)
{
	int res;

	if (!ida_pre_get(&mnt_group_ida, GFP_KERNEL))
		return -ENOMEM;

	res = ida_get_new_above(&mnt_group_ida,
				mnt_group_start,
				&mnt->mnt_group_id);
	if (!res)
		mnt_group_start = mnt->mnt_group_id + 1;

	return res;
}
EXPORT_SYMBOL(mnt_alloc_group_id);

/*
 * Release a peer group ID
 */
void mnt_release_group_id(struct vfsmount *mnt)
{
	int id = mnt->mnt_group_id;
	ida_remove(&mnt_group_ida, id);
	if (mnt_group_start > id)
		mnt_group_start = id;
	mnt->mnt_group_id = 0;
}

/*
 * Operations with a big amount of mount points can require a lot of time.
 * This operations take the global lock namespace_sem, so they can affect
 * other containers.
 */

struct vfsmount *alloc_vfsmnt(const char *name)
{
	struct vfsmount *mnt;
	struct ve_struct *ve = get_exec_env();

	if (atomic_add_return(1, &ve->mnt_nr) > sysctl_ve_mount_nr &&
							!ve_is_super(ve))
		goto out_mnt_nr_dec;

	mnt = kmem_cache_zalloc(mnt_cache, GFP_KERNEL);
	if (mnt) {
		int err;

		err = mnt_alloc_id(mnt);
		if (err)
			goto out_free_cache;

		if (name) {
			mnt->mnt_devname = kstrdup(name, GFP_KERNEL_UBC);
			if (!mnt->mnt_devname)
				goto out_free_id;
		}

		mnt->owner = VEID(get_exec_env());
		atomic_set(&mnt->mnt_count, 1);
		INIT_LIST_HEAD(&mnt->mnt_hash);
		INIT_LIST_HEAD(&mnt->mnt_child);
		INIT_LIST_HEAD(&mnt->mnt_mounts);
		INIT_LIST_HEAD(&mnt->mnt_list);
		INIT_LIST_HEAD(&mnt->mnt_expire);
		INIT_LIST_HEAD(&mnt->mnt_share);
		INIT_LIST_HEAD(&mnt->mnt_slave_list);
		INIT_LIST_HEAD(&mnt->mnt_slave);
#ifdef CONFIG_SMP
		mnt->mnt_writers = alloc_percpu(int);
		if (!mnt->mnt_writers)
			goto out_free_devname;
#else
		mnt->mnt_writers = 0;
#endif
	} else
		goto out_mnt_nr_dec;

	return mnt;

#ifdef CONFIG_SMP
out_free_devname:
	kfree(mnt->mnt_devname);
#endif
out_free_id:
	mnt_free_id(mnt);
out_free_cache:
	kmem_cache_free(mnt_cache, mnt);
out_mnt_nr_dec:
	atomic_dec(&ve->mnt_nr);
	return NULL;
}

/*
 * Most r/o checks on a fs are for operations that take
 * discrete amounts of time, like a write() or unlink().
 * We must keep track of when those operations start
 * (for permission checks) and when they end, so that
 * we can determine when writes are able to occur to
 * a filesystem.
 */
/*
 * __mnt_is_readonly: check whether a mount is read-only
 * @mnt: the mount to check for its write status
 *
 * This shouldn't be used directly ouside of the VFS.
 * It does not guarantee that the filesystem will stay
 * r/w, just that it is right *now*.  This can not and
 * should not be used in place of IS_RDONLY(inode).
 * mnt_want/drop_write() will _keep_ the filesystem
 * r/w.
 */
int __mnt_is_readonly(struct vfsmount *mnt)
{
	if (mnt->mnt_flags & MNT_READONLY)
		return 1;
	if (mnt->mnt_sb->s_flags & MS_RDONLY)
		return 1;
	return 0;
}
EXPORT_SYMBOL_GPL(__mnt_is_readonly);

static inline void inc_mnt_writers(struct vfsmount *mnt)
{
#ifdef CONFIG_SMP
	(*per_cpu_ptr(mnt->mnt_writers, smp_processor_id()))++;
#else
	mnt->mnt_writers++;
#endif
}

static inline void dec_mnt_writers(struct vfsmount *mnt)
{
#ifdef CONFIG_SMP
	(*per_cpu_ptr(mnt->mnt_writers, smp_processor_id()))--;
#else
	mnt->mnt_writers--;
#endif
}

static unsigned int count_mnt_writers(struct vfsmount *mnt)
{
#ifdef CONFIG_SMP
	unsigned int count = 0;
	int cpu;

	for_each_possible_cpu(cpu) {
		count += *per_cpu_ptr(mnt->mnt_writers, cpu);
	}

	return count;
#else
	return mnt->mnt_writers;
#endif
}

/*
 * Most r/o & frozen checks on a fs are for operations that take discrete
 * amounts of time, like a write() or unlink().  We must keep track of when
 * those operations start (for permission checks) and when they end, so that we
 * can determine when writes are able to occur to a filesystem.
 */
/**
 * mnt_want_write - get write access to a mount without freeze protection
 * @mnt: the mount on which to take a write
 *
 * This tells the low-level filesystem that a write is about to be performed to
 * it, and makes sure that writes are allowed (mnt it read-write) before
 * returning success. This operation does not protect against filesystem being
 * frozen. When the write operation is finished, __mnt_drop_write() must be
 * called. This is effectively a refcount.
 */
int __mnt_want_write(struct vfsmount *mnt)
{
	int ret = 0;

	preempt_disable();
	inc_mnt_writers(mnt);
	/*
	 * The store to inc_mnt_writers must be visible before we pass
	 * MNT_WRITE_HOLD loop below, so that the slowpath can see our
	 * incremented count after it has set MNT_WRITE_HOLD.
	 */
	smp_mb();
	while (mnt->mnt_flags & MNT_WRITE_HOLD)
		cpu_relax();
	/*
	 * After the slowpath clears MNT_WRITE_HOLD, mnt_is_readonly will
	 * be set to match its requirements. So we must not load that until
	 * MNT_WRITE_HOLD is cleared.
	 */
	smp_rmb();
	if (__mnt_is_readonly(mnt)) {
		dec_mnt_writers(mnt);
		ret = -EROFS;
		goto out;
	}
out:
	preempt_enable();

	return ret;
}
EXPORT_SYMBOL_GPL(__mnt_want_write);

/**
 * mnt_want_write - get write access to a mount
 * @m: the mount on which to take a write
 *
 * This tells the low-level filesystem that a write is about to be performed to
 * it, and makes sure that writes are allowed (mount is read-write, filesystem
 * is not frozen) before returning success.  When the write operation is
 * finished, mnt_drop_write() must be called.  This is effectively a refcount.
 */
int mnt_want_write(struct vfsmount *m)
{
	int ret;

	sb_start_write(m->mnt_sb);
	ret = __mnt_want_write(m);
	if (ret)
		sb_end_write(m->mnt_sb);
	return ret;
}
EXPORT_SYMBOL(mnt_want_write);

/**
 * mnt_clone_write - get write access to a mount
 * @mnt: the mount on which to take a write
 *
 * This is effectively like mnt_want_write, except
 * it must only be used to take an extra write reference
 * on a mountpoint that we already know has a write reference
 * on it. This allows some optimisation.
 *
 * After finished, mnt_drop_write must be called as usual to
 * drop the reference.
 */
int mnt_clone_write(struct vfsmount *mnt)
{
	/* superblock may be r/o */
	if (__mnt_is_readonly(mnt))
		return -EROFS;
	preempt_disable();
	inc_mnt_writers(mnt);
	preempt_enable();
	return 0;
}
EXPORT_SYMBOL_GPL(mnt_clone_write);

/**
 * __mnt_want_write_file - get write access to a file's mount
 * @file: the file who's mount on which to take a write
 *
 * This is like mnt_want_write, but it takes a file and can
 * do some optimisations if the file is open for write already
 */
int __mnt_want_write_file(struct file *file)
{
	struct inode *inode = file->f_dentry->d_inode;
	if (!(file->f_mode & FMODE_WRITE) || special_file(inode->i_mode))
		return __mnt_want_write(file->f_path.mnt);
	else
		return mnt_clone_write(file->f_path.mnt);
}
EXPORT_SYMBOL_GPL(__mnt_want_write_file);

/**
 * mnt_want_write_file - get write access to a file's mount
 * @file: the file who's mount on which to take a write
 *
 * This is like mnt_want_write, but it takes a file and can
 * do some optimisations if the file is open for write already
 */
int mnt_want_write_file(struct file *file)
{
	int ret;

	sb_start_write(file->f_path.mnt->mnt_sb);
	ret = __mnt_want_write_file(file);
	if (ret)
		sb_end_write(file->f_path.mnt->mnt_sb);
	return ret;
}
EXPORT_SYMBOL_GPL(mnt_want_write_file);

/**
 * __mnt_drop_write - give up write access to a mount
 * @mnt: the mount on which to give up write access
 *
 * Tells the low-level filesystem that we are done
 * performing writes to it.  Must be matched with
 * __mnt_want_write() call above.
 */
void __mnt_drop_write(struct vfsmount *mnt)
{
	preempt_disable();
	dec_mnt_writers(mnt);
	preempt_enable();
}
EXPORT_SYMBOL_GPL(__mnt_drop_write);

/**
 * mnt_drop_write - give up write access to a mount
 * @mnt: the mount on which to give up write access
 *
 * Tells the low-level filesystem that we are done performing writes to it and
 * also allows filesystem to be frozen again.  Must be matched with
 * mnt_want_write() call above.
 */
void mnt_drop_write(struct vfsmount *mnt)
{
	__mnt_drop_write(mnt);
	sb_end_write(mnt->mnt_sb);
}
EXPORT_SYMBOL(mnt_drop_write);

void __mnt_drop_write_file(struct file *file)
{
	__mnt_drop_write(file->f_path.mnt);
}
EXPORT_SYMBOL(__mnt_drop_write_file);

void mnt_drop_write_file(struct file *file)
{
	mnt_drop_write(file->f_path.mnt);
}
EXPORT_SYMBOL(mnt_drop_write_file);

static int mnt_make_readonly(struct vfsmount *mnt)
{
	int ret = 0;

	spin_lock(&vfsmount_lock);
	mnt->mnt_flags |= MNT_WRITE_HOLD;
	/*
	 * After storing MNT_WRITE_HOLD, we'll read the counters. This store
	 * should be visible before we do.
	 */
	smp_mb();

	/*
	 * With writers on hold, if this value is zero, then there are
	 * definitely no active writers (although held writers may subsequently
	 * increment the count, they'll have to wait, and decrement it after
	 * seeing MNT_READONLY).
	 *
	 * It is OK to have counter incremented on one CPU and decremented on
	 * another: the sum will add up correctly. The danger would be when we
	 * sum up each counter, if we read a counter before it is incremented,
	 * but then read another CPU's count which it has been subsequently
	 * decremented from -- we would see more decrements than we should.
	 * MNT_WRITE_HOLD protects against this scenario, because
	 * mnt_want_write first increments count, then smp_mb, then spins on
	 * MNT_WRITE_HOLD, so it can't be decremented by another CPU while
	 * we're counting up here.
	 */
	if (count_mnt_writers(mnt) > 0)
		ret = -EBUSY;
	else
		mnt->mnt_flags |= MNT_READONLY;
	/*
	 * MNT_READONLY must become visible before ~MNT_WRITE_HOLD, so writers
	 * that become unheld will see MNT_READONLY.
	 */
	smp_wmb();
	mnt->mnt_flags &= ~MNT_WRITE_HOLD;
	spin_unlock(&vfsmount_lock);
	return ret;
}

static void __mnt_unmake_readonly(struct vfsmount *mnt)
{
	spin_lock(&vfsmount_lock);
	mnt->mnt_flags &= ~MNT_READONLY;
	spin_unlock(&vfsmount_lock);
}

void simple_set_mnt(struct vfsmount *mnt, struct super_block *sb)
{
	mnt->mnt_sb = sb;
	mnt->mnt_root = dget(sb->s_root);
}

EXPORT_SYMBOL(simple_set_mnt);

void free_vfsmnt(struct vfsmount *mnt)
{
	struct ve_struct *ve = get_ve_by_id(mnt->owner);

	if (ve) {
		atomic_dec(&ve->mnt_nr);
		put_ve(ve);
	}

	kfree(mnt->mnt_devname);
	mnt_free_id(mnt);
#ifdef CONFIG_SMP
	free_percpu(mnt->mnt_writers);
#endif
	kmem_cache_free(mnt_cache, mnt);
}

/*
 * find the first or last mount at @dentry on vfsmount @mnt depending on
 * @dir. If @dir is set return the first mount else return the last mount.
 */
struct vfsmount *__lookup_mnt(struct vfsmount *mnt, struct dentry *dentry,
			      int dir)
{
	struct list_head *head = mount_hashtable + hash(mnt, dentry);
	struct list_head *tmp = head;
	struct vfsmount *p, *found = NULL;

	for (;;) {
		tmp = dir ? tmp->next : tmp->prev;
		p = NULL;
		if (tmp == head)
			break;
		p = list_entry(tmp, struct vfsmount, mnt_hash);
		if (p->mnt_parent == mnt && p->mnt_mountpoint == dentry) {
			found = p;
			break;
		}
	}
	return found;
}

/*
 * lookup_mnt increments the ref count before returning
 * the vfsmount struct.
 */
struct vfsmount *lookup_mnt(struct path *path)
{
	struct vfsmount *child_mnt;
	spin_lock(&vfsmount_lock);
	if ((child_mnt = __lookup_mnt(path->mnt, path->dentry, 1)))
		mntget(child_mnt);
	spin_unlock(&vfsmount_lock);
	return child_mnt;
}

static inline int check_mnt(struct vfsmount *mnt)
{
	return mnt->mnt_ns == current->nsproxy->mnt_ns;
}

#ifdef CONFIG_VE
void get_mnt_poll(struct mnt_namespace *ns,
		  wait_queue_head_t **ppoll, int **pevent)
{
	struct ve_struct *ve = get_exec_env();

	if (ns == init_task.nsproxy->mnt_ns) {
		*ppoll = &ve->mnt_poll;
		*pevent = &ve->mnt_event;
	} else {
		*ppoll = &ns->poll;
		*pevent = &ns->event;
	}
}
#endif

static void touch_mnt_namespace(struct mnt_namespace *ns)
{
	wait_queue_head_t *ppoll;
	int *pevent;

	if (ns) {
		get_mnt_poll(ns, &ppoll, &pevent);
		*pevent = ++event;
		wake_up_interruptible(ppoll);
	}
}

static void __touch_mnt_namespace(struct mnt_namespace *ns)
{
	wait_queue_head_t *ppoll;
	int *pevent;

	if (ns) {
		get_mnt_poll(ns, &ppoll, &pevent);
		if (*pevent != event) {
			*pevent = event;
			wake_up_interruptible(ppoll);
		}
	}
}

static void detach_mnt(struct vfsmount *mnt, struct path *old_path)
{
	old_path->dentry = mnt->mnt_mountpoint;
	old_path->mnt = mnt->mnt_parent;
	mnt->mnt_parent = mnt;
	mnt->mnt_mountpoint = mnt->mnt_root;
	list_del_init(&mnt->mnt_child);
	list_del_init(&mnt->mnt_hash);
	old_path->dentry->d_mounted--;
}

void mnt_set_mountpoint(struct vfsmount *mnt, struct dentry *dentry,
			struct vfsmount *child_mnt)
{
	child_mnt->mnt_parent = mntget(mnt);
	child_mnt->mnt_mountpoint = dget(dentry);
	dentry->d_mounted++;
}

static void attach_mnt(struct vfsmount *mnt, struct path *path)
{
	mnt_set_mountpoint(path->mnt, path->dentry, mnt);
	list_add_tail(&mnt->mnt_hash, mount_hashtable +
			hash(path->mnt, path->dentry));
	list_add_tail(&mnt->mnt_child, &path->mnt->mnt_mounts);
}

/*
 * the caller must hold vfsmount_lock
 */
static void commit_tree(struct vfsmount *mnt)
{
	struct vfsmount *parent = mnt->mnt_parent;
	struct vfsmount *m;
	LIST_HEAD(head);
	struct mnt_namespace *n = parent->mnt_ns;

	BUG_ON(parent == mnt);

	list_add_tail(&head, &mnt->mnt_list);
	list_for_each_entry(m, &head, mnt_list)
		m->mnt_ns = n;
	list_splice(&head, n->list.prev);

	list_add_tail(&mnt->mnt_hash, mount_hashtable +
				hash(parent, mnt->mnt_mountpoint));
	list_add_tail(&mnt->mnt_child, &parent->mnt_mounts);
	touch_mnt_namespace(n);
}

struct vfsmount *next_mnt(struct vfsmount *p, struct vfsmount *root)
{
	struct list_head *next = p->mnt_mounts.next;
	if (next == &p->mnt_mounts) {
		while (1) {
			if (p == root)
				return NULL;
			next = p->mnt_child.next;
			if (next != &p->mnt_parent->mnt_mounts)
				break;
			p = p->mnt_parent;
		}
	}
	return list_entry(next, struct vfsmount, mnt_child);
}
EXPORT_SYMBOL(next_mnt);

static struct vfsmount *skip_mnt_tree(struct vfsmount *p)
{
	struct list_head *prev = p->mnt_mounts.prev;
	while (prev != &p->mnt_mounts) {
		p = list_entry(prev, struct vfsmount, mnt_child);
		prev = p->mnt_mounts.prev;
	}
	return p;
}

static struct vfsmount *clone_mnt(struct vfsmount *old, struct dentry *root,
					int flag)
{
	struct super_block *sb = old->mnt_sb;
	struct vfsmount *mnt = alloc_vfsmnt(old->mnt_devname);

	if (mnt) {
		if (flag & (CL_SLAVE | CL_PRIVATE))
			mnt->mnt_group_id = 0; /* not a peer of original */
		else
			mnt->mnt_group_id = old->mnt_group_id;

		if ((flag & CL_MAKE_SHARED) && !mnt->mnt_group_id) {
			int err = mnt_alloc_group_id(mnt);
			if (err)
				goto out_free;
		}

		mnt->mnt_flags = old->mnt_flags;
		atomic_inc(&sb->s_active);
		mnt->mnt_sb = sb;
		mnt->mnt_root = dget(root);
		mnt->mnt_mountpoint = mnt->mnt_root;
		mnt->mnt_parent = mnt;

		if (flag & CL_SLAVE) {
			list_add(&mnt->mnt_slave, &old->mnt_slave_list);
			mnt->mnt_master = old;
			CLEAR_MNT_SHARED(mnt);
		} else if (!(flag & CL_PRIVATE)) {
			if ((flag & CL_PROPAGATION) || IS_MNT_SHARED(old))
				list_add(&mnt->mnt_share, &old->mnt_share);
			if (IS_MNT_SLAVE(old))
				list_add(&mnt->mnt_slave, &old->mnt_slave);
			mnt->mnt_master = old->mnt_master;
		}
		if (flag & CL_MAKE_SHARED)
			set_mnt_shared(mnt);

		/* stick the duplicate mount on the same expiry list
		 * as the original if that was on one */
		if (flag & CL_EXPIRE) {
			if (!list_empty(&old->mnt_expire))
				list_add(&mnt->mnt_expire, &old->mnt_expire);
		}
	}
	return mnt;

 out_free:
	free_vfsmnt(mnt);
	return NULL;
}

static struct vfsmount *__vfs_bind_mount(struct vfsmount *old, struct dentry *root, int flag)
{
	struct vfsmount *mnt;

	mnt = clone_mnt(old, root, flag);
	if (!mnt)
		return ERR_PTR(-ENOMEM);

	return mnt;
}

struct vfsmount *vfs_bind_mount_private(struct vfsmount *old, struct dentry *root)
{
	return __vfs_bind_mount(old, root, CL_PRIVATE);
}
EXPORT_SYMBOL(vfs_bind_mount_private);

struct vfsmount *vfs_bind_mount(struct vfsmount *old, struct dentry *root)
{
	return __vfs_bind_mount(old, root, 0);
}
EXPORT_SYMBOL_GPL(vfs_bind_mount);

static inline void __mntput(struct vfsmount *mnt)
{
	struct super_block *sb = mnt->mnt_sb;
	/*
	 * This probably indicates that somebody messed
	 * up a mnt_want/drop_write() pair.  If this
	 * happens, the filesystem was probably unable
	 * to make r/w->r/o transitions.
	 */
	/*
	 * atomic_dec_and_lock() used to deal with ->mnt_count decrements
	 * provides barriers, so count_mnt_writers() below is safe.  AV
	 */
	WARN_ON(count_mnt_writers(mnt));
	dput(mnt->mnt_root);
	free_vfsmnt(mnt);
	deactivate_super(sb);
}

void mntput_no_expire(struct vfsmount *mnt)
{
repeat:
	if (atomic_dec_and_lock(&mnt->mnt_count, &vfsmount_lock)) {
		if (likely(!mnt->mnt_pinned)) {
			spin_unlock(&vfsmount_lock);
			__mntput(mnt);
			return;
		}
		atomic_add(mnt->mnt_pinned + 1, &mnt->mnt_count);
		mnt->mnt_pinned = 0;
		spin_unlock(&vfsmount_lock);
		acct_auto_close_mnt(mnt);
		security_sb_umount_close(mnt);
		fsnotify_unmount_mnt(mnt);
		goto repeat;
	}
}

EXPORT_SYMBOL(mntput_no_expire);

void mnt_pin(struct vfsmount *mnt)
{
	spin_lock(&vfsmount_lock);
	mnt->mnt_pinned++;
	spin_unlock(&vfsmount_lock);
}

EXPORT_SYMBOL(mnt_pin);

void mnt_unpin(struct vfsmount *mnt)
{
	spin_lock(&vfsmount_lock);
	if (mnt->mnt_pinned) {
		atomic_inc(&mnt->mnt_count);
		mnt->mnt_pinned--;
	}
	spin_unlock(&vfsmount_lock);
}

EXPORT_SYMBOL(mnt_unpin);

static inline void mangle(struct seq_file *m, const char *s)
{
	seq_escape(m, s, " \t\n\\");
}

/*
 * Simple .show_options callback for filesystems which don't want to
 * implement more complex mount option showing.
 *
 * See also save_mount_options().
 */
int generic_show_options(struct seq_file *m, struct vfsmount *mnt)
{
	const char *options;

	rcu_read_lock();
	options = rcu_dereference(mnt->mnt_sb->s_options);

	if (options != NULL && options[0]) {
		seq_putc(m, ',');
		mangle(m, options);
	}
	rcu_read_unlock();

	return 0;
}
EXPORT_SYMBOL(generic_show_options);

/*
 * If filesystem uses generic_show_options(), this function should be
 * called from the fill_super() callback.
 *
 * The .remount_fs callback usually needs to be handled in a special
 * way, to make sure, that previous options are not overwritten if the
 * remount fails.
 *
 * Also note, that if the filesystem's .remount_fs function doesn't
 * reset all options to their default value, but changes only newly
 * given options, then the displayed options will not reflect reality
 * any more.
 */
void save_mount_options(struct super_block *sb, char *options)
{
	BUG_ON(sb->s_options);
	rcu_assign_pointer(sb->s_options, kstrdup(options, GFP_KERNEL));
}
EXPORT_SYMBOL(save_mount_options);

void replace_mount_options(struct super_block *sb, char *options)
{
	char *old = sb->s_options;
	rcu_assign_pointer(sb->s_options, options);
	if (old) {
		synchronize_rcu();
		kfree(old);
	}
}
EXPORT_SYMBOL(replace_mount_options);

#ifdef CONFIG_PROC_FS
/* iterator */
static void *m_start(struct seq_file *m, loff_t *pos)
{
	struct proc_mounts *p = m->private;

	down_read(&namespace_sem);
	if (p->iter_advanced) {
		p->iter_advanced = 0;
		if (p->iter_pos < *pos)
			p->iter_pos++;
	}

	if (!p->iter || (p->iter_pos > *pos && p->iter == &p->ns->list)) {
		p->iter = p->ns->list.next;
		p->iter_pos = 0;
	}

	while (p->iter_pos < *pos && p->iter != &p->ns->list) {
		p->iter = p->iter->next;
		p->iter_pos++;
	}

	while (p->iter_pos > *pos && p->iter != p->ns->list.next) {
		p->iter = p->iter->prev;
		p->iter_pos--;
	}

	p->iter_pos = *pos;
	return p->iter != &p->ns->list ? p->iter : NULL;
}

static void *m_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct proc_mounts *p = m->private;

	p->iter = p->iter->next;
	p->iter_pos++;
	*pos = p->iter_pos;
	return p->iter != &p->ns->list ? p->iter : NULL;
}

static void m_stop(struct seq_file *m, void *v)
{
	up_read(&namespace_sem);
}

struct proc_fs_info {
	int flag;
	const char *str;
};

static int show_sb_opts(struct seq_file *m, struct super_block *sb)
{
	static const struct proc_fs_info fs_info[] = {
		{ MS_SYNCHRONOUS, ",sync" },
		{ MS_DIRSYNC, ",dirsync" },
		{ MS_MANDLOCK, ",mand" },
		{ MS_LAZYTIME, ",lazytime" },
		{ 0, NULL }
	};
	const struct proc_fs_info *fs_infop;

	for (fs_infop = fs_info; fs_infop->flag; fs_infop++) {
		if (sb->s_flags & fs_infop->flag)
			seq_puts(m, fs_infop->str);
	}

	return security_sb_show_options(m, sb);
}

static void show_mnt_opts(struct seq_file *m, struct vfsmount *mnt)
{
	static const struct proc_fs_info mnt_info[] = {
		{ MNT_NOSUID, ",nosuid" },
		{ MNT_NODEV, ",nodev" },
		{ MNT_NOEXEC, ",noexec" },
		{ MNT_NOATIME, ",noatime" },
		{ MNT_NODIRATIME, ",nodiratime" },
		{ MNT_RELATIME, ",relatime" },
		{ MNT_STRICTATIME, ",strictatime" },
		{ 0, NULL }
	};
	const struct proc_fs_info *fs_infop;

	for (fs_infop = mnt_info; fs_infop->flag; fs_infop++) {
		if (mnt->mnt_flags & fs_infop->flag)
			seq_puts(m, fs_infop->str);
	}
}

static void show_type(struct seq_file *m, struct super_block *sb)
{
	if (!sb->s_op->show_type) {
		mangle(m, sb->s_type->name);
		if (sb->s_subtype && sb->s_subtype[0]) {
			seq_putc(m, '.');
			mangle(m, sb->s_subtype);
		}
	} else
	        sb->s_op->show_type(m, sb);
}

static int prepare_mnt_root_mangle(struct path *path,
		char **path_buf, char **ret_path)
{
	/* skip FS_NOMOUNT mounts (rootfs) */
	if (path->mnt->mnt_sb->s_flags & MS_NOUSER)
		return -EACCES;

	*path_buf = (char *)__get_free_page(GFP_KERNEL);
	if (!*path_buf)
		return -ENOMEM;

	*ret_path = d_path(path, *path_buf, PAGE_SIZE);
	if (IS_ERR(*ret_path)) {
		free_page((unsigned long)*path_buf);
		/*
		 * This means that the file position will be incremented, i.e.
		 * the total number of "invisible" vfsmnt will leak.
		 */
		return -EACCES;
	}
	return 0;
}

static int show_vfsmnt(struct seq_file *m, void *v)
{
	struct vfsmount *mnt = list_entry(v, struct vfsmount, mnt_list);
	int err;
	struct path mnt_path = { .dentry = mnt->mnt_root, .mnt = mnt };
	char *path_buf, *path;

	err = prepare_mnt_root_mangle(&mnt_path, &path_buf, &path);
	if (err < 0)
		return (err == -EACCES ? 0 : err);

	if (mnt->mnt_sb->s_op->show_devname) {
		err = mnt->mnt_sb->s_op->show_devname(m, mnt);
		if (err)
			goto out;
	} else {
		mangle(m, mnt->mnt_devname ? mnt->mnt_devname : "none");
	}
	seq_putc(m, ' ');
	mangle(m, path);
	free_page((unsigned long) path_buf);
	seq_putc(m, ' ');
	show_type(m, mnt->mnt_sb);
	seq_puts(m, __mnt_is_readonly(mnt) ? " ro" : " rw");
	err = show_sb_opts(m, mnt->mnt_sb);
	if (err)
		goto out;
	show_mnt_opts(m, mnt);
	if (mnt->mnt_sb->s_op->show_options)
		err = mnt->mnt_sb->s_op->show_options(m, mnt);
	seq_puts(m, " 0 0\n");
out:
	return err;
}

const struct seq_operations mounts_op = {
	.start	= m_start,
	.next	= m_next,
	.stop	= m_stop,
	.show	= show_vfsmnt
};

static int show_mountinfo(struct seq_file *m, void *v)
{
	struct proc_mounts *p = m->private;
	struct vfsmount *mnt = list_entry(v, struct vfsmount, mnt_list);
	struct super_block *sb = mnt->mnt_sb;
	struct path mnt_path = { .dentry = mnt->mnt_root, .mnt = mnt };
	struct path root = p->root;
	int err = 0;

	seq_printf(m, "%i %i %u:%u ", mnt->mnt_id, mnt->mnt_parent->mnt_id,
		   MAJOR(sb->s_dev), MINOR(sb->s_dev));
	if (sb->s_op->show_path)
		err = sb->s_op->show_path(m, mnt);
	else
		seq_dentry(m, mnt->mnt_root, " \t\n\\");
	if (err)
		goto out;
	seq_putc(m, ' ');
	err = seq_path_root(m, &mnt_path, &root, " \t\n\\");
	if (root.mnt != p->root.mnt || root.dentry != p->root.dentry ||
							err == -EINVAL) {
		/*
		 * Mountpoint is outside root, discard that one.  Ugly,
		 * but less so than trying to do that in iterator in a
		 * race-free way (due to renames).
		 */
		return SEQ_SKIP;
	}
	seq_puts(m, mnt->mnt_flags & MNT_READONLY ? " ro" : " rw");
	show_mnt_opts(m, mnt);

	/* Tagged fields ("foo:X" or "bar") */
	if (IS_MNT_SHARED(mnt))
		seq_printf(m, " shared:%i", mnt->mnt_group_id);
	if (IS_MNT_SLAVE(mnt)) {
		int master = mnt->mnt_master->mnt_group_id;
		int dom = get_dominating_id(mnt, &p->root);
		seq_printf(m, " master:%i", master);
		if (dom && dom != master)
			seq_printf(m, " propagate_from:%i", dom);
	}
	if (IS_MNT_UNBINDABLE(mnt))
		seq_puts(m, " unbindable");

	/* Filesystem specific data */
	seq_puts(m, " - ");
	show_type(m, sb);
	seq_putc(m, ' ');
	if (sb->s_op->show_devname) {
		err = sb->s_op->show_devname(m, mnt);
		if (err)
			goto out;
	} else
		mangle(m, mnt->mnt_devname ? mnt->mnt_devname : "none");
	seq_puts(m, sb->s_flags & MS_RDONLY ? " ro" : " rw");
	err = show_sb_opts(m, sb);
	if (err)
		goto out;
	if (sb->s_op->show_options)
		err = sb->s_op->show_options(m, mnt);
	seq_putc(m, '\n');
out:
	return err;
}

const struct seq_operations mountinfo_op = {
	.start	= m_start,
	.next	= m_next,
	.stop	= m_stop,
	.show	= show_mountinfo,
};

static int show_vfsstat(struct seq_file *m, void *v)
{
	struct vfsmount *mnt = list_entry(v, struct vfsmount, mnt_list);
	struct path mnt_path = { .dentry = mnt->mnt_root, .mnt = mnt };
	char *path_buf, *path;
	int err;

	err = prepare_mnt_root_mangle(&mnt_path, &path_buf, &path);
	if (err < 0)
		return (err == -EACCES ? 0 : err);

	/* device */
	if (mnt->mnt_sb->s_op->show_devname) {
		seq_puts(m, "device ");
		err = mnt->mnt_sb->s_op->show_devname(m, mnt);
	} else {
		if (mnt->mnt_devname) {
			seq_puts(m, "device ");
			mangle(m, mnt->mnt_devname);
		} else
			seq_puts(m, "no device");
	}

	/* mount point */
	seq_puts(m, " mounted on ");
	mangle(m, path);
	free_page((unsigned long)path_buf);
	seq_putc(m, ' ');

	/* file system type */
	seq_puts(m, "with fstype ");
	show_type(m, mnt->mnt_sb);

	/* optional statistics */
	if (mnt->mnt_sb->s_op->show_stats) {
		seq_putc(m, ' ');
		if (!err)
			err = mnt->mnt_sb->s_op->show_stats(m, mnt);
	}

	seq_putc(m, '\n');
	return err;
}

const struct seq_operations mountstats_op = {
	.start	= m_start,
	.next	= m_next,
	.stop	= m_stop,
	.show	= show_vfsstat,
};
#endif  /* CONFIG_PROC_FS */

/**
 * may_umount_tree - check if a mount tree is busy
 * @mnt: root of mount tree
 *
 * This is called to check if a tree of mounts has any
 * open files, pwds, chroots or sub mounts that are
 * busy.
 */
int may_umount_tree(struct vfsmount *mnt)
{
	int actual_refs = 0;
	int minimum_refs = 0;
	struct vfsmount *p;

	spin_lock(&vfsmount_lock);
	for (p = mnt; p; p = next_mnt(p, mnt)) {
		actual_refs += atomic_read(&p->mnt_count);
		minimum_refs += 2;
	}
	spin_unlock(&vfsmount_lock);

	if (actual_refs > minimum_refs)
		return 0;

	return 1;
}

EXPORT_SYMBOL(may_umount_tree);

/**
 * may_umount - check if a mount point is busy
 * @mnt: root of mount
 *
 * This is called to check if a mount point has any
 * open files, pwds, chroots or sub mounts. If the
 * mount has sub mounts this will return busy
 * regardless of whether the sub mounts are busy.
 *
 * Doesn't take quota and stuff into account. IOW, in some cases it will
 * give false negatives. The main reason why it's here is that we need
 * a non-destructive way to look for easily umountable filesystems.
 */
int may_umount(struct vfsmount *mnt)
{
	int ret = 1;
	spin_lock(&vfsmount_lock);
	if (propagate_mount_busy(mnt, 2))
		ret = 0;
	spin_unlock(&vfsmount_lock);
	return ret;
}

EXPORT_SYMBOL(may_umount);

void release_mounts(struct list_head *head)
{
	struct vfsmount *mnt;
	while (!list_empty(head)) {
		mnt = list_first_entry(head, struct vfsmount, mnt_hash);
		list_del_init(&mnt->mnt_hash);
		if (mnt->mnt_parent != mnt) {
			struct dentry *dentry;
			struct vfsmount *m;
			spin_lock(&vfsmount_lock);
			dentry = mnt->mnt_mountpoint;
			m = mnt->mnt_parent;
			mnt->mnt_mountpoint = mnt->mnt_root;
			mnt->mnt_parent = mnt;
			m->mnt_ghosts--;
			spin_unlock(&vfsmount_lock);
			dput(dentry);
			mntput(m);
		}
		mntput(mnt);
	}
}

void umount_tree(struct vfsmount *mnt, int propagate, struct list_head *kill)
{
	LIST_HEAD(tmp_list);
	struct vfsmount *p;

	for (p = mnt; p; p = next_mnt(p, mnt))
		list_move(&p->mnt_hash, &tmp_list);

	if (propagate)
		propagate_umount(&tmp_list);

	list_for_each_entry(p, &tmp_list, mnt_hash) {
		list_del_init(&p->mnt_expire);
		advance_mounts_readers(&p->mnt_list);
		list_del_init(&p->mnt_list);
		__touch_mnt_namespace(p->mnt_ns);
		p->mnt_ns = NULL;
		list_del_init(&p->mnt_child);
		if (p->mnt_parent != p) {
			p->mnt_parent->mnt_ghosts++;
			p->mnt_mountpoint->d_mounted--;
		}
		change_mnt_propagation(p, MS_PRIVATE);
	}
	list_splice(&tmp_list, kill);
}

static void shrink_submounts(struct vfsmount *mnt, struct list_head *umounts);

static int do_umount(struct vfsmount *mnt, int flags)
{
	struct super_block *sb = mnt->mnt_sb;
	int retval;
	LIST_HEAD(umount_list);

	retval = security_sb_umount(mnt, flags);
	if (retval)
		return retval;

	/*
	 * Allow userspace to request a mountpoint be expired rather than
	 * unmounting unconditionally. Unmount only happens if:
	 *  (1) the mark is already set (the mark is cleared by mntput())
	 *  (2) the usage count == 1 [parent vfsmount] + 1 [sys_umount]
	 */
	if (flags & MNT_EXPIRE) {
		if (mnt == current->fs->root.mnt ||
		    flags & (MNT_FORCE | MNT_DETACH))
			return -EINVAL;

		if (atomic_read(&mnt->mnt_count) != 2)
			return -EBUSY;

		if (!xchg(&mnt->mnt_expiry_mark, 1))
			return -EAGAIN;
	}

	/*
	 * If we may have to abort operations to get out of this
	 * mount, and they will themselves hold resources we must
	 * allow the fs to do things. In the Unix tradition of
	 * 'Gee thats tricky lets do it in userspace' the umount_begin
	 * might fail to complete on the first run through as other tasks
	 * must return, and the like. Thats for the mount program to worry
	 * about for the moment.
	 */

	if (flags & MNT_FORCE && sb->s_op->umount_begin) {
		sb->s_op->umount_begin(sb);
	}

	/*
	 * No sense to grab the lock for this test, but test itself looks
	 * somewhat bogus. Suggestions for better replacement?
	 * Ho-hum... In principle, we might treat that as umount + switch
	 * to rootfs. GC would eventually take care of the old vfsmount.
	 * Actually it makes sense, especially if rootfs would contain a
	 * /reboot - static binary that would close all descriptors and
	 * call reboot(9). Then init(8) could umount root and exec /reboot.
	 */
	if (mnt == current->fs->root.mnt && !(flags & MNT_DETACH)) {
		/*
		 * Special case for "unmounting" root ...
		 * we just try to remount it readonly.
		 */
		down_write(&sb->s_umount);
		if (!(sb->s_flags & MS_RDONLY))
			retval = do_remount_sb(sb, MS_RDONLY, NULL, 0);
		up_write(&sb->s_umount);
		return retval;
	}

	down_write(&namespace_sem);
	spin_lock(&vfsmount_lock);
	event++;

	if (!(flags & MNT_DETACH))
		shrink_submounts(mnt, &umount_list);

	retval = -EBUSY;
	if (flags & MNT_DETACH || !propagate_mount_busy(mnt, 2)) {
		if (!list_empty(&mnt->mnt_list))
			umount_tree(mnt, 1, &umount_list);
		retval = 0;
	}
	spin_unlock(&vfsmount_lock);
	if (retval)
		security_sb_umount_busy(mnt);
	up_write(&namespace_sem);
	release_mounts(&umount_list);
	return retval;
}

#ifdef CONFIG_VE
void umount_ve_fs_type(struct file_system_type *local_fs_type, int veid)
{
	struct vfsmount *mnt;
	LIST_HEAD(kill);
	LIST_HEAD(umount_list);

	down_write(&namespace_sem);
	spin_lock(&vfsmount_lock);
	list_for_each_entry(mnt, &current->nsproxy->mnt_ns->list, mnt_list) {
		if (mnt->mnt_sb->s_type != local_fs_type)
			continue;
		if (veid >= 0 && mnt->owner != veid)
			continue;
		list_move(&mnt->mnt_hash, &kill);
	}

	while (!list_empty(&kill)) {
		LIST_HEAD(kill2);
		mnt = list_entry(kill.next, struct vfsmount, mnt_hash);
		umount_tree(mnt, 1, &kill2);
		list_splice(&kill2, &umount_list);
	}
	spin_unlock(&vfsmount_lock);
	up_write(&namespace_sem);
	release_mounts(&umount_list);
}
EXPORT_SYMBOL(umount_ve_fs_type);
#endif

/*
 * Now umount can handle mount points as well as block devices.
 * This is important for filesystems which use unnamed block devices.
 *
 * We now support a flag for forced unmount like the other 'big iron'
 * unixes. Our API is identical to OSF/1 to avoid making a mess of AMD
 */

SYSCALL_DEFINE2(umount, char __user *, name, int, flags)
{
	struct path path;
	int retval;
	int lookup_flags = 0;

	if (flags & ~(MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW))
		return -EINVAL;

	if (!(flags & UMOUNT_NOFOLLOW))
		lookup_flags |= LOOKUP_FOLLOW;

	retval = user_path_mountpoint_at(AT_FDCWD, name, lookup_flags, &path);
	if (retval)
		goto out;
	retval = -EINVAL;
	if (path.dentry != path.mnt->mnt_root)
		goto dput_and_out;
	if (!check_mnt(path.mnt))
		goto dput_and_out;
	if (path.mnt->mnt_parent == path.mnt)
		goto dput_and_out;

	retval = -EPERM;
	if (!capable(CAP_VE_SYS_ADMIN) && !capable(CAP_SYS_ADMIN))
		goto dput_and_out;

	retval = do_umount(path.mnt, flags);
dput_and_out:
	/* we mustn't call path_put() as that would clear mnt_expiry_mark */
	dput(path.dentry);
	mntput_no_expire(path.mnt);
out:
	return retval;
}

#ifdef __ARCH_WANT_SYS_OLDUMOUNT

/*
 *	The 2.0 compatible umount. No flags.
 */
SYSCALL_DEFINE1(oldumount, char __user *, name)
{
	return sys_umount(name, 0);
}

#endif

static int mount_is_safe(struct path *path)
{
	if (capable(CAP_VE_SYS_ADMIN) || capable(CAP_SYS_ADMIN))
		return 0;
	return -EPERM;
#ifdef notyet
	if (S_ISLNK(path->dentry->d_inode->i_mode))
		return -EPERM;
	if (path->dentry->d_inode->i_mode & S_ISVTX) {
		if (current_uid() != path->dentry->d_inode->i_uid)
			return -EPERM;
	}
	if (inode_permission(path->dentry->d_inode, MAY_WRITE))
		return -EPERM;
	return 0;
#endif
}

static bool mnt_ns_loop(struct path *path)
{
	/* Could bind mounting the mount namespace inode cause a
	 * mount namespace loop?
	 */
	struct inode *inode = path->dentry->d_inode;
	struct proc_inode *ei;
	struct mnt_namespace *mnt_ns;

	if (!proc_ns_inode(inode))
		return false;

	ei = PROC_I(inode);
	if (ei->ns_ops != &mntns_operations)
		return false;

	mnt_ns = ei->ns;
	return current->nsproxy->mnt_ns->seq >= mnt_ns->seq;
}

struct vfsmount *copy_tree(struct vfsmount *mnt, struct dentry *dentry,
					int flag)
{
	struct vfsmount *res, *p, *q, *r, *s;
	struct path path;

	if (!(flag & CL_COPY_ALL) && IS_MNT_UNBINDABLE(mnt))
		return NULL;

	res = q = clone_mnt(mnt, dentry, flag);
	if (!q)
		goto Enomem;
	q->mnt_mountpoint = mnt->mnt_mountpoint;

	p = mnt;
	list_for_each_entry(r, &mnt->mnt_mounts, mnt_child) {
		if (!is_subdir(r->mnt_mountpoint, dentry))
			continue;

		for (s = r; s; s = next_mnt(s, r)) {
			if (!(flag & CL_COPY_ALL) && IS_MNT_UNBINDABLE(s)) {
				s = skip_mnt_tree(s);
				continue;
			}
			while (p != s->mnt_parent) {
				p = p->mnt_parent;
				q = q->mnt_parent;
			}
			p = s;
			path.mnt = q;
			path.dentry = p->mnt_mountpoint;
			q = clone_mnt(p, p->mnt_root, flag);
			if (!q)
				goto Enomem;
			spin_lock(&vfsmount_lock);
			list_add_tail(&q->mnt_list, &res->mnt_list);
			attach_mnt(q, &path);
			spin_unlock(&vfsmount_lock);
		}
	}
	return res;
Enomem:
	if (res) {
		LIST_HEAD(umount_list);
		spin_lock(&vfsmount_lock);
		umount_tree(res, 0, &umount_list);
		spin_unlock(&vfsmount_lock);
		release_mounts(&umount_list);
	}
	return NULL;
}

struct vfsmount *collect_mounts(struct path *path)
{
	struct vfsmount *tree;
	down_write(&namespace_sem);
	tree = copy_tree(path->mnt, path->dentry, CL_COPY_ALL | CL_PRIVATE);
	up_write(&namespace_sem);
	return tree;
}

void drop_collected_mounts(struct vfsmount *mnt)
{
	LIST_HEAD(umount_list);
	down_write(&namespace_sem);
	spin_lock(&vfsmount_lock);
	umount_tree(mnt, 0, &umount_list);
	spin_unlock(&vfsmount_lock);
	up_write(&namespace_sem);
	release_mounts(&umount_list);
}

static void cleanup_group_ids(struct vfsmount *mnt, struct vfsmount *end)
{
	struct vfsmount *p;

	for (p = mnt; p != end; p = next_mnt(p, mnt)) {
		if (p->mnt_group_id && !IS_MNT_SHARED(p))
			mnt_release_group_id(p);
	}
}

static int invent_group_ids(struct vfsmount *mnt, bool recurse)
{
	struct vfsmount *p;

	for (p = mnt; p; p = recurse ? next_mnt(p, mnt) : NULL) {
		if (!p->mnt_group_id && !IS_MNT_SHARED(p)) {
			int err = mnt_alloc_group_id(p);
			if (err) {
				cleanup_group_ids(mnt, p);
				return err;
			}
		}
	}

	return 0;
}

/*
 *  @source_mnt : mount tree to be attached
 *  @nd         : place the mount tree @source_mnt is attached
 *  @parent_nd  : if non-null, detach the source_mnt from its parent and
 *  		   store the parent mount and mountpoint dentry.
 *  		   (done when source_mnt is moved)
 *
 *  NOTE: in the table below explains the semantics when a source mount
 *  of a given type is attached to a destination mount of a given type.
 * ---------------------------------------------------------------------------
 * |         BIND MOUNT OPERATION                                            |
 * |**************************************************************************
 * | source-->| shared        |       private  |       slave    | unbindable |
 * | dest     |               |                |                |            |
 * |   |      |               |                |                |            |
 * |   v      |               |                |                |            |
 * |**************************************************************************
 * |  shared  | shared (++)   |     shared (+) |     shared(+++)|  invalid   |
 * |          |               |                |                |            |
 * |non-shared| shared (+)    |      private   |      slave (*) |  invalid   |
 * ***************************************************************************
 * A bind operation clones the source mount and mounts the clone on the
 * destination mount.
 *
 * (++)  the cloned mount is propagated to all the mounts in the propagation
 * 	 tree of the destination mount and the cloned mount is added to
 * 	 the peer group of the source mount.
 * (+)   the cloned mount is created under the destination mount and is marked
 *       as shared. The cloned mount is added to the peer group of the source
 *       mount.
 * (+++) the mount is propagated to all the mounts in the propagation tree
 *       of the destination mount and the cloned mount is made slave
 *       of the same master as that of the source mount. The cloned mount
 *       is marked as 'shared and slave'.
 * (*)   the cloned mount is made a slave of the same master as that of the
 * 	 source mount.
 *
 * ---------------------------------------------------------------------------
 * |         		MOVE MOUNT OPERATION                                 |
 * |**************************************************************************
 * | source-->| shared        |       private  |       slave    | unbindable |
 * | dest     |               |                |                |            |
 * |   |      |               |                |                |            |
 * |   v      |               |                |                |            |
 * |**************************************************************************
 * |  shared  | shared (+)    |     shared (+) |    shared(+++) |  invalid   |
 * |          |               |                |                |            |
 * |non-shared| shared (+*)   |      private   |    slave (*)   | unbindable |
 * ***************************************************************************
 *
 * (+)  the mount is moved to the destination. And is then propagated to
 * 	all the mounts in the propagation tree of the destination mount.
 * (+*)  the mount is moved to the destination.
 * (+++)  the mount is moved to the destination and is then propagated to
 * 	all the mounts belonging to the destination mount's propagation tree.
 * 	the mount is marked as 'shared and slave'.
 * (*)	the mount continues to be a slave at the new location.
 *
 * if the source mount is a tree, the operations explained above is
 * applied to each mount in the tree.
 * Must be called without spinlocks held, since this function can sleep
 * in allocations.
 */
static int attach_recursive_mnt(struct vfsmount *source_mnt,
			struct path *path, struct path *parent_path)
{
	LIST_HEAD(tree_list);
	struct vfsmount *dest_mnt = path->mnt;
	struct dentry *dest_dentry = path->dentry;
	struct vfsmount *child, *p;
	int err;

	if (source_mnt->mnt_flags & MNT_CPT)
		goto lock;

	if (IS_MNT_SHARED(dest_mnt)) {
		err = invent_group_ids(source_mnt, true);
		if (err)
			goto out;
	}
	err = propagate_mnt(dest_mnt, dest_dentry, source_mnt, &tree_list);
	if (err)
		goto out_cleanup_ids;

	if (IS_MNT_SHARED(dest_mnt)) {
		for (p = source_mnt; p; p = next_mnt(p, source_mnt))
			set_mnt_shared(p);
	}
lock:
	spin_lock(&vfsmount_lock);
	if (parent_path) {
		detach_mnt(source_mnt, parent_path);
		attach_mnt(source_mnt, path);
		touch_mnt_namespace(parent_path->mnt->mnt_ns);
	} else {
		mnt_set_mountpoint(dest_mnt, dest_dentry, source_mnt);
		commit_tree(source_mnt);
	}

	list_for_each_entry_safe(child, p, &tree_list, mnt_hash) {
		list_del_init(&child->mnt_hash);
		commit_tree(child);
	}
	spin_unlock(&vfsmount_lock);
	return 0;

 out_cleanup_ids:
	if (IS_MNT_SHARED(dest_mnt))
		cleanup_group_ids(source_mnt, NULL);
 out:
	return err;
}

void replace_mount(struct vfsmount *src_mnt, struct vfsmount *dst_mnt)
{
	struct nameidata src_nd, dst_nd;
	LIST_HEAD(umount_list);

	down_write(&namespace_sem);
	spin_lock(&vfsmount_lock);

	detach_mnt(dst_mnt, &dst_nd.path);
	umount_tree(dst_mnt, 0, &umount_list);

	if (src_mnt->mnt_parent != src_mnt) {
		detach_mnt(src_mnt, &src_nd.path);
		attach_mnt(src_mnt, &dst_nd.path);
	} else {
		memset(&src_nd, 0, sizeof(src_nd));
		mnt_set_mountpoint(dst_nd.path.mnt, dst_nd.path.dentry, src_mnt);
		commit_tree(src_mnt);
	}

	spin_unlock(&vfsmount_lock);
	up_write(&namespace_sem);

	path_put(&src_nd.path);
	path_put(&dst_nd.path);
	release_mounts(&umount_list);

	return;
}
EXPORT_SYMBOL_GPL(replace_mount);

static int graft_tree(struct vfsmount *mnt, struct path *path)
{
	int err;
	if (mnt->mnt_sb->s_flags & MS_NOUSER)
		return -EINVAL;

	if (S_ISDIR(path->dentry->d_inode->i_mode) !=
	      S_ISDIR(mnt->mnt_root->d_inode->i_mode))
		return -ENOTDIR;

	err = -ENOENT;
	mutex_lock(&path->dentry->d_inode->i_mutex);
	if (IS_DEADDIR(path->dentry->d_inode))
		goto out_unlock;

	err = security_sb_check_sb(mnt, path);
	if (err)
		goto out_unlock;

	err = -ENOENT;
	if (!d_unlinked(path->dentry))
		err = attach_recursive_mnt(mnt, path, NULL);
out_unlock:
	mutex_unlock(&path->dentry->d_inode->i_mutex);
	if (!err)
		security_sb_post_addmount(mnt, path);
	return err;
}

/*
 * recursively change the type of the mountpoint.
 */
static int do_change_type(struct path *path, int flag)
{
	struct vfsmount *m, *mnt = path->mnt;
	int recurse = flag & MS_REC;
	int type = flag & ~MS_REC;
	int err = 0;

	if (!capable(CAP_SYS_ADMIN) && !capable(CAP_VE_SYS_ADMIN))
		return -EPERM;

	if (path->dentry != path->mnt->mnt_root)
		return -EINVAL;

	if (!ve_accessible_veid(path->mnt->owner, get_exec_env()->veid))
		return -EPERM;

	down_write(&namespace_sem);
	if (type == MS_SHARED) {
		err = invent_group_ids(mnt, recurse);
		if (err)
			goto out_unlock;
	}

	spin_lock(&vfsmount_lock);
	for (m = mnt; m; m = (recurse ? next_mnt(m, mnt) : NULL))
		change_mnt_propagation(m, type);
	spin_unlock(&vfsmount_lock);

 out_unlock:
	up_write(&namespace_sem);
	return err;
}

/*
 * do loopback mount.
 */
static int do_loopback(struct path *path, char *old_name,
				int recurse, int mnt_flags)
{
	struct path old_path;
	struct vfsmount *mnt = NULL;
	int err = mount_is_safe(path);
	if (err)
		return err;
	if (!old_name || !*old_name)
		return -EINVAL;
	err = kern_path(old_name, LOOKUP_FOLLOW|LOOKUP_AUTOMOUNT, &old_path);
	if (err)
		return err;

	err = -EINVAL;
	if (mnt_ns_loop(&old_path))
		goto out_path;

	down_write(&namespace_sem);
	err = -EINVAL;
	if (IS_MNT_UNBINDABLE(old_path.mnt))
		goto out;

	if (!check_mnt(path->mnt) || !check_mnt(old_path.mnt))
		goto out;

	err = -ENOMEM;
	if (recurse)
		mnt = copy_tree(old_path.mnt, old_path.dentry, 0);
	else
		mnt = clone_mnt(old_path.mnt, old_path.dentry, 0);

	if (!mnt)
		goto out;

	mnt->mnt_flags |= mnt_flags;
	err = graft_tree(mnt, path);
	if (err) {
		LIST_HEAD(umount_list);
		spin_lock(&vfsmount_lock);
		umount_tree(mnt, 0, &umount_list);
		spin_unlock(&vfsmount_lock);
		release_mounts(&umount_list);
	}

out:
	up_write(&namespace_sem);
out_path:
	path_put(&old_path);
	return err;
}

static int change_mount_flags(struct vfsmount *mnt, int ms_flags)
{
	int error = 0;
	int readonly_request = 0;

	if (ms_flags & MS_RDONLY)
		readonly_request = 1;
	if (readonly_request == __mnt_is_readonly(mnt))
		return 0;

	if (readonly_request)
		error = mnt_make_readonly(mnt);
	else
		__mnt_unmake_readonly(mnt);
	return error;
}

static inline int ve_remount_allowed(struct vfsmount *mnt, int flags, int mnt_flags)
{
	struct ve_struct *ve = get_exec_env();
	struct super_block *sb = mnt->mnt_sb;

	if (ve_accessible_veid(mnt->owner, ve->veid))
		return 0;

	if (mnt != ve->root_path.mnt)
		return -EPERM;
	if ((sb->s_flags ^ flags) & MS_RMT_MASK & ~MS_VE_RMT_MASK)
		return -EPERM;
	if ((mnt->mnt_flags ^ mnt_flags) & ~MNT_VE_RMT_MASK)
		return -EPERM;

	return 0;
}

#ifdef CONFIG_VE
/*
 * Returns first occurrence of needle in haystack separated by sep,
 * or NULL if not found
 */
static char *strstr_separated(char *haystack, char *needle, char sep)
{
	int needle_len = strlen(needle);

	while (haystack) {
		if (!strncmp(haystack, needle, needle_len) &&
		    (haystack[needle_len] == 0 || /* end-of-line or */
		     haystack[needle_len] == sep)) /* separator */
			return haystack;

		haystack = strchr(haystack, sep);
		if (haystack)
			haystack++;
	}

	return NULL;
}

static int ve_devmnt_check(char *options, char *allowed)
{
	char *p;

	if (!options || !*options)
		return 0;

	if (!allowed)
		return -EPERM;

	while ((p = strsep(&options, ",")) != NULL) {
		if (!*p)
			continue;

		if (!strstr_separated(allowed, p, ','))
			return -EPERM;
	}

	return 0;
}

static int ve_devmnt_insert(char *options, char *hidden)
{
	int options_len;
	int hidden_len;

	if (!hidden)
		return 0;

	if (!options)
		return -EAGAIN;

	options_len = strlen(options);
	hidden_len = strlen(hidden);
	
	if (hidden_len + options_len + 2 > PAGE_SIZE)
		return -EPERM;

	memmove(options + hidden_len + 1, options, options_len);
	memcpy(options, hidden, hidden_len);

	options[hidden_len] = ',';
	options[hidden_len + options_len + 1] = 0;
		
	return 0;
}

int ve_devmnt_process(struct ve_struct *ve, dev_t dev, void **data_pp, int remount)
{
	void *data = *data_pp;
	struct ve_devmnt *devmnt;
	int err;
again:
	err = 1;
	mutex_lock(&ve->devmnt_mutex);
	list_for_each_entry(devmnt, &ve->devmnt_list, link) {
		if (devmnt->dev == dev) {
			err = ve_devmnt_check(data, devmnt->allowed_options);

			if (!err && !remount)
				err = ve_devmnt_insert(data, devmnt->hidden_options);

			break;
		}
	}
	mutex_unlock(&ve->devmnt_mutex);

	switch (err) {
	case -EAGAIN:
		if (!(data = (void *)__get_free_page(GFP_KERNEL)))
			return -ENOMEM;
		*(char *)data = 0; /* the string must be zero-terminated */
		goto again;
	case 1:
		if (*data_pp) {
			ve_printk(VE_LOG_BOTH, KERN_WARNING "VE%u: no allowed "
				  "mount options found for device %u:%u\n",
				  ve->veid, MAJOR(dev), MINOR(dev));
			err = -EPERM;
		} else
			err = 0;
		break;
	case 0:
		*data_pp = data;
		break;
	}

	if (data && data != *data_pp)
		free_page((unsigned long)data);

	return err;
}
#endif

static int do_check_and_remount_sb(struct super_block *sb, int flags, void *data)
{
#ifdef CONFIG_VE
	struct ve_struct *ve = get_exec_env();

	if (sb->s_bdev && data && !ve_is_super(ve)) {
		int err;

		err = ve_devmnt_process(ve, sb->s_bdev->bd_dev, &data, 1);
		if (err)
			return err;
		
	}
#endif
	return do_remount_sb(sb, flags, data, 0);
}

/*
 * change filesystem flags. dir should be a physical root of filesystem.
 * If you've mounted a non-root directory somewhere and want to do remount
 * on it - tough luck.
 */
int do_remount(struct path *path, int flags, int mnt_flags, void *data)
{
	int err;
	struct super_block *sb = path->mnt->mnt_sb;

	if (!capable(CAP_VE_SYS_ADMIN) && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (!check_mnt(path->mnt))
		return -EINVAL;

	if (path->dentry != path->mnt->mnt_root)
		return -EINVAL;

	err = ve_remount_allowed(path->mnt, flags, mnt_flags);
	if (err)
		return err;

	err = security_sb_remount(sb, data);
	if (err)
		return err;

	down_write(&sb->s_umount);
	if (flags & MS_BIND)
		err = change_mount_flags(path->mnt, flags);
	else
		err = do_check_and_remount_sb(sb, flags, data);
	if (!err)
		path->mnt->mnt_flags = mnt_flags;
	up_write(&sb->s_umount);
	if (!err) {
		security_sb_post_remount(path->mnt, flags, data);

		spin_lock(&vfsmount_lock);
		touch_mnt_namespace(path->mnt->mnt_ns);
		spin_unlock(&vfsmount_lock);
	}
	return err;
}
EXPORT_SYMBOL(do_remount);

static inline int tree_contains_unbindable(struct vfsmount *mnt)
{
	struct vfsmount *p;
	for (p = mnt; p; p = next_mnt(p, mnt)) {
		if (IS_MNT_UNBINDABLE(p))
			return 1;
	}
	return 0;
}

static int do_move_mount(struct path *path, char *old_name)
{
	struct path old_path, parent_path;
	struct vfsmount *p;
	int err = 0;
	if (!capable(CAP_VE_SYS_ADMIN) && !capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (!old_name || !*old_name)
		return -EINVAL;
	err = kern_path(old_name, LOOKUP_FOLLOW, &old_path);
	if (err)
		return err;

	err = -EPERM;
	if (!ve_accessible_veid(old_path.mnt->owner, get_exec_env()->veid))
		goto out_nosem;

	down_write(&namespace_sem);
	err = __follow_down(path, true);
	if (err < 0)
		goto out;

	err = -EINVAL;
	if (!check_mnt(path->mnt) || !check_mnt(old_path.mnt))
		goto out;

	err = -ENOENT;
	mutex_lock(&path->dentry->d_inode->i_mutex);
	if (IS_DEADDIR(path->dentry->d_inode))
		goto out1;

	if (d_unlinked(path->dentry))
		goto out1;

	err = -EINVAL;
	if (old_path.dentry != old_path.mnt->mnt_root)
		goto out1;

	if (old_path.mnt == old_path.mnt->mnt_parent)
		goto out1;

	if (S_ISDIR(path->dentry->d_inode->i_mode) !=
	      S_ISDIR(old_path.dentry->d_inode->i_mode))
		goto out1;
	/*
	 * Don't move a mount residing in a shared parent.
	 */
	if (old_path.mnt->mnt_parent &&
	    IS_MNT_SHARED(old_path.mnt->mnt_parent))
		goto out1;
	/*
	 * Don't move a mount tree containing unbindable mounts to a destination
	 * mount which is shared.
	 */
	if (IS_MNT_SHARED(path->mnt) &&
	    tree_contains_unbindable(old_path.mnt))
		goto out1;
	err = -ELOOP;
	for (p = path->mnt; p->mnt_parent != p; p = p->mnt_parent)
		if (p == old_path.mnt)
			goto out1;

	err = attach_recursive_mnt(old_path.mnt, path, &parent_path);
	if (err)
		goto out1;

	/* if the mount is moved, it should no longer be expire
	 * automatically */
	list_del_init(&old_path.mnt->mnt_expire);
out1:
	mutex_unlock(&path->dentry->d_inode->i_mutex);
out:
	up_write(&namespace_sem);
	if (!err)
		path_put(&parent_path);
out_nosem:
	path_put(&old_path);
	return err;
}

static int __do_add_mount(struct vfsmount *, struct path *, int);

/*
 * create a new mount for userspace and request it to be added into the
 * namespace's tree
 */
static int do_new_mount(struct path *path, char *type, int flags,
			int mnt_flags, char *name, void *data)
{
	struct vfsmount *mnt;
	int err;

	if (!type)
		return -EINVAL;

	/* we need capabilities... */
	if (!capable(CAP_VE_SYS_ADMIN) && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	lock_kernel();
	mnt = do_kern_mount(type, flags, name, data);
	unlock_kernel();
	if (IS_ERR(mnt))
		return PTR_ERR(mnt);

	err = __do_add_mount(mnt, path, mnt_flags);
	if (err)
		mntput(mnt);
	return err;
}

int finish_automount(struct vfsmount *m, struct path *path)
{
	int err;
	/* The new mount record should have at least 2 refs to prevent it being
	 * expired before we get a chance to add it
	 */
	BUG_ON(atomic_read(&m->mnt_count) < 2);

	if (m->mnt_sb == path->mnt->mnt_sb &&
	    m->mnt_root == path->dentry) {
		err = -ELOOP;
		goto fail;
	}

	err = __do_add_mount(m, path, path->mnt->mnt_flags | MNT_SHRINKABLE);
	if (!err)
		return 0;
fail:
	/* remove m from any expiration list it may be on */
	if (!list_empty(&m->mnt_expire)) {
		down_write(&namespace_sem);
		spin_lock(&vfsmount_lock);
		list_del_init(&m->mnt_expire);
		spin_unlock(&vfsmount_lock);
		up_write(&namespace_sem);
	}
	mntput(m);
	mntput(m);
	return err;
}

/*
 * add a mount into a namespace's mount tree
 */
static int do_add_mount_unlocked(struct vfsmount *newmnt, struct path *path, int mnt_flags)
{
	int err;

	/* Something was mounted here while we slept */
	err = __follow_down(path, true);
	if (err < 0)
		goto unlock;

	err = -EINVAL;
	if (!(mnt_flags & (MNT_SHRINKABLE | MNT_CPT)) && !check_mnt(path->mnt))
		goto unlock;

        /* and in any case, we want non-NULL ->mnt_ns */
        if (!path->mnt->mnt_ns)
                goto unlock;

	/* Refuse the same filesystem on the same mount point */
	err = -EBUSY;
	if (!(mnt_flags & MNT_CPT) &&
	    path->mnt->mnt_sb == newmnt->mnt_sb &&
	    path->mnt->mnt_root == path->dentry)
		goto unlock;

	err = -EINVAL;
	if (S_ISLNK(newmnt->mnt_root->d_inode->i_mode))
		goto unlock;

	newmnt->mnt_flags = mnt_flags;
	err = graft_tree(newmnt, path);

unlock:
	return err;
}

/*
 * add a mount into a namespace's mount tree
 */
static int __do_add_mount(struct vfsmount *newmnt, struct path *path, int mnt_flags)
{
	int err;

	down_write(&namespace_sem);
	err = do_add_mount_unlocked(newmnt, path, mnt_flags);
	up_write(&namespace_sem);
	return err;
}

int do_add_mount(struct vfsmount *newmnt, struct path *path,
		 int mnt_flags, struct list_head *fslist)
{
	int err;

	down_write(&namespace_sem);
	err = do_add_mount_unlocked(newmnt, path, mnt_flags);
	if (!err) {
		if (fslist) /* add to the specified expiration list */
			list_add_tail(&newmnt->mnt_expire, fslist);
	}
	up_write(&namespace_sem);
	if (err)
		mntput(newmnt);
	return err;
}
EXPORT_SYMBOL_GPL(do_add_mount);

/**
 * mnt_set_expiry - Put a mount on an expiration list
 * @mnt: The mount to list.
 * @expiry_list: The list to add the mount to.
 */
void mnt_set_expiry(struct vfsmount *mnt, struct list_head *expiry_list)
{
	down_write(&namespace_sem);
	spin_lock(&vfsmount_lock);

	list_add_tail(&mnt->mnt_expire, expiry_list);

	spin_unlock(&vfsmount_lock);
	up_write(&namespace_sem);
}
EXPORT_SYMBOL(mnt_set_expiry);

/*
 * process a list of expirable mountpoints with the intent of discarding any
 * mountpoints that aren't in use and haven't been touched since last we came
 * here
 */
void mark_mounts_for_expiry(struct list_head *mounts)
{
	struct vfsmount *mnt, *next;
	LIST_HEAD(graveyard);
	LIST_HEAD(umounts);

	if (list_empty(mounts))
		return;

	down_write(&namespace_sem);
	spin_lock(&vfsmount_lock);

	/* extract from the expiration list every vfsmount that matches the
	 * following criteria:
	 * - only referenced by its parent vfsmount
	 * - still marked for expiry (marked on the last call here; marks are
	 *   cleared by mntput())
	 */
	list_for_each_entry_safe(mnt, next, mounts, mnt_expire) {
		if (!xchg(&mnt->mnt_expiry_mark, 1) ||
			propagate_mount_busy(mnt, 1))
			continue;
		list_move(&mnt->mnt_expire, &graveyard);
	}
	while (!list_empty(&graveyard)) {
		mnt = list_first_entry(&graveyard, struct vfsmount, mnt_expire);
		touch_mnt_namespace(mnt->mnt_ns);
		umount_tree(mnt, 1, &umounts);
	}
	spin_unlock(&vfsmount_lock);
	up_write(&namespace_sem);

	release_mounts(&umounts);
}

EXPORT_SYMBOL_GPL(mark_mounts_for_expiry);

/*
 * Ripoff of 'select_parent()'
 *
 * search the list of submounts for a given mountpoint, and move any
 * shrinkable submounts to the 'graveyard' list.
 */
static int select_submounts(struct vfsmount *parent, struct list_head *graveyard)
{
	struct vfsmount *this_parent = parent;
	struct list_head *next;
	int found = 0;

repeat:
	next = this_parent->mnt_mounts.next;
resume:
	while (next != &this_parent->mnt_mounts) {
		struct list_head *tmp = next;
		struct vfsmount *mnt = list_entry(tmp, struct vfsmount, mnt_child);

		next = tmp->next;
		if (!(mnt->mnt_flags & MNT_SHRINKABLE))
			continue;
		/*
		 * Descend a level if the d_mounts list is non-empty.
		 */
		if (!list_empty(&mnt->mnt_mounts)) {
			this_parent = mnt;
			goto repeat;
		}

		if (!propagate_mount_busy(mnt, 1)) {
			list_move_tail(&mnt->mnt_expire, graveyard);
			found++;
		}
	}
	/*
	 * All done at this level ... ascend and resume the search
	 */
	if (this_parent != parent) {
		next = this_parent->mnt_child.next;
		this_parent = this_parent->mnt_parent;
		goto resume;
	}
	return found;
}

/*
 * process a list of expirable mountpoints with the intent of discarding any
 * submounts of a specific parent mountpoint
 */
static void shrink_submounts(struct vfsmount *mnt, struct list_head *umounts)
{
	LIST_HEAD(graveyard);
	struct vfsmount *m;

	/* extract submounts of 'mountpoint' from the expiration list */
	while (select_submounts(mnt, &graveyard)) {
		while (!list_empty(&graveyard)) {
			m = list_first_entry(&graveyard, struct vfsmount,
						mnt_expire);
			touch_mnt_namespace(m->mnt_ns);
			umount_tree(m, 1, umounts);
		}
	}
}

/*
 * Some copy_from_user() implementations do not return the exact number of
 * bytes remaining to copy on a fault.  But copy_mount_options() requires that.
 * Note that this function differs from copy_from_user() in that it will oops
 * on bad values of `to', rather than returning a short copy.
 */
static long exact_copy_from_user(void *to, const void __user * from,
				 unsigned long n)
{
	char *t = to;
	const char __user *f = from;
	char c;

	if (!access_ok(VERIFY_READ, from, n))
		return n;

	while (n) {
		if (__get_user(c, f)) {
			memset(t, 0, n);
			break;
		}
		*t++ = c;
		f++;
		n--;
	}
	return n;
}

int copy_mount_options(const void __user * data, unsigned long *where)
{
	int i;
	unsigned long page;
	unsigned long size;

	*where = 0;
	if (!data)
		return 0;

	if (!(page = __get_free_page(GFP_KERNEL)))
		return -ENOMEM;

	/* We only care that *some* data at the address the user
	 * gave us is valid.  Just in case, we'll zero
	 * the remainder of the page.
	 */
	/* copy_from_user cannot cross TASK_SIZE ! */
	size = TASK_SIZE - (unsigned long)data;
	if (size > PAGE_SIZE)
		size = PAGE_SIZE;

	i = size - exact_copy_from_user((void *)page, data, size);
	if (!i) {
		free_page(page);
		return -EFAULT;
	}
	if (i != PAGE_SIZE)
		memset((char *)page + i, 0, PAGE_SIZE - i);
	*where = page;
	return 0;
}

int copy_mount_string(const void __user *data, char **where)
{
	char *tmp;

	if (!data) {
		*where = NULL;
		return 0;
	}

	tmp = strndup_user(data, PAGE_SIZE);
	if (IS_ERR(tmp))
		return PTR_ERR(tmp);

	*where = tmp;
	return 0;
}

/*
 * Flags is a 32-bit value that allows up to 31 non-fs dependent flags to
 * be given to the mount() call (ie: read-only, no-dev, no-suid etc).
 *
 * data is a (void *) that can point to any structure up to
 * PAGE_SIZE-1 bytes, which can contain arbitrary fs-dependent
 * information (or be NULL).
 *
 * Pre-0.97 versions of mount() didn't have a flags word.
 * When the flags word was introduced its top half was required
 * to have the magic value 0xC0ED, and this remained so until 2.4.0-test9.
 * Therefore, if this magic number is present, it carries no information
 * and must be discarded.
 */
long do_mount(char *dev_name, const char *dir_name, char *type_page,
		  unsigned long flags, void *data_page)
{
	struct path path;
	int retval = 0;
	int mnt_flags = 0;

	/* Discard magic */
	if ((flags & MS_MGC_MSK) == MS_MGC_VAL)
		flags &= ~MS_MGC_MSK;

	/* Basic sanity checks */

	if (!dir_name || !*dir_name || !memchr(dir_name, 0, PAGE_SIZE))
		return -EINVAL;

	if (data_page)
		((char *)data_page)[PAGE_SIZE - 1] = 0;

	/* Default to relatime unless overriden */
	if (!(flags & MS_NOATIME))
		mnt_flags |= MNT_RELATIME;

	/* Separate the per-mountpoint flags */
	if (flags & MS_NOSUID)
		mnt_flags |= MNT_NOSUID;
	if (flags & MS_NODEV)
		mnt_flags |= MNT_NODEV;
	if (flags & MS_NOEXEC)
		mnt_flags |= MNT_NOEXEC;
	if (flags & MS_NOATIME)
		mnt_flags |= MNT_NOATIME;
	if (flags & MS_NODIRATIME)
		mnt_flags |= MNT_NODIRATIME;
	if (flags & MS_STRICTATIME)
		mnt_flags &= ~(MNT_RELATIME | MNT_NOATIME);
	if (flags & MS_RDONLY)
		mnt_flags |= MNT_READONLY;

	flags &= ~(MS_NOSUID | MS_NOEXEC | MS_NODEV | MS_ACTIVE | MS_BORN |
		   MS_NOATIME | MS_NODIRATIME | MS_RELATIME| MS_KERNMOUNT |
		   MS_STRICTATIME | MS_CPTMOUNT);

	/* ... and get the mountpoint */
	retval = kern_path(dir_name, LOOKUP_FOLLOW, &path);
	if (retval)
		return retval;

	retval = security_sb_mount(dev_name, &path,
				   type_page, flags, data_page);
	if (retval)
		goto dput_out;

	if (flags & MS_REMOUNT)
		retval = do_remount(&path, flags & ~MS_REMOUNT, mnt_flags,
				    data_page);
	else if (flags & MS_BIND)
		retval = do_loopback(&path, dev_name, flags & MS_REC, mnt_flags);
	else if (flags & (MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE))
		retval = do_change_type(&path, flags);
	else if (flags & MS_MOVE)
		retval = do_move_mount(&path, dev_name);
	else
		retval = do_new_mount(&path, type_page, flags, mnt_flags,
				      dev_name, data_page);
dput_out:
	path_put(&path);
	return retval;
}

static void free_mnt_ns(struct mnt_namespace *ns)
{
	proc_free_inum(ns->proc_inum);
	kfree(ns);
}

/*
 * Assign a sequence number so we can detect when we attempt to bind
 * mount a reference to an older mount namespace into the current
 * mount namespace, preventing reference counting loops.  A 64bit
 * number incrementing at 10Ghz will take 12,427 years to wrap which
 * is effectively never, so we can ignore the possibility.
 */
static atomic64_t mnt_ns_seq = ATOMIC64_INIT(1);

static struct mnt_namespace *alloc_mnt_ns(void)
{
	struct mnt_namespace *new_ns;
	int ret;

	new_ns = kmalloc(sizeof(struct mnt_namespace), GFP_KERNEL);
	if (!new_ns)
		return ERR_PTR(-ENOMEM);
	ret = proc_alloc_inum(&new_ns->proc_inum);
	if (ret) {
		kfree(new_ns);
		return ERR_PTR(ret);
	}
	new_ns->seq = atomic64_add_return(1, &mnt_ns_seq);
	atomic_set(&new_ns->count, 1);
	new_ns->root = NULL;
	INIT_LIST_HEAD(&new_ns->list);
	init_waitqueue_head(&new_ns->poll);
	new_ns->event = 0;
	return new_ns;
}

/*
 * Allocate a new namespace structure and populate it with contents
 * copied from the namespace of the passed in task structure.
 */
static struct mnt_namespace *dup_mnt_ns(struct mnt_namespace *mnt_ns,
		struct fs_struct *fs)
{
	struct ve_struct *ve = get_exec_env();
	struct mnt_namespace *new_ns;
	struct vfsmount *rootmnt = NULL, *pwdmnt = NULL;
	struct vfsmount *p, *q, *old_root, *new_root;

	new_ns = alloc_mnt_ns();
	if (IS_ERR(new_ns))
		return new_ns;

	down_write(&namespace_sem);

	/* For VE clone only its vfsmount tree */
	old_root = ve->root_path.mnt;
	if (old_root != mnt_ns->root && ve->ve_ns->mnt_ns == mnt_ns) {
		/* clone rootfs vfsmount */
		new_ns->root = clone_mnt(mnt_ns->root,
				mnt_ns->root->mnt_root, 0);
		if (!new_ns->root) {
			up_write(&namespace_sem);
			kfree(new_ns);
			return ERR_PTR(-ENOMEM);
		}
		if (!old_root->mnt_ns) {
			new_ns->root->mnt_ns = new_ns;
			up_write(&namespace_sem);
			return new_ns;
		}
	} else
		old_root = mnt_ns->root;

	/* First pass: copy the tree topology */
	new_root = copy_tree(old_root, old_root->mnt_root,
					CL_COPY_ALL | CL_EXPIRE);
	if (!new_root) {
		up_write(&namespace_sem);
		mntput(new_ns->root);
		free_mnt_ns(new_ns);
		return ERR_PTR(-ENOMEM);
	}
	spin_lock(&vfsmount_lock);
	if (new_ns->root) {
		struct path root_path = {
			.mnt = new_ns->root,
			.dentry = new_ns->root->mnt_root,
		};
		new_ns->root->mnt_ns = new_ns;
		list_add(&new_ns->root->mnt_list, &new_root->mnt_list);
		attach_mnt(new_root, &root_path);
	} else
		new_ns->root = new_root;
	list_add_tail(&new_ns->list, &new_ns->root->mnt_list);
	spin_unlock(&vfsmount_lock);

	/*
	 * Second pass: switch the tsk->fs->* elements and mark new vfsmounts
	 * as belonging to new namespace.  We have already acquired a private
	 * fs_struct, so tsk->fs->lock is not needed.
	 */
	p = old_root;
	q = new_root;
	while (p) {
		q->mnt_ns = new_ns;
		if (fs) {
			if (p == fs->root.mnt) {
				rootmnt = p;
				fs->root.mnt = mntget(q);
			}
			if (p == fs->pwd.mnt) {
				pwdmnt = p;
				fs->pwd.mnt = mntget(q);
			}
		}
		p = next_mnt(p, old_root);
		q = next_mnt(q, new_root);
	}
	up_write(&namespace_sem);

	if (rootmnt)
		mntput(rootmnt);
	if (pwdmnt)
		mntput(pwdmnt);

	return new_ns;
}

struct mnt_namespace *copy_mnt_ns(unsigned long flags, struct mnt_namespace *ns,
		struct fs_struct *new_fs)
{
	struct mnt_namespace *new_ns;

	BUG_ON(!ns);
	get_mnt_ns(ns);

	if (!(flags & CLONE_NEWNS))
		return ns;

	new_ns = dup_mnt_ns(ns, new_fs);

	put_mnt_ns(ns);
	return new_ns;
}

/**
 * create_mnt_ns - creates a private namespace and adds a root filesystem
 * @mnt: pointer to the new root filesystem mountpoint
 */
struct mnt_namespace *create_mnt_ns(struct vfsmount *mnt)
{
	struct mnt_namespace *new_ns;

	new_ns = alloc_mnt_ns();
	if (!IS_ERR(new_ns)) {
		mnt->mnt_ns = new_ns;
		new_ns->root = mnt;
		list_add(&new_ns->list, &new_ns->root->mnt_list);
	}
	return new_ns;
}
EXPORT_SYMBOL(create_mnt_ns);

SYSCALL_DEFINE5(mount, char __user *, dev_name, char __user *, dir_name,
		char __user *, type, unsigned long, flags, void __user *, data)
{
	int ret;
	char *kernel_type;
	struct filename *kernel_dir;
	char *kernel_dev;
	unsigned long data_page;

	ret = copy_mount_string(type, &kernel_type);
	if (ret < 0)
		goto out_type;

	kernel_dir = getname(dir_name);
	if (IS_ERR(kernel_dir)) {
		ret = PTR_ERR(kernel_dir);
		goto out_dir;
	}

	ret = copy_mount_string(dev_name, &kernel_dev);
	if (ret < 0)
		goto out_dev;

	ret = copy_mount_options(data, &data_page);
	if (ret < 0)
		goto out_data;

	ret = do_mount(kernel_dev, kernel_dir->name, kernel_type, flags,
		(void *) data_page);

	free_page(data_page);
out_data:
	kfree(kernel_dev);
out_dev:
	putname(kernel_dir);
out_dir:
	kfree(kernel_type);
out_type:
	return ret;
}
EXPORT_SYMBOL(sys_mount);

/*
 * pivot_root Semantics:
 * Moves the root file system of the current process to the directory put_old,
 * makes new_root as the new root file system of the current process, and sets
 * root/cwd of all processes which had them on the current root to new_root.
 *
 * Restrictions:
 * The new_root and put_old must be directories, and  must not be on the
 * same file  system as the current process root. The put_old  must  be
 * underneath new_root,  i.e. adding a non-zero number of /.. to the string
 * pointed to by put_old must yield the same directory as new_root. No other
 * file system may be mounted on put_old. After all, new_root is a mountpoint.
 *
 * Also, the current root cannot be on the 'rootfs' (initial ramfs) filesystem.
 * See Documentation/filesystems/ramfs-rootfs-initramfs.txt for alternatives
 * in this situation.
 *
 * Notes:
 *  - we don't move root/cwd if they are not at the root (reason: if something
 *    cared enough to change them, it's probably wrong to force them elsewhere)
 *  - it's okay to pick a root that isn't the root of a file system, e.g.
 *    /nfs/my_root where /nfs is the mount point. It must be a mountpoint,
 *    though, so you may need to say mount --bind /nfs/my_root /nfs/my_root
 *    first.
 */
SYSCALL_DEFINE2(pivot_root, const char __user *, new_root,
		const char __user *, put_old)
{
	struct vfsmount *tmp;
	struct path new, old, parent_path, root_parent, root;
	struct ve_struct *ve = get_exec_env();
	int error;

	if (!capable(CAP_SYS_ADMIN) && !capable(CAP_VE_SYS_ADMIN))
		return -EPERM;

	error = user_path_dir(new_root, &new);
	if (error)
		goto out0;
	error = -EINVAL;
	if (!check_mnt(new.mnt))
		goto out1;

	error = user_path_dir(put_old, &old);
	if (error)
		goto out1;

	error = security_sb_pivotroot(&old, &new);
	if (error)
		goto out1_5;

	error = -EPERM;
	if (!ve_accessible_veid(old.mnt->owner, ve->veid)||
	    !ve_accessible_veid(new.mnt->owner, ve->veid))
		goto out1_5;

	get_fs_root(current->fs, &root);
	if (ve->root_path.mnt == root.mnt &&
	    ve->root_path.dentry == root.dentry)
		goto out1_6;

	down_write(&namespace_sem);
	mutex_lock(&old.dentry->d_inode->i_mutex);
	error = -EINVAL;
	if (IS_MNT_SHARED(old.mnt) ||
		IS_MNT_SHARED(new.mnt->mnt_parent) ||
		IS_MNT_SHARED(root.mnt->mnt_parent))
		goto out2;
	if (!check_mnt(root.mnt))
		goto out2;
	error = -ENOENT;
	if (IS_DEADDIR(new.dentry->d_inode))
		goto out2;
	if (d_unlinked(new.dentry))
		goto out2;
	if (d_unlinked(old.dentry))
		goto out2;
	error = -EBUSY;
	if (new.mnt == root.mnt ||
	    old.mnt == root.mnt)
		goto out2; /* loop, on the same file system  */
	error = -EINVAL;
	if (root.mnt->mnt_root != root.dentry)
		goto out2; /* not a mountpoint */
	if (root.mnt->mnt_parent == root.mnt)
		goto out2; /* not attached */
	if (new.mnt->mnt_root != new.dentry)
		goto out2; /* not a mountpoint */
	if (new.mnt->mnt_parent == new.mnt)
		goto out2; /* not attached */
	/* make sure we can reach put_old from new_root */
	tmp = old.mnt;
	spin_lock(&vfsmount_lock);
	if (tmp != new.mnt) {
		for (;;) {
			if (tmp->mnt_parent == tmp)
				goto out3; /* already mounted on put_old */
			if (tmp->mnt_parent == new.mnt)
				break;
			tmp = tmp->mnt_parent;
		}
		if (!is_subdir(tmp->mnt_mountpoint, new.dentry))
			goto out3;
	} else if (!is_subdir(old.dentry, new.dentry))
		goto out3;
	detach_mnt(new.mnt, &parent_path);
	detach_mnt(root.mnt, &root_parent);
	/* mount old root on put_old */
	attach_mnt(root.mnt, &old);
	/* mount new_root on / */
	attach_mnt(new.mnt, &root_parent);
	touch_mnt_namespace(current->nsproxy->mnt_ns);
	spin_unlock(&vfsmount_lock);
	chroot_fs_refs(&root, &new);
	security_sb_post_pivotroot(&root, &new);
	error = 0;
	path_put(&root_parent);
	path_put(&parent_path);
out2:
	mutex_unlock(&old.dentry->d_inode->i_mutex);
	up_write(&namespace_sem);
out1_6:
	path_put(&root);
out1_5:
	path_put(&old);
out1:
	path_put(&new);
out0:
	return error;
out3:
	spin_unlock(&vfsmount_lock);
	goto out2;
}

static void __init init_mount_tree(void)
{
	struct vfsmount *mnt;
	struct mnt_namespace *ns;
	struct path root;

	mnt = do_kern_mount("rootfs", 0, "rootfs", NULL);
	if (IS_ERR(mnt))
		panic("Can't create rootfs");
	ns = create_mnt_ns(mnt);
	if (IS_ERR(ns))
		panic("Can't allocate initial namespace");

	init_task.nsproxy->mnt_ns = ns;
	get_mnt_ns(ns);

	root.mnt = ns->root;
	root.dentry = ns->root->mnt_root;

	set_fs_pwd(current->fs, &root);
	set_fs_root(current->fs, &root);
}

void __init mnt_init(void)
{
	unsigned u;
	int err;

	init_rwsem(&namespace_sem);

	mnt_cache = kmem_cache_create("mnt_cache", sizeof(struct vfsmount),
			0, SLAB_HWCACHE_ALIGN | SLAB_PANIC | SLAB_UBC, NULL);

	mount_hashtable = (struct list_head *)__get_free_page(GFP_ATOMIC);

	if (!mount_hashtable)
		panic("Failed to allocate mount hash table\n");

	printk("Mount-cache hash table entries: %lu\n", HASH_SIZE);

	for (u = 0; u < HASH_SIZE; u++)
		INIT_LIST_HEAD(&mount_hashtable[u]);

	err = sysfs_init();
	if (err)
		printk(KERN_WARNING "%s: sysfs_init error: %d\n",
			__func__, err);
	fs_kobj = kobject_create_and_add("fs", NULL);
	if (!fs_kobj)
		printk(KERN_WARNING "%s: kobj create error\n", __func__);
	init_rootfs();
	init_mount_tree();
}

void put_mnt_ns(struct mnt_namespace *ns)
{
	struct vfsmount *root;
	LIST_HEAD(umount_list);

	if (!atomic_dec_and_lock(&ns->count, &vfsmount_lock))
		return;
	root = ns->root;
	ns->root = NULL;
	spin_unlock(&vfsmount_lock);
	down_write(&namespace_sem);
	spin_lock(&vfsmount_lock);
	umount_tree(root, 0, &umount_list);
	spin_unlock(&vfsmount_lock);
	up_write(&namespace_sem);
	release_mounts(&umount_list);
	free_mnt_ns(ns);
}
EXPORT_SYMBOL(put_mnt_ns);

static void *mntns_get(struct task_struct *task)
{
	struct mnt_namespace *ns = NULL;
	struct nsproxy *nsproxy;

	rcu_read_lock();
	nsproxy = task_nsproxy(task);
	if (nsproxy) {
		ns = nsproxy->mnt_ns;
		get_mnt_ns(ns);
	}
	rcu_read_unlock();

	return ns;
}

static void mntns_put(void *ns)
{
	put_mnt_ns(ns);
}

static int mntns_install(struct nsproxy *nsproxy, void *ns)
{
	struct ve_struct *ve = get_exec_env();
	struct path *ve_path = &ve->root_path;
	struct fs_struct *fs = current->fs;
	struct mnt_namespace *mnt_ns = ns;
	struct path root;

	if ((!capable(CAP_SYS_ADMIN) && !capable(CAP_VE_SYS_ADMIN)) || !capable(CAP_SYS_CHROOT))
		return -EINVAL;

	if (fs->users != 1)
		return -EINVAL;

	get_mnt_ns(mnt_ns);
	put_mnt_ns(nsproxy->mnt_ns);
	nsproxy->mnt_ns = mnt_ns;

	/* Find the root */
	if (ve->ve_ns->mnt_ns == mnt_ns) {
		root.mnt = ve_path->mnt;
		root.dentry = ve_path->dentry;
	} else {
		root.mnt    = mnt_ns->root;
		root.dentry = mnt_ns->root->mnt_root;
	}
	path_get(&root);
	while(d_mountpoint(root.dentry) && follow_down(&root))
		;

	/* Update the pwd and root */
	set_fs_pwd(fs, &root);
	set_fs_root(fs, &root);

	path_put(&root);
	return 0;
}

static unsigned int mntns_inum(void *ns)
{
	struct mnt_namespace *mnt_ns = ns;
	return mnt_ns->proc_inum;
}

const struct proc_ns_operations mntns_operations = {
	.name		= "mnt",
	.type		= CLONE_NEWNS,
	.get		= mntns_get,
	.put		= mntns_put,
	.install	= mntns_install,
	.inum		= mntns_inum,
};
