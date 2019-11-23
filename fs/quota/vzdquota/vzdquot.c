/*
 * Copyright (C) 2001, 2002, 2004, 2005  SWsoft
 * All rights reserved.
 * 
 * Licensing governed by "linux/COPYING.SWsoft" file.
 *
 * This file contains the core of Virtuozzo disk quota implementation:
 * maintenance of VZDQ information in inodes,
 * external interfaces,
 * module entry.
 */

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/list.h>
#include <asm/atomic.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/fs_struct.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/quota.h>
#include <linux/rcupdate.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/vzctl.h>
#include <linux/vzctl_quota.h>
#include <linux/vzquota.h>
#include <linux/virtinfo.h>
#include <linux/vzdq_tree.h>
#include <linux/mount.h>
#include <linux/quotaops.h>

/* ----------------------------------------------------------------------
 *
 * Locking
 *
 * ---------------------------------------------------------------------- */

/*
 * Serializes on/off and all other do_vzquotactl operations.
 * Protects qmblk hash.
 */
struct mutex vz_quota_mutex;

/*
 * Data access locks
 *  inode_qmblk
 *	protects qmblk pointers in all inodes and qlnk content in general
 *	(but not qmblk content);
 *	also protects related qmblk invalidation procedures;
 *	can't be per-inode because of vzquota_dtree_qmblk complications
 *	and problems with serialization with quota_on,
 *	but can be per-superblock;
 *  qmblk_data
 *	protects qmblk fields (such as current usage)
 *  quota_data
 *	protects charge/uncharge operations, thus, implies
 *	qmblk_data lock and, if CONFIG_VZ_QUOTA_UGID, inode_qmblk lock
 *	(to protect ugid pointers).
 *
 * Lock order:
 *  inode_qmblk_lock -> dcache_lock
 *  inode_qmblk_lock -> qmblk_data
 */
static DEFINE_SPINLOCK(vzdq_qmblk_lock);

inline void inode_qmblk_lock(struct super_block *sb)
{
	spin_lock(&vzdq_qmblk_lock);
}

inline void inode_qmblk_unlock(struct super_block *sb)
{
	spin_unlock(&vzdq_qmblk_lock);
}

inline void qmblk_data_read_lock(struct vz_quota_master *qmblk)
{
	spin_lock(&qmblk->dq_data_lock);
}

inline void qmblk_data_read_unlock(struct vz_quota_master *qmblk)
{
	spin_unlock(&qmblk->dq_data_lock);
}

inline void qmblk_data_write_lock(struct vz_quota_master *qmblk)
{
	spin_lock(&qmblk->dq_data_lock);
}

inline void qmblk_data_write_unlock(struct vz_quota_master *qmblk)
{
	spin_unlock(&qmblk->dq_data_lock);
}

struct quota_format_type vz_quota_empty_v2_format = {
	.qf_fmt_id	= QFMT_VFS_V0,
	.qf_ops		= NULL,
	.qf_owner	= THIS_MODULE,
};

/* ----------------------------------------------------------------------
 *
 * Master hash table handling.
 *
 * SMP not safe, serialied by vz_quota_mutex within quota syscalls
 *
 * --------------------------------------------------------------------- */

static struct kmem_cache *vzquota_cachep;

/*
 * Hash function.
 */
#define QHASH_BITS		6
#define	VZ_QUOTA_HASH_SIZE	(1 << QHASH_BITS)
#define QHASH_MASK		(VZ_QUOTA_HASH_SIZE - 1)

struct list_head vzquota_hash_table[VZ_QUOTA_HASH_SIZE];
int vzquota_hash_size = VZ_QUOTA_HASH_SIZE;

static inline int vzquota_hash_func(unsigned int qid)
{
	return (((qid >> QHASH_BITS) ^ qid) & QHASH_MASK);
}

/**
 * vzquota_alloc_master - alloc and instantiate master quota record
 *
 * Returns:
 *	pointer to newly created record if SUCCESS
 *	-ENOMEM if out of memory
 *	-EEXIST if record with given quota_id already exist
 */
struct vz_quota_master *vzquota_alloc_master(unsigned int quota_id,
		struct vz_quota_kstat *qstat)
{
	int err;
	struct vz_quota_master *qmblk;

	err = -EEXIST;
	if (vzquota_find_master(quota_id) != NULL)
		goto out;

	err = -ENOMEM;
	qmblk = kmem_cache_alloc(vzquota_cachep, GFP_KERNEL);
	if (qmblk == NULL)
		goto out;
#ifdef CONFIG_VZ_QUOTA_UGID
	qmblk->dq_uid_tree = quotatree_alloc();
	if (!qmblk->dq_uid_tree)
		goto out_free;

	qmblk->dq_gid_tree = quotatree_alloc();
	if (!qmblk->dq_gid_tree)
		goto out_free_tree;
#endif

	qmblk->dq_state = VZDQ_STARTING;
	mutex_init(&qmblk->dq_mutex);
	mutex_init(&qmblk->dq_write_lock);
	spin_lock_init(&qmblk->dq_data_lock);

	qmblk->dq_id = quota_id;
	qmblk->dq_stat = qstat->dq_stat;
	qmblk->dq_info = qstat->dq_info;
	qmblk->dq_root_path.dentry = NULL;
	qmblk->dq_root_path.mnt = NULL;
	qmblk->dq_sb = NULL;
	qmblk->dq_ugid_count = 0;
	qmblk->dq_ugid_max = 0;
	qmblk->dq_flags = 0;
	qmblk->qfile = NULL;
	qmblk->dq_snap = NULL;
	memset(qmblk->dq_ugid_info, 0, sizeof(qmblk->dq_ugid_info));
	INIT_LIST_HEAD(&qmblk->dq_ilink_list);

	atomic_set(&qmblk->dq_count, 1);

	/* insert in hash chain */
	list_add(&qmblk->dq_hash,
		&vzquota_hash_table[vzquota_hash_func(quota_id)]);

	/* success */
	return qmblk;

#ifdef CONFIG_VZ_QUOTA_UGID
out_free_tree:
	quotatree_free(qmblk->dq_uid_tree, NULL);
out_free:
	kmem_cache_free(vzquota_cachep, qmblk);
#endif
out:
	return ERR_PTR(err);
}

static struct vz_quota_master *vzquota_alloc_fake(void)
{
	struct vz_quota_master *qmblk;

	qmblk = kmem_cache_alloc(vzquota_cachep, GFP_KERNEL);
	if (qmblk == NULL)
		return NULL;
	memset(qmblk, 0, sizeof(*qmblk));
	qmblk->dq_state = VZDQ_STOPING;
	qmblk->dq_flags = VZDQ_NOQUOT;
	spin_lock_init(&qmblk->dq_data_lock);
	INIT_LIST_HEAD(&qmblk->dq_ilink_list);
	atomic_set(&qmblk->dq_count, 1);
	return qmblk;
}

/**
 * vzquota_find_master - find master record with given id
 *
 * Returns qmblk without touching its refcounter.
 * Called under vz_quota_mutex.
 */
struct vz_quota_master *vzquota_find_master(unsigned int quota_id)
{
	int i;
	struct vz_quota_master *qp;

	i = vzquota_hash_func(quota_id);
	list_for_each_entry(qp, &vzquota_hash_table[i], dq_hash) {
		if (qp->dq_id == quota_id)
			return qp;
	}
	return NULL;
}

/**
 * vzquota_free_master - release resources taken by qmblk, freeing memory
 *
 * qmblk is assumed to be already taken out from the hash.
 * Should be called outside vz_quota_mutex.
 */
void vzquota_free_master(struct vz_quota_master *qmblk)
{
#ifdef CONFIG_VZ_QUOTA_UGID
	vzquota_kill_ugid(qmblk);
#endif
	BUG_ON(!list_empty(&qmblk->dq_ilink_list));
	kmem_cache_free(vzquota_cachep, qmblk);
}

void vzquota_qlnk_init(struct vz_quota_ilink *);

static inline int vzquota_cur_qmblk_check(void)
{
	return current->magic == VZDQ_CUR_MAGIC;
}

static inline struct inode *vzquota_cur_qmblk_fetch(void)
{
	struct inode *inode = current->ino;

	/*
	 * If nfsd is running on the host, we may get a "parent" inode with
	 * uninitialized qmblk. Let us initialize it.
	 */
	if (!INODE_QLNK(inode)->qmblk)
		vzquota_qlnk_init(INODE_QLNK(inode));
	return inode;
}

static inline struct vz_quota_master *vzquota_cur_qmblk_orphan_cleanup(void)
{
	struct task_struct *tsk;
	struct vz_quota_master *qmblk;

	tsk = current;
	if (tsk->magic != VZDQ_CUR_CLEANUP)
		return NULL;

	qmblk = (struct vz_quota_master *)current->ino;
	BUG_ON(qmblk->dq_state != VZDQ_ORPHAN_CLEANUP);
	return qmblk;
}

void vzquota_cur_qmblk_orphan_set(struct vz_quota_master *qmblk)
{
	struct task_struct *tsk;

	tsk = current;
	if (qmblk) {
		tsk->magic = VZDQ_CUR_CLEANUP;
		tsk->ino = (struct inode *)qmblk;
	} else {
		tsk->magic = 0;
		tsk->ino = NULL;
	}
}

#if 0
static inline void vzquota_cur_qmblk_reset(void)
{
	current->magic = 0;
}
#endif


/* ----------------------------------------------------------------------
 *
 * Superblock quota operations
 *
 * --------------------------------------------------------------------- */

/*
 * Kernel structure abuse.
 * We use files[0] pointer as an int variable:
 * reference counter of how many quota blocks uses this superblock.
 * files[1] is used for generations structure which helps us to track
 * when traversing of dentries is really required.
 */
#define __VZ_QUOTA_NOQUOTA(sb)		sb->s_dquot.vzdq_master
#define __VZ_QUOTA_TSTAMP(sb)		((struct timeval *)\
						&sb->s_dquot.dqio_mutex)

#if defined(VZ_QUOTA_UNLOAD)

#define __VZ_QUOTA_SBREF(sb)		sb->s_dquot.vzdq_count

/**
 * quota_get_super - account for new a quoted tree under the superblock
 *
 * One superblock can have multiple directory subtrees with different VZ
 * quotas.  We keep a counter of such subtrees and set VZ quota operations or
 * reset the default ones.
 *
 * Called under vz_quota_mutex (from quota_on).
 */
int vzquota_get_super(struct super_block *sb)
{
	if (!IS_VZ_QUOTA(sb)) {
		down(&sb->s_dquot.dqonoff_sem);
		if (sb->s_dquot.flags & (DQUOT_USR_ENABLED|DQUOT_GRP_ENABLED)) {
			up(&sb->s_dquot.dqonoff_sem);
			return -EEXIST;
		}
		sb->s_dquot.dq_op_orig = sb->dq_op;
		if (sb->s_dquot.dq_op_orig->reserve_space)
			sb->dq_op = &vz_quota_operations_rsv;
		else
			sb->dq_op = &vz_quota_operations;
		/* XXX this may race with sys_quotactl */
#ifdef CONFIG_VZ_QUOTA_UGID
		sb->s_dquot.qcop_orig = sb->s_qcop;
		sb->s_qcop = &vz_quotactl_operations;
#else
		sb->s_qcop = NULL;
#endif
		do_gettimeofday(__VZ_QUOTA_TSTAMP(sb));
		memset(&sb->s_dquot.info, 0, sizeof(sb->s_dquot.info));

		INIT_LIST_HEAD(&sb->s_dquot.info[USRQUOTA].dqi_dirty_list);
		INIT_LIST_HEAD(&sb->s_dquot.info[GRPQUOTA].dqi_dirty_list);
		sb->s_dquot.info[USRQUOTA].dqi_format = &vz_quota_empty_v2_format;
		sb->s_dquot.info[GRPQUOTA].dqi_format = &vz_quota_empty_v2_format;
		/*
		 * To get quotaops.h call us we need to mark superblock
		 * as having quota.  These flags mark the moment when
		 * our dq_op start to be called.
		 *
		 * The ordering of dq_op and s_dquot.flags assignment
		 * needs to be enforced, but other CPUs do not do rmb()
		 * between s_dquot.flags and dq_op accesses.
		 */
		wmb(); synchronize_sched();
		sb->s_dquot.flags = DQUOT_USR_ENABLED|DQUOT_GRP_ENABLED;
		__module_get(THIS_MODULE);
		up(&sb->s_dquot.dqonoff_sem);
	}
	/* protected by vz_quota_mutex */
	__VZ_QUOTA_SBREF(sb)++;
	return 0;
}

/**
 * quota_put_super - release superblock when one quota tree goes away
 *
 * Called under vz_quota_mutex.
 */
void vzquota_put_super(struct super_block *sb)
{
	int count;

	count = --__VZ_QUOTA_SBREF(sb);
	if (count == 0) {
		down(&sb->s_dquot.dqonoff_sem);
		sb->s_dquot.flags = 0;
		wmb(); synchronize_sched();
		sema_init(&sb->s_dquot.dqio_sem, 1);

		sb->s_qcop = sb->s_dquot.qcop_orig;
		sb->dq_op = sb->s_dquot.dq_op_orig;
		inode_qmblk_lock(sb);
		quota_gen_put(SB_QGEN(sb));
		SB_QGEN(sb) = NULL;
		/* release qlnk's without qmblk */
		remove_inode_quota_links_list(&non_vzquota_inodes_lh,
				sb, NULL);
		/*
		 * Races with quota initialization:
		 * after this inode_qmblk_unlock all inode's generations are
		 * invalidated, quota_inode_qmblk checks superblock operations.
		 */
		inode_qmblk_unlock(sb);
		/*
		 * Module refcounting: in theory, this is the best place
		 * to call module_put(THIS_MODULE).
		 * In reality, it can't be done because we can't be sure that
		 * other CPUs do not enter our code segment through dq_op
		 * cached long time ago.  Quotaops interface isn't supposed to
		 * go into modules currently (that is, into unloadable
		 * modules).  By omitting module_put, our module isn't
		 * unloadable.
		 */
		up(&sb->s_dquot.dqonoff_sem);
	}
}

#else

/**
 * vzquota_shutdown_super - callback on umount
 */
void vzquota_shutdown_super(struct super_block *sb)
{
	struct vz_quota_master *qmblk;

	qmblk = __VZ_QUOTA_NOQUOTA(sb);
	__VZ_QUOTA_NOQUOTA(sb) = NULL;
	if (qmblk != NULL)
		qmblk_put(qmblk);
}

/**
 * vzquota_get_super - account for new a quoted tree under the superblock
 *
 * One superblock can have multiple directory subtrees with different VZ
 * quotas.
 *
 * Called under vz_quota_mutex (from vzquota_on).
 */
int vzquota_get_super(struct super_block *sb)
{
	struct vz_quota_master *qnew;
	int err;

	mutex_lock(&sb->s_dquot.dqonoff_mutex);
	err = -EEXIST;
	if (sb_any_quota_loaded(sb) && !IS_VZ_QUOTA(sb))
		goto out_up;

	/*
	 * This allocation code should be under sb->dq_op check below, but
	 * it doesn't really matter...
	 */
	if (__VZ_QUOTA_NOQUOTA(sb) == NULL) {
		qnew = vzquota_alloc_fake();
		if (qnew == NULL)
			goto out_up;
		__VZ_QUOTA_NOQUOTA(sb) = qnew;
	}

	if (!IS_VZ_QUOTA(sb)) {
		sb->s_dquot.dq_op_orig = sb->dq_op;
		if (sb->s_dquot.dq_op_orig->reserve_space)
			sb->dq_op = &vz_quota_operations_rsv;
		else
			sb->dq_op = &vz_quota_operations;
#ifdef CONFIG_VZ_QUOTA_UGID
		sb->s_dquot.qcop_orig = sb->s_qcop;
		sb->s_qcop = &vz_quotactl_operations;
#else
		sb->s_qcop = NULL;
#endif
		do_gettimeofday(__VZ_QUOTA_TSTAMP(sb));

		memset(&sb->s_dquot.info, 0, sizeof(sb->s_dquot.info));
		/* these 2 list heads are checked in sync_dquots() */
		INIT_LIST_HEAD(&sb->s_dquot.info[USRQUOTA].dqi_dirty_list);
		INIT_LIST_HEAD(&sb->s_dquot.info[GRPQUOTA].dqi_dirty_list);
		sb->s_dquot.info[USRQUOTA].dqi_format =
						&vz_quota_empty_v2_format;
		sb->s_dquot.info[GRPQUOTA].dqi_format =
						&vz_quota_empty_v2_format;

		/*
		 * To get quotaops.h to call us we need to mark superblock
		 * as having quota.  These flags mark the moment when
		 * our dq_op start to be called.
		 *
		 * The ordering of dq_op and s_dquot.flags assignment
		 * needs to be enforced, but other CPUs do not do rmb()
		 * between s_dquot.flags and dq_op accesses.
		 */
		wmb(); synchronize_sched();
		sb->s_dquot.flags =
			dquot_state_flag(DQUOT_USAGE_ENABLED |
					DQUOT_LIMITS_ENABLED,
					USRQUOTA) |
			dquot_state_flag(DQUOT_USAGE_ENABLED |
					DQUOT_LIMITS_ENABLED,
					GRPQUOTA);
	}
	err = 0;

out_up:
	mutex_unlock(&sb->s_dquot.dqonoff_mutex);
	return err;
}

/**
 * vzquota_put_super - one quota tree less on this superblock
 *
 * Called under vz_quota_mutex.
 */
void vzquota_put_super(struct super_block *sb)
{
	/*
	 * Even if this put is the last one,
	 * sb->s_dquot.flags can't be cleared, because otherwise vzquota_drop
	 * won't be called and the remaining qmblk references won't be put.
	 */
}

#endif


/* ----------------------------------------------------------------------
 *
 * Helpers for inode -> qmblk link maintenance
 *
 * --------------------------------------------------------------------- */

#define __VZ_QUOTA_EMPTY		((void *)0xbdbdbdbd)
#define VZ_QUOTA_IS_NOQUOTA(qm, sb)	((qm)->dq_flags & VZDQ_NOQUOT)
#define VZ_QUOTA_EMPTY_IOPS		(&vfs_empty_iops)
extern struct inode_operations vfs_empty_iops;

static int VZ_QUOTA_IS_ACTUAL(struct inode *inode)
{
	struct vz_quota_master *qmblk;

	qmblk = INODE_QLNK(inode)->qmblk;
	if (qmblk == VZ_QUOTA_BAD)
		return 1;
	if (qmblk == __VZ_QUOTA_EMPTY)
		return 0;
	if (qmblk->dq_flags & VZDQ_NOACT)
		/* not actual (invalidated) qmblk */
		return 0;
	return 1;
}

static inline int vzquota_qlnk_is_empty(struct vz_quota_ilink *qlnk)
{
	return qlnk->qmblk == __VZ_QUOTA_EMPTY;
}

static inline void set_qlnk_origin(struct vz_quota_ilink *qlnk,
		unsigned char origin)
{
	qlnk->origin[0] = qlnk->origin[1];
	qlnk->origin[1] = origin;
}

static inline void vzquota_qlnk_set_empty(struct vz_quota_ilink *qlnk)
{
	qlnk->qmblk = __VZ_QUOTA_EMPTY;
	set_qlnk_origin(qlnk, VZ_QUOTAO_SETE);
}

void vzquota_qlnk_init(struct vz_quota_ilink *qlnk)
{
	memset(qlnk, 0, sizeof(*qlnk));
	INIT_LIST_HEAD(&qlnk->list);
	vzquota_qlnk_set_empty(qlnk);
	set_qlnk_origin(qlnk, VZ_QUOTAO_INIT);
}

void vzquota_qlnk_destroy(struct vz_quota_ilink *qlnk)
{
	might_sleep();
	if (vzquota_qlnk_is_empty(qlnk))
		return;
#if defined(CONFIG_VZ_QUOTA_UGID)
	if (qlnk->qmblk != NULL && qlnk->qmblk != VZ_QUOTA_BAD) {
		struct vz_quota_master *qmblk;
		struct vz_quota_ugid *quid, *qgid;
		qmblk = qlnk->qmblk;
		quid = qlnk->qugid[USRQUOTA];
		qgid = qlnk->qugid[GRPQUOTA];
		if (quid != NULL || qgid != NULL) {
			mutex_lock(&qmblk->dq_mutex);
			if (qgid != NULL)
				vzquota_put_ugid(qmblk, qgid);
			if (quid != NULL)
				vzquota_put_ugid(qmblk, quid);
			mutex_unlock(&qmblk->dq_mutex);
		}
	}
#endif
	if (qlnk->qmblk != NULL && qlnk->qmblk != VZ_QUOTA_BAD)
		qmblk_put(qlnk->qmblk);
	set_qlnk_origin(qlnk, VZ_QUOTAO_DESTR);
}

/**
 * vzquota_qlnk_swap - swap inode's and temporary vz_quota_ilink contents
 * @qlt: temporary
 * @qli: inode's
 *
 * Locking is provided by the caller (depending on the context).
 * After swap, @qli is inserted into the corresponding dq_ilink_list,
 * @qlt list is reinitialized.
 */
static void vzquota_qlnk_swap(struct vz_quota_ilink *qlt,
		struct vz_quota_ilink *qli)
{
	struct vz_quota_master *qb;
	struct vz_quota_ugid *qu;
	int i;

	qb = qlt->qmblk;
	qlt->qmblk = qli->qmblk;
	qli->qmblk = qb;
	list_del_init(&qli->list);
	if (qb != __VZ_QUOTA_EMPTY && qb != VZ_QUOTA_BAD)
		list_add(&qli->list, &qb->dq_ilink_list);
	INIT_LIST_HEAD(&qlt->list);
	set_qlnk_origin(qli, VZ_QUOTAO_SWAP);

	for (i = 0; i < MAXQUOTAS; i++) {
		qu = qlt->qugid[i];
		qlt->qugid[i] = qli->qugid[i];
		qli->qugid[i] = qu;
	}
}

/**
 * vzquota_qlnk_reinit_locked - destroy qlnk content, called under locks
 *
 * Called under dcache_lock and inode_qmblk locks.
 * Returns 1 if locks were dropped inside, 0 if atomic.
 */
static int vzquota_qlnk_reinit_locked(struct vz_quota_ilink *qlnk,
		struct inode *inode)
{
	if (vzquota_qlnk_is_empty(qlnk))
		return 0;
	if (qlnk->qmblk == VZ_QUOTA_BAD) {
		vzquota_qlnk_set_empty(qlnk);
		set_qlnk_origin(qlnk, VZ_QUOTAO_RE_LOCK);
		return 0;
	}
	spin_unlock(&dcache_lock);
	inode_qmblk_unlock(inode->i_sb);
	vzquota_qlnk_destroy(qlnk);
	vzquota_qlnk_init(qlnk);
	inode_qmblk_lock(inode->i_sb);
	spin_lock(&dcache_lock);
	return 1;
}

#if defined(CONFIG_VZ_QUOTA_UGID)
/**
 * vzquota_qlnk_reinit_attr - destroy and reinit qlnk content
 *
 * Similar to vzquota_qlnk_reinit_locked, called under different locks.
 */
static int vzquota_qlnk_reinit_attr(struct vz_quota_ilink *qlnk,
		struct inode *inode,
		struct vz_quota_master *qmblk)
{
	if (vzquota_qlnk_is_empty(qlnk))
		return 0;
	/* may be optimized if qlnk->qugid all NULLs */
	qmblk_data_write_unlock(qmblk);
	inode_qmblk_unlock(inode->i_sb);
	vzquota_qlnk_destroy(qlnk);
	vzquota_qlnk_init(qlnk);
	inode_qmblk_lock(inode->i_sb);
	qmblk_data_write_lock(qmblk);
	return 1;
}
#endif

/**
 * vzquota_qlnk_fill - fill vz_quota_ilink content
 * @qlnk: vz_quota_ilink to fill
 * @inode: inode for which @qlnk is filled (i_sb, i_uid, i_gid)
 * @qmblk: qmblk to which this @qlnk will belong
 *
 * Called under dcache_lock and inode_qmblk locks.
 * Returns 1 if locks were dropped inside, 0 if atomic.
 * @qlnk is expected to be empty.
 */
static int vzquota_qlnk_fill(struct vz_quota_ilink *qlnk,
		struct inode *inode,
		struct vz_quota_master *qmblk)
{
	if (qmblk != VZ_QUOTA_BAD)
		qmblk_get(qmblk);
	qlnk->qmblk = qmblk;

#if defined(CONFIG_VZ_QUOTA_UGID)
	if (qmblk != VZ_QUOTA_BAD &&
	    !VZ_QUOTA_IS_NOQUOTA(qmblk, inode->i_sb) &&
	    (qmblk->dq_flags & VZDQUG_ON)) {
		struct vz_quota_ugid *quid, *qgid;

		spin_unlock(&dcache_lock);
		inode_qmblk_unlock(inode->i_sb);

		mutex_lock(&qmblk->dq_mutex);
		quid = __vzquota_find_ugid(qmblk, inode->i_uid, USRQUOTA, 0);
		qgid = __vzquota_find_ugid(qmblk, inode->i_gid, GRPQUOTA, 0);
		mutex_unlock(&qmblk->dq_mutex);

		inode_qmblk_lock(inode->i_sb);
		spin_lock(&dcache_lock);
		qlnk->qugid[USRQUOTA] = quid;
		qlnk->qugid[GRPQUOTA] = qgid;
		return 1;
	}
#endif

	return 0;
}

#if defined(CONFIG_VZ_QUOTA_UGID)
/**
 * vzquota_qlnk_fill_attr - fill vz_quota_ilink content for uid, gid
 *
 * This function is a helper for vzquota_transfer, and differs from
 * vzquota_qlnk_fill only by locking.
 */
static int vzquota_qlnk_fill_attr(struct vz_quota_ilink *qlnk,
		struct inode *inode,
		struct iattr *iattr,
		int mask,
		struct vz_quota_master *qmblk)
{
	qmblk_get(qmblk);
	qlnk->qmblk = qmblk;

	if (mask) {
		struct vz_quota_ugid *quid, *qgid;

		quid = qgid = NULL; /* to make gcc happy */
		if (!(mask & (1 << USRQUOTA)))
			quid = vzquota_get_ugid(INODE_QLNK(inode)->
							qugid[USRQUOTA]);
		if (!(mask & (1 << GRPQUOTA)))
			qgid = vzquota_get_ugid(INODE_QLNK(inode)->
							qugid[GRPQUOTA]);

		qmblk_data_write_unlock(qmblk);
		inode_qmblk_unlock(inode->i_sb);

		mutex_lock(&qmblk->dq_mutex);
		if (mask & (1 << USRQUOTA))
			quid = __vzquota_find_ugid(qmblk, iattr->ia_uid,
					USRQUOTA, 0);
		if (mask & (1 << GRPQUOTA))
			qgid = __vzquota_find_ugid(qmblk, iattr->ia_gid,
					GRPQUOTA, 0);
		mutex_unlock(&qmblk->dq_mutex);

		inode_qmblk_lock(inode->i_sb);
		qmblk_data_write_lock(qmblk);
		qlnk->qugid[USRQUOTA] = quid;
		qlnk->qugid[GRPQUOTA] = qgid;
		return 1;
	}

	return 0;
}
#endif

/**
 * __vzquota_inode_init - make sure inode's qlnk is initialized
 *
 * May be called if qlnk is already initialized, detects this situation itself.
 * Called under inode_qmblk_lock.
 */
static void __vzquota_inode_init(struct inode *inode, unsigned char origin)
{
	if (inode->i_dquot[USRQUOTA] == NULL) {
		vzquota_qlnk_init(INODE_QLNK(inode));
		inode->i_dquot[USRQUOTA] = (void *)~(unsigned long)NULL;
	}
	set_qlnk_origin(INODE_QLNK(inode), origin);
}

/**
 * vzquota_inode_drop - destroy VZ quota information in the inode
 *
 * Inode must not be externally accessible or dirty.
 */
static void vzquota_inode_drop(struct inode *inode)
{
	struct vz_quota_ilink qlnk;

	vzquota_qlnk_init(&qlnk);
	inode_qmblk_lock(inode->i_sb);
	vzquota_qlnk_swap(&qlnk, INODE_QLNK(inode));
	set_qlnk_origin(INODE_QLNK(inode), VZ_QUOTAO_DRCAL);
	inode->i_dquot[USRQUOTA] = NULL;
	inode_qmblk_unlock(inode->i_sb);
	vzquota_qlnk_destroy(&qlnk);
}

/**
 * vzquota_inode_qmblk_set - initialize inode's qlnk
 * @inode: inode to be initialized
 * @qmblk: quota master block to which this inode should belong (may be BAD)
 * @qlnk: placeholder to store data to resolve locking issues
 *
 * Returns 1 if locks were dropped and rechecks possibly needed, 0 otherwise.
 * Called under dcache_lock and inode_qmblk locks.
 * @qlnk will be destroyed in the caller chain.
 *
 * It is not mandatory to restart parent checks since quota on/off currently
 * shrinks dentry tree and checks that there are not outside references.
 * But if at some time that shink is removed, restarts will be required.
 * Additionally, the restarts prevent inconsistencies if the dentry tree
 * changes (inode is moved).  This is not a big deal, but anyway...
 */
static int vzquota_inode_qmblk_set(struct inode *inode,
		struct vz_quota_master *qmblk,
		struct vz_quota_ilink *qlnk)
{
	if (qmblk == NULL) {
		printk(KERN_ERR "VZDQ: NULL in set, orig {%u, %u}, "
				"dev %s, inode %lu, fs %s\n",
				INODE_QLNK(inode)->origin[0],
				INODE_QLNK(inode)->origin[1],
				inode->i_sb->s_id, inode->i_ino,
				inode->i_sb->s_type->name);
		printk(KERN_ERR "current %d (%s), VE %d\n",
				current->pid, current->comm,
				VEID(get_exec_env()));
		dump_stack();
		qmblk = VZ_QUOTA_BAD;
	}
	while (1) {
		if (vzquota_qlnk_is_empty(qlnk) &&
		    vzquota_qlnk_fill(qlnk, inode, qmblk))
			return 1;
		if (qlnk->qmblk == qmblk)
			break;
		if (vzquota_qlnk_reinit_locked(qlnk, inode))
			return 1;
	}
	vzquota_qlnk_swap(qlnk, INODE_QLNK(inode));
	set_qlnk_origin(INODE_QLNK(inode), VZ_QUOTAO_QSET);
	return 0;
}


/* ----------------------------------------------------------------------
 *
 * vzquota_inode_qmblk (inode -> qmblk lookup) parts
 *
 * --------------------------------------------------------------------- */

static char *vzquota_check_parent(struct inode *parent, struct inode *inode)
{
	char *msg;

	msg = "uninitialized parent";
	if (vzquota_qlnk_is_empty(INODE_QLNK(parent)))
		goto out;
	msg = "parent not in tree";
	if (list_empty(&parent->i_dentry))
		goto out;
	msg = "parent has 0 refcount";
	if (!atomic_read(&parent->i_count))
		goto out;
	msg = "parent has different sb";
	if (parent->i_sb != inode->i_sb)
		goto out;

	msg = NULL;
out:
	return msg;
}

static int vzquota_dparents_check_attach(struct inode *inode)
{
	if (!list_empty(&inode->i_dentry))
		return 0;
	printk(KERN_ERR "VZDQ: no parent for "
			"dev %s, inode %lu, fs %s\n",
			inode->i_sb->s_id,
			inode->i_ino,
			inode->i_sb->s_type->name);
	return -1;
}

static struct inode *vzquota_dparents_check_actual(struct inode *inode)
{
	struct dentry *de;

	list_for_each_entry(de, &inode->i_dentry, d_alias) {
		if (de->d_parent == de) /* detached dentry, perhaps */
			continue;
		/* first access to parent, make sure its qlnk initialized */
		__vzquota_inode_init(de->d_parent->d_inode, VZ_QUOTAO_ACT);
		if (!VZ_QUOTA_IS_ACTUAL(de->d_parent->d_inode))
			return de->d_parent->d_inode;
	}
	return NULL;
}

static struct vz_quota_master *vzquota_dparents_check_same(struct inode *inode)
{
	struct dentry *de;
	struct vz_quota_master *qmblk;
	char *msg = "";

	qmblk = NULL;
	list_for_each_entry(de, &inode->i_dentry, d_alias) {
		if (de->d_parent == de) /* detached dentry, perhaps */
			continue;
		if (qmblk == NULL) {
			qmblk = INODE_QLNK(de->d_parent->d_inode)->qmblk;
			continue;
		}
		if (INODE_QLNK(de->d_parent->d_inode)->qmblk != qmblk) {
			printk(KERN_WARNING "VZDQ: multiple quotas for "
					"dev %s, inode %lu, fs %s\n",
					inode->i_sb->s_id,
					inode->i_ino,
					inode->i_sb->s_type->name);
			qmblk = VZ_QUOTA_BAD;
			break;
		}
	}

	if (qmblk != NULL)
		goto out;

	if (vzquota_cur_qmblk_check()) {
		struct inode *parent;

		parent = vzquota_cur_qmblk_fetch();

		msg = vzquota_check_parent(parent, inode);
		if (msg != NULL)
			goto fail;

		msg = "parent not actual";
		if (!VZ_QUOTA_IS_ACTUAL(parent))
			goto fail;

		qmblk = INODE_QLNK(parent)->qmblk;
		goto out;
	}
fail:
	printk(KERN_WARNING "VZDQ: not attached to tree, "
			"dev %s, inode %lu, fs %s. %s\n",
			inode->i_sb->s_id,
			inode->i_ino,
			inode->i_sb->s_type->name, msg);
	qmblk = VZ_QUOTA_BAD;
out:
	return qmblk;
}

/* NFS root is disconnected dentry. */

static int is_nfs_root(struct inode * inode)
{
	struct dentry *de;

	if (inode->i_sb->s_magic != 0x6969)
		return 0;

	if (list_empty(&inode->i_dentry))
		return 0;

	list_for_each_entry(de, &inode->i_dentry, d_alias) {
		if (de->d_parent != de)
			return 0;
		if (d_unhashed(de))
			return 0;
		if (!(de->d_flags & DCACHE_DISCONNECTED))
			return 0;
	}
	return 1;
}

static void vzquota_dbranch_actualize(struct inode *inode,
		struct inode *refinode)
{
	struct inode *pinode;
	struct vz_quota_master *qmblk;
	struct vz_quota_ilink qlnk;

	vzquota_qlnk_init(&qlnk);

start:
	if (inode == inode->i_sb->s_root->d_inode || is_nfs_root(inode)) {
		/* filesystem root */
		atomic_inc(&inode->i_count);
		do {
			qmblk = __VZ_QUOTA_NOQUOTA(inode->i_sb);
		} while (vzquota_inode_qmblk_set(inode, qmblk, &qlnk));
		goto out;
	}

	if (!vzquota_dparents_check_attach(inode)) {
		pinode = vzquota_dparents_check_actual(inode);
		if (pinode != NULL) {
			inode = pinode;
			goto start;
		}
	}

	atomic_inc(&inode->i_count);
	while (1) {
		if (VZ_QUOTA_IS_ACTUAL(inode)) /* actualized without us */
			break;
		/*
		 * Need to check parents again if we have slept inside
		 * vzquota_inode_qmblk_set() in the loop.
		 * If the state of parents is different, just return and repeat
		 * the actualizing process again from the inode passed to
		 * vzquota_inode_qmblk_recalc().
		 */
		if (!vzquota_dparents_check_attach(inode)) {
			if (vzquota_dparents_check_actual(inode) != NULL)
				break;
			qmblk = vzquota_dparents_check_same(inode);
		} else
			qmblk = VZ_QUOTA_BAD;
		if (!vzquota_inode_qmblk_set(inode, qmblk, &qlnk)){/* success */
			set_qlnk_origin(INODE_QLNK(inode), VZ_QUOTAO_ACT);
			break;
		}
	}

out:
	spin_unlock(&dcache_lock);
	inode_qmblk_unlock(refinode->i_sb);
	vzquota_qlnk_destroy(&qlnk);
	iput(inode);
	inode_qmblk_lock(refinode->i_sb);
	spin_lock(&dcache_lock);
}

static void vzquota_dtree_qmblk_recalc(struct inode *inode,
		struct vz_quota_ilink *qlnk)
{
	struct inode *pinode;
	struct vz_quota_master *qmblk;

	if (inode == inode->i_sb->s_root->d_inode || is_nfs_root(inode)) {
		/* filesystem root */
		do {
			qmblk = __VZ_QUOTA_NOQUOTA(inode->i_sb);
		} while (vzquota_inode_qmblk_set(inode, qmblk, qlnk));
		return;
	}

start:
	if (VZ_QUOTA_IS_ACTUAL(inode))
		return;
	/*
	 * Here qmblk is (re-)initialized for all ancestors.
	 * This is not a very efficient procedure, but it guarantees that
	 * the quota tree is consistent (that is, the inode doesn't have two
	 * ancestors with different qmblk).
	 */
	if (!vzquota_dparents_check_attach(inode)) {
		pinode = vzquota_dparents_check_actual(inode);
		if (pinode != NULL) {
			vzquota_dbranch_actualize(pinode, inode);
			goto start;
		}
		qmblk = vzquota_dparents_check_same(inode);
	} else
		qmblk = VZ_QUOTA_BAD;

	if (vzquota_inode_qmblk_set(inode, qmblk, qlnk))
		goto start;
	set_qlnk_origin(INODE_QLNK(inode), VZ_QUOTAO_DTREE);
}

static void vzquota_det_qmblk_recalc(struct inode *inode,
		struct vz_quota_ilink *qlnk)
{
	struct inode *parent;
	struct vz_quota_master *qmblk;
	char *msg;
	int cnt;
	time_t timeout;

	cnt = 0;
	parent = NULL;
start:
	/*
	 * qmblk of detached inodes shouldn't be considered as not actual.
	 * They are not in any dentry tree, so quota on/off shouldn't affect
	 * them.
	 */
	if (!vzquota_qlnk_is_empty(INODE_QLNK(inode)))
		return;

	qmblk = vzquota_cur_qmblk_orphan_cleanup();
	if (qmblk)
		goto set;

	timeout = 3;
	qmblk = __VZ_QUOTA_NOQUOTA(inode->i_sb);
	/*
	 * Scenario:
	 *	open
	 *	unlink
	 * 	quotaon
	 *	generic_delete_inode
	 *
	 * This is the first time vzquota sees inode. inode is outside of
	 * vzquota area of interest, otherwise quotaon would have got -EBUSY
	 * due to shrink_dcache_parent().
	 * inode is almost completely destroyed, so don't intervene.
	 * 
	 * dev@:
	 * However, there is a small race here...
	 * dput() first removes itself from all the lists,
	 * so shrink_dcache_parent() can succeed while dentry_iput is not
	 * done yet.
	 */
	if (inode->i_state & I_FREEING)
		goto set;

	msg = "detached inode not in creation";
	if (inode->i_op != VZ_QUOTA_EMPTY_IOPS)
		goto fail;
	qmblk = VZ_QUOTA_BAD;
	msg = "unexpected creation context";
	if (!vzquota_cur_qmblk_check())
		goto fail;
	timeout = 0;
	parent = vzquota_cur_qmblk_fetch();
	msg = vzquota_check_parent(parent, inode);
	if (msg != NULL)
		goto fail;

	if (!VZ_QUOTA_IS_ACTUAL(parent)) {
		vzquota_dbranch_actualize(parent, inode);
		goto start;
	}

	qmblk = INODE_QLNK(parent)->qmblk;
set:
	if (vzquota_inode_qmblk_set(inode, qmblk, qlnk))
		goto start;
	set_qlnk_origin(INODE_QLNK(inode), VZ_QUOTAO_DET);
	return;

fail:
	{
		struct timeval tv, tvo;
		do_gettimeofday(&tv);
		memcpy(&tvo, __VZ_QUOTA_TSTAMP(inode->i_sb), sizeof(tvo));
		tv.tv_sec -= tvo.tv_sec;
		if (tv.tv_usec < tvo.tv_usec) {
			tv.tv_sec--;
			tv.tv_usec += USEC_PER_SEC - tvo.tv_usec;
		} else
			tv.tv_usec -= tvo.tv_usec;
		if (tv.tv_sec < timeout)
			goto set;
		printk(KERN_ERR "VZDQ: %s, orig {%u, %u},"
			" dev %s, inode %lu, fs %s\n",
			msg,
			INODE_QLNK(inode)->origin[0],
			INODE_QLNK(inode)->origin[1],
			inode->i_sb->s_id, inode->i_ino,
			inode->i_sb->s_type->name);
		printk(KERN_ERR "i_count %u, ", atomic_read(&inode->i_count));
		printk(KERN_ERR "i_mode %o, ", inode->i_mode);
		printk(KERN_ERR "i_state %lx, ", inode->i_state);
		printk(KERN_ERR "i_flags %x\n", inode->i_flags);
		printk(KERN_ERR "i_op %p, vfs_empty_iops %p, "
				"i_fop %p, i_mapping %p\n",
				inode->i_op, &vfs_empty_iops,
				inode->i_fop, inode->i_mapping);
		if (!cnt++) {
			printk(KERN_ERR "current %d (%s), VE %d,"
				" time %ld.%06ld\n",
				current->pid, current->comm,
				VEID(get_exec_env()),
				tv.tv_sec, (long)tv.tv_usec);
			dump_stack();
		}
		if (parent != NULL)
			printk(KERN_ERR "VZDQ: parent of %lu is %lu\n",
				inode->i_ino, parent->i_ino);
	}
	goto set;
}

static void vzquota_inode_qmblk_recalc(struct inode *inode,
		struct vz_quota_ilink *qlnk)
{
	spin_lock(&dcache_lock);
	if (!list_empty(&inode->i_dentry))
		vzquota_dtree_qmblk_recalc(inode, qlnk);
	else
		vzquota_det_qmblk_recalc(inode, qlnk);
	spin_unlock(&dcache_lock);
}

/**
 * vzquota_inode_qmblk - obtain inode's qmblk
 *
 * Returns qmblk with refcounter taken, %NULL if not under
 * VZ quota or %VZ_QUOTA_BAD.
 *
 * FIXME: This function should be removed when vzquota_find_qmblk /
 * get_quota_root / vzquota_dstat code is cleaned up.
 */
struct vz_quota_master *vzquota_inode_qmblk(struct inode *inode)
{
	struct vz_quota_master *qmblk;
	struct vz_quota_ilink qlnk;

	might_sleep();

	if (!IS_VZ_QUOTA(inode->i_sb))
		return NULL;
#if defined(VZ_QUOTA_UNLOAD)
#error Make sure qmblk does not disappear
#endif

	vzquota_qlnk_init(&qlnk);
	inode_qmblk_lock(inode->i_sb);
	__vzquota_inode_init(inode, VZ_QUOTAO_INICAL);

	if (vzquota_qlnk_is_empty(INODE_QLNK(inode)) ||
	    !VZ_QUOTA_IS_ACTUAL(inode))
		vzquota_inode_qmblk_recalc(inode, &qlnk);

	qmblk = INODE_QLNK(inode)->qmblk;
	if (qmblk != VZ_QUOTA_BAD) {
		if (!VZ_QUOTA_IS_NOQUOTA(qmblk, inode->i_sb))
			qmblk_get(qmblk);
		else
			qmblk = NULL;
	}

	inode_qmblk_unlock(inode->i_sb);
	vzquota_qlnk_destroy(&qlnk);
	return qmblk;
}

/**
 * vzquota_find_qmblk - helper to emulate quota on virtual filesystems
 *
 * This function finds a quota master block corresponding to the root of
 * a virtual filesystem.
 * Returns a quota master block with reference taken, or %NULL if not under
 * quota, or %VZ_QUOTA_BAD if quota inconsistency is found (and all allocation
 * operations will fail).
 *
 * Note: this function uses vzquota_inode_qmblk().
 * The latter is a rather confusing function: it returns qmblk that used to be
 * on the inode some time ago (without guarantee that it still has any
 * relations to the inode).  So, vzquota_find_qmblk() leaves it up to the
 * caller to think whether the inode could have changed its qmblk and what to
 * do in that case.
 * Currently, the callers appear to not care :(
 */
struct vz_quota_master *vzquota_find_qmblk(struct super_block *sb)
{
	struct inode *qrinode;
	struct vz_quota_master *qmblk;

	qmblk = NULL;
	qrinode = NULL;
	if (sb->s_op->get_quota_root != NULL)
		qrinode = sb->s_op->get_quota_root(sb);
	if (qrinode != NULL)
		qmblk = vzquota_inode_qmblk(qrinode);
	return qmblk;
}

/* ----------------------------------------------------------------------
 *
 * Calls from quota operations
 *
 * --------------------------------------------------------------------- */

/**
 * vzquota_inode_init_call - call from DQUOT_INIT
 */
void vzquota_inode_init_call(struct inode *inode)
{
	struct vz_quota_master *qmblk;
	struct vz_quota_datast data;

	/* initializes inode's quota inside */
	qmblk = vzquota_inode_data(inode, &data);
	if (qmblk != NULL && qmblk != VZ_QUOTA_BAD)
		vzquota_data_unlock(inode, &data);

	/*
	 * The check is needed for repeated new_inode() calls from a single
	 * ext3 call like create or mkdir in case of -ENOSPC.
	 */
	spin_lock(&dcache_lock);
	if (!list_empty(&inode->i_dentry))
		vzquota_cur_qmblk_set(inode);
	spin_unlock(&dcache_lock);
}

void vzquota_inode_swap_call(struct inode *inode, struct inode *tmpl)
{
	struct vz_quota_master *qmblk;

	__vzquota_inode_init(inode, VZ_QUOTAO_INIT);

	might_sleep();

	inode_qmblk_lock(tmpl->i_sb);
	if (unlikely(tmpl->i_flags & S_NOQUOTA)) {
		inode_qmblk_unlock(tmpl->i_sb);
		return;
	}
	__vzquota_inode_init(tmpl, VZ_QUOTAO_INICAL);

	qmblk = INODE_QLNK(tmpl)->qmblk;
	if (qmblk != VZ_QUOTA_BAD) {
		void * uq;
		list_del_init(&INODE_QLNK(tmpl)->list);
		vzquota_qlnk_swap(INODE_QLNK(tmpl), INODE_QLNK(inode));
		uq = inode->i_dquot[USRQUOTA];
		inode->i_dquot[USRQUOTA] = tmpl->i_dquot[USRQUOTA];
		tmpl->i_dquot[USRQUOTA] = uq;
		tmpl->i_flags |= S_NOQUOTA;
		inode_qmblk_unlock(inode->i_sb);

		vzquota_inode_drop(tmpl);
	} else {
		inode_qmblk_unlock(tmpl->i_sb);
	}
}


/**
 * vzquota_inode_drop_call - call from DQUOT_DROP
 */
void vzquota_inode_drop_call(struct inode *inode)
{
	vzquota_inode_drop(inode);
}

/**
 * vzquota_inode_data - initialize (if nec.) and lock inode quota ptrs
 * @inode: the inode
 * @data: storage space
 *
 * Returns: qmblk is NULL or VZ_QUOTA_BAD or actualized qmblk.
 * On return if qmblk is neither NULL nor VZ_QUOTA_BAD:
 *   qmblk in inode's qlnk is the same as returned,
 *   ugid pointers inside inode's qlnk are valid,
 *   some locks are taken (and should be released by vzquota_data_unlock).
 * If qmblk is NULL or VZ_QUOTA_BAD, locks are NOT taken.
 */
struct vz_quota_master *vzquota_inode_data(struct inode *inode,
		struct vz_quota_datast *data)
{
	struct vz_quota_master *qmblk;

	might_sleep();

	vzquota_qlnk_init(&data->qlnk);
	inode_qmblk_lock(inode->i_sb);
	if (unlikely(inode->i_flags & S_NOQUOTA)) {
		inode_qmblk_unlock(inode->i_sb);
		return NULL;
	}
	__vzquota_inode_init(inode, VZ_QUOTAO_INICAL);

	if (vzquota_qlnk_is_empty(INODE_QLNK(inode)) ||
	    !VZ_QUOTA_IS_ACTUAL(inode))
		vzquota_inode_qmblk_recalc(inode, &data->qlnk);

	qmblk = INODE_QLNK(inode)->qmblk;
	if (qmblk != VZ_QUOTA_BAD) {
		if (!VZ_QUOTA_IS_NOQUOTA(qmblk, inode->i_sb)) {
			/*
			 * Note that in the current implementation,
			 * inode_qmblk_lock can theoretically be dropped here.
			 * This place is serialized with quota_off because
			 * quota_off fails when there are extra dentry
			 * references and syncs inodes before removing quota
			 * information from them.
			 * However, quota usage information should stop being
			 * updated immediately after vzquota_off.
			 */
			qmblk_data_write_lock(qmblk);
		} else {
			inode_qmblk_unlock(inode->i_sb);
			vzquota_qlnk_destroy(&data->qlnk);
			qmblk = NULL;
		}
	} else {
		inode_qmblk_unlock(inode->i_sb);
	}
	return qmblk;
}

void vzquota_data_unlock(struct inode *inode,
		struct vz_quota_datast *data)
{
	qmblk_data_write_unlock(INODE_QLNK(inode)->qmblk);
	inode_qmblk_unlock(inode->i_sb);
	vzquota_qlnk_destroy(&data->qlnk);
}

#if defined(CONFIG_VZ_QUOTA_UGID)
static void vzquota_handle_dirty_ugids(struct vz_quota_master *qmblk,
		struct vz_quota_ugid **dirty)
{
	int i;

	if (qmblk->qfile != NULL)
		__vzquota_mark_dirty_ugids(qmblk, dirty);

	for (i = 0; i < MAXQUOTAS; i++) {
		if (dirty[i] == NULL)
			continue;

		vzquota_put_ugid(qmblk, dirty[i]);
		vzquota_put_ugid(qmblk, dirty[i + MAXQUOTAS]);
	}
}

/**
 * vzquota_inode_transfer_call - call from vzquota_transfer
 */
int vzquota_inode_transfer_call(struct inode *inode, struct iattr *iattr)
{
	struct vz_quota_master *qmblk;
	struct vz_quota_datast data;
	struct vz_quota_ilink qlnew;
	struct vz_quota_ugid *dirty_ugids[MAXQUOTAS * 2];
	int mask;
	int ret;

	might_sleep();
	vzquota_qlnk_init(&qlnew);
	memset(dirty_ugids, 0, sizeof(dirty_ugids));
start:
	qmblk = vzquota_inode_data(inode, &data);
	ret = NO_QUOTA;
	if (qmblk == VZ_QUOTA_BAD)
		goto out_destr;
	ret = QUOTA_OK;
	if (qmblk == NULL)
		goto out_destr;
	qmblk_get(qmblk);

	ret = QUOTA_OK;
	if (!(qmblk->dq_flags & VZDQUG_ON))
		/* no ugid quotas */
		goto out_unlock;

	mask = 0;
	if ((iattr->ia_valid & ATTR_UID) && iattr->ia_uid != inode->i_uid)
		mask |= 1 << USRQUOTA;
	if ((iattr->ia_valid & ATTR_GID) && iattr->ia_gid != inode->i_gid)
		mask |= 1 << GRPQUOTA;
	while (1) {
		if (vzquota_qlnk_is_empty(&qlnew) &&
		    vzquota_qlnk_fill_attr(&qlnew, inode, iattr, mask, qmblk))
			break;
		if (qlnew.qmblk == INODE_QLNK(inode)->qmblk &&
		    qlnew.qmblk == qmblk)
			goto finish;
		if (vzquota_qlnk_reinit_attr(&qlnew, inode, qmblk))
			break;
	}

	/* prepare for restart */
	vzquota_data_unlock(inode, &data);
	qmblk_put(qmblk);
	goto start;

finish:
	/* all references obtained successfully */
	ret = vzquota_transfer_usage(inode, mask, &qlnew, dirty_ugids);
	if (!ret) {
		vzquota_qlnk_swap(&qlnew, INODE_QLNK(inode));
		set_qlnk_origin(INODE_QLNK(inode), VZ_QUOTAO_TRANS);
	}
out_unlock:
	vzquota_data_unlock(inode, &data);
	vzquota_handle_dirty_ugids(qmblk, dirty_ugids);
	qmblk_put(qmblk);
out_destr:
	vzquota_qlnk_destroy(&qlnew);
	return ret;
}
#endif

int vzquota_rename_check(struct inode *inode,
		struct inode *old_dir, struct inode *new_dir)
{
	struct vz_quota_master *qmblk;
	struct vz_quota_ilink qlnk1, qlnk2, qlnk3;
	int c, ret;

	if (inode->i_sb != old_dir->i_sb || inode->i_sb != new_dir->i_sb)
		return -1;

	might_sleep();

	vzquota_qlnk_init(&qlnk1);
	vzquota_qlnk_init(&qlnk2);
	vzquota_qlnk_init(&qlnk3);
	inode_qmblk_lock(inode->i_sb);
	__vzquota_inode_init(inode, VZ_QUOTAO_INICAL);
	__vzquota_inode_init(old_dir, VZ_QUOTAO_INICAL);
	__vzquota_inode_init(new_dir, VZ_QUOTAO_INICAL);

	do {
		c = 0;
		if (vzquota_qlnk_is_empty(INODE_QLNK(inode)) ||
		    !VZ_QUOTA_IS_ACTUAL(inode)) {
			vzquota_inode_qmblk_recalc(inode, &qlnk1);
			c++;
		}
		if (vzquota_qlnk_is_empty(INODE_QLNK(new_dir)) ||
		    !VZ_QUOTA_IS_ACTUAL(new_dir)) {
			vzquota_inode_qmblk_recalc(new_dir, &qlnk2);
			c++;
		}
	} while (c);

	ret = 0;
	qmblk = INODE_QLNK(inode)->qmblk;
	if (qmblk != INODE_QLNK(new_dir)->qmblk) {
		ret = -1;
		while (vzquota_qlnk_is_empty(INODE_QLNK(old_dir)) ||
		       !VZ_QUOTA_IS_ACTUAL(old_dir))
			vzquota_inode_qmblk_recalc(old_dir, &qlnk3);
		if (qmblk != VZ_QUOTA_BAD &&
		    !VZ_QUOTA_IS_NOQUOTA(qmblk, inode->i_sb) &&
		    qmblk->dq_root_path.dentry->d_inode == inode &&
		    VZ_QUOTA_IS_NOQUOTA(INODE_QLNK(new_dir)->qmblk,
			    				inode->i_sb) &&
		    VZ_QUOTA_IS_NOQUOTA(INODE_QLNK(old_dir)->qmblk,
			    				inode->i_sb))
			/* quota root rename is allowed */
			ret = 0;
	}

	inode_qmblk_unlock(inode->i_sb);
	vzquota_qlnk_destroy(&qlnk3);
	vzquota_qlnk_destroy(&qlnk2);
	vzquota_qlnk_destroy(&qlnk1);
	return ret;
}

/*
 * Scan parent subdirs and find busy dentries names/path
 * @parent: parent dentry
 * @buf: buffer to store path.
 */
static void vzdquota_read_busy_dentries(struct path *parent,
		char *buf, int buflen)
{
	struct dentry *this_parent = parent->dentry;
	struct list_head *next;
	char *res, *end, *start;
	struct path root, path;
	int len;

	if (!buf || buflen <= 0)
		return;

	path.mnt = parent->mnt;
	/* From d_path() ... */
	get_fs_root(current->fs, &root);

	spin_lock(&dcache_lock);

	end = buf + buflen;
	start = buf;
repeat:
	next = this_parent->d_subdirs.next;
resume:
	while (next != &this_parent->d_subdirs) {
		struct list_head *tmp = next;
		struct dentry *dentry;
		int subdirs;

		dentry = list_entry(tmp, struct dentry, d_u.d_child);
		next = tmp->next;
		subdirs = !list_empty(&dentry->d_subdirs); 

		if (atomic_read(&dentry->d_count) && !subdirs) {
			if (!buflen)
				goto out;
			/*
			 * Note: __d_path will store filename at the
			 * end of buf.
			 */
			path.dentry = dentry;
			res = __d_path(&path, &root, buf, buflen);
			/* Exit if name is too long */
			if (IS_ERR(res))
				goto out;

			/*
			 * Move the string obtained by __d_path,
			 * behind the last dentry path in buf.
			 */
			len = end - res;
			BUG_ON(len <= 0);

			memmove(buf, res, len);

			/* Trick: replace \0 by \n */
			if (buf != start)
				*(char *)(buf - 1) = '\n';

			buf += len;
			buflen -= len;
		}

		/*
		 * Descend a level if the d_subdirs list is non-empty.
		 */
		if (subdirs) {
			this_parent = dentry;
			goto repeat;
		}
	}
	/*
	 * All done at this level ... ascend and resume the search.
	 */
	if (this_parent != parent->dentry) {
		next = this_parent->d_u.d_child.next;
		this_parent = this_parent->d_parent;
		goto resume;
	}
out:
	/* From d_path() ... */
	spin_unlock(&dcache_lock);
	path_put(&root);
}

/* ----------------------------------------------------------------------
 *
 * qmblk-related parts of on/off operations
 *
 * --------------------------------------------------------------------- */

/**
 * vzquota_check_dtree - check dentry tree if quota on/off is allowed
 *
 * This function doesn't allow quota to be turned on/off if some dentries in
 * the tree have external references.
 * In addition to technical reasons, it enforces user-space correctness:
 * current usage (taken from or reported to the user space) can be meaningful
 * and accurate only if the tree is not being modified.
 * Side effect: additional vfsmount structures referencing the tree (bind
 * mounts of tree nodes to some other places) are not allowed at on/off time.
 *
 * Store busy dentries path to the buf (if passed) in case of vzquota_off
 * ioctl fail.
 */
int vzquota_check_dtree(struct vz_quota_master *qmblk, int off,
						char *buf, int buflen)
{
	struct dentry *dentry;
	int err, count;

	err = -EBUSY;
	dentry = qmblk->dq_root_path.dentry;

	if (d_unhashed(dentry) && dentry != dentry->d_sb->s_root)
		goto unhashed;

	/* attempt to shrink */
  	if (!list_empty(&dentry->d_subdirs)) {
		spin_unlock(&dcache_lock);
		inode_qmblk_unlock(dentry->d_sb);
		shrink_dcache_parent(dentry);
		inode_qmblk_lock(dentry->d_sb);
		spin_lock(&dcache_lock);
		if (!list_empty(&dentry->d_subdirs)) {
        		spin_unlock(&dcache_lock);
			vzdquota_read_busy_dentries(&qmblk->dq_root_path,
								buf, buflen);
			spin_lock(&dcache_lock);
			goto out;
		}

		count = 1;
		if (dentry == dentry->d_sb->s_root)
			count += 2;	/* sb and mnt refs */
		if (atomic_read(&dentry->d_count) < count) {
			printk(KERN_ERR "%s: too small count %d vs %d.\n",
					__FUNCTION__,
					atomic_read(&dentry->d_count), count);
			goto out;
		}
		if (atomic_read(&dentry->d_count) > count)
			goto out;
	}

	err = 0;
out:
	return err;

unhashed:
	/*
	 * Quota root is removed.
	 * Allow to turn quota off, but not on.
	 */
	if (off)
		err = 0;
	goto out;
}

int vzquota_on_qmblk(struct super_block *sb, struct inode *inode,
		struct vz_quota_master *qmblk, char __user *ubuf)
{
	struct vz_quota_ilink qlnk;
	struct vz_quota_master *qold, *qnew;
	int err;
	char *buf;

	buf = (ubuf != NULL) ? (char *)__get_free_page(GFP_KERNEL) : NULL;

	might_sleep();

	qold = NULL;
	qnew = vzquota_alloc_fake();
	if (qnew == NULL) {
		free_page((unsigned long)buf);
		return -ENOMEM;
	}

	vzquota_qlnk_init(&qlnk);
	inode_qmblk_lock(sb);
	__vzquota_inode_init(inode, VZ_QUOTAO_INICAL);

	spin_lock(&dcache_lock);
	while (1) {
		err = vzquota_check_dtree(qmblk, 0, buf, PAGE_SIZE);
		if (err)
			break;
		if (!vzquota_inode_qmblk_set(inode, qmblk, &qlnk))
			break;
	}
	set_qlnk_origin(INODE_QLNK(inode), VZ_QUOTAO_ON);
	spin_unlock(&dcache_lock);

	if (!err) {
		qold = __VZ_QUOTA_NOQUOTA(sb);
		qold->dq_flags |= VZDQ_NOACT;
		__VZ_QUOTA_NOQUOTA(sb) = qnew;
	} else
		qold = qnew;

	inode_qmblk_unlock(sb);
	vzquota_qlnk_destroy(&qlnk);
	if (qold != NULL)
		qmblk_put(qold);

	if (buf) {
		if (copy_to_user(ubuf, buf, PAGE_SIZE))
			;
		free_page((unsigned long)buf);
	}
	return err;
}

int vzquota_off_qmblk(struct super_block *sb, struct vz_quota_master *qmblk,
						char __user *ubuf, int force)
{
	int ret;
	char *buf;

	buf = (ubuf != NULL) ? (char *)__get_free_page(GFP_KERNEL) : NULL;

	ret = 0;
	inode_qmblk_lock(sb);

	spin_lock(&dcache_lock);
	if (vzquota_check_dtree(qmblk, 1, buf, PAGE_SIZE) && !force)
		ret = -EBUSY;
	spin_unlock(&dcache_lock);

	if (!ret)
		qmblk->dq_flags |= VZDQ_NOACT | VZDQ_NOQUOT;
	inode_qmblk_unlock(sb);

	if (buf) {
		if (copy_to_user(ubuf, buf, PAGE_SIZE))
			;
		free_page((unsigned long)buf);
	}
	return ret;
}


/* ----------------------------------------------------------------------
 *
 * External interfaces
 *
 * ---------------------------------------------------------------------*/

static int vzquota_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int err;

	switch (cmd) {
	case VZCTL_QUOTA_NEW_CTL: {
		struct vzctl_quotactl qb;

		err = -EFAULT;
		if (copy_from_user(&qb, (void __user *)arg, sizeof(qb)))
			break;
		err = do_vzquotactl(qb.cmd, qb.quota_id,
				qb.qstat, qb.ve_root, 0);
		break;
	}
#ifdef CONFIG_VZ_QUOTA_UGID
	case VZCTL_QUOTA_UGID_CTL: {
		struct vzctl_quotaugidctl qub;

		err = -EFAULT;
		if (copy_from_user(&qub, (void __user *)arg, sizeof(qub)))
			break;
		err = do_vzquotaugidctl(qub.cmd, qub.quota_id,
				qub.ugid_index, qub.ugid_size, qub.addr, 0);
		break;
	}
#endif
	default:
		err = -ENOTTY;
	}
	return err;
}

#ifdef CONFIG_COMPAT
static int compat_vzquota_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int err;

	switch (cmd) {
	case VZCTL_COMPAT_QUOTA_CTL: {
		struct compat_vzctl_quotactl cs;

		err = -EFAULT;
		if (copy_from_user(&cs, (void *)arg, sizeof(cs)))
			break;
		err = do_vzquotactl(cs.cmd, cs.quota_id,
				compat_ptr(cs.qstat),
				compat_ptr(cs.ve_root), 1);
		break;
	}
#ifdef CONFIG_VZ_QUOTA_UGID
	case VZCTL_COMPAT_QUOTA_UGID_CTL: {
		struct compat_vzctl_quotaugidctl cs;

		err = -EFAULT;
		if (copy_from_user(&cs, (void *)arg, sizeof(cs)))
			break;

		err = do_vzquotaugidctl(cs.cmd, cs.quota_id, cs.ugid_index,
				cs.ugid_size, compat_ptr(cs.addr), 1);
		break;
	}
#endif
	default:
		err = -ENOIOCTLCMD;
	}
	return err;
}
#endif

static struct vzioctlinfo vzdqcalls = {
	.type		= VZDQCTLTYPE,
	.ioctl		= vzquota_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= compat_vzquota_ioctl,
#endif
	.owner		= THIS_MODULE,
};

/**
 * vzquota_dstat - get quota usage info for virtual superblock
 */
static int vzquota_dstat(struct inode *inode, struct dq_kstat *qstat)
{
	struct vz_quota_master *qmblk;

	qmblk = vzquota_inode_qmblk(inode);
	if (qmblk == NULL)
		return -ENOENT;
	if (qmblk == VZ_QUOTA_BAD) {
		memset(qstat, 0, sizeof(*qstat));
		return 0;
	}

	qmblk_data_read_lock(qmblk);
	memcpy(qstat, &qmblk->dq_stat, sizeof(*qstat));
	qmblk_data_read_unlock(qmblk);
	qmblk_put(qmblk);
	return 0;
}

int
vzquota_snap_init(struct super_block *vsuper, void *vzs, struct path *path)
{
	int err;
	struct vz_quota_master *qmblk;

	qmblk = vzquota_find_qmblk(vsuper);
	if (qmblk == NULL)
		return -ENOENT;
	if (qmblk == VZ_QUOTA_BAD)
		return -ENOENT;

	err = -EBUSY;
	qmblk_data_write_lock(qmblk);
	if (!qmblk->dq_snap && qmblk->dq_root_path.mnt &&
			qmblk->dq_root_path.dentry &&
			qmblk->dq_root_path.mnt->mnt_sb->s_bdev) {
		qmblk->dq_snap = vzs;
		*path = qmblk->dq_root_path;
		path_get(path);
		err = 0;
	}
	qmblk_data_write_unlock(qmblk);

	qmblk_put(qmblk);
	return err;
}
EXPORT_SYMBOL(vzquota_snap_init);

int vzquota_snap_stop(struct super_block *super, void *vzs)
{
	int err;
	struct vz_quota_master *qmblk;

	qmblk = vzquota_find_qmblk(super);
	if (qmblk == NULL)
		return -ENOENT;
	if (qmblk == VZ_QUOTA_BAD)
		return -ENOENT;

	err = -ENOENT;
	qmblk_data_write_lock(qmblk);
	if (qmblk->dq_snap == vzs) {
		err = 0;
		qmblk->dq_snap = NULL;
	}
	qmblk_data_write_unlock(qmblk);

	qmblk_put(qmblk);
	return err;
}
EXPORT_SYMBOL(vzquota_snap_stop);

/* ----------------------------------------------------------------------
 *
 * Init/exit helpers
 *
 * ---------------------------------------------------------------------*/

static int vzquota_cache_init(void)
{
	int i;

	vzquota_cachep = kmem_cache_create("vz_quota_master",
					 sizeof(struct vz_quota_master),
					 0, SLAB_HWCACHE_ALIGN, NULL);
	if (vzquota_cachep == NULL) {
		printk(KERN_ERR "Cannot create VZ_QUOTA SLAB cache\n");
		goto nomem2;
	}
	for (i = 0; i < VZ_QUOTA_HASH_SIZE; i++)
		INIT_LIST_HEAD(&vzquota_hash_table[i]);

	return 0;

nomem2:
	return -ENOMEM;
}

static void vzquota_cache_release(void)
{
	int i;

	/* sanity check */
	for (i = 0; i < VZ_QUOTA_HASH_SIZE; i++)
		if (!list_empty(&vzquota_hash_table[i]))
			BUG();

	/* release caches */
	kmem_cache_destroy(vzquota_cachep);
	vzquota_cachep = NULL;
}

static int quota_notifier_call(struct vnotifier_block *self,
		unsigned long n, void *data, int err)
{
	struct virt_info_quota *viq;
	struct super_block *sb;

	viq = (struct virt_info_quota *)data;
	switch (n) {
	case VIRTINFO_QUOTA_ON:
		err = NOTIFY_BAD;
		if (!try_module_get(THIS_MODULE))
			break;
		sb = viq->super;
		memset(&sb->s_dquot.info, 0, sizeof(sb->s_dquot.info));
		INIT_LIST_HEAD(&sb->s_dquot.info[USRQUOTA].dqi_dirty_list);
		INIT_LIST_HEAD(&sb->s_dquot.info[GRPQUOTA].dqi_dirty_list);
		err = NOTIFY_OK;
		break;
	case VIRTINFO_QUOTA_OFF:
		module_put(THIS_MODULE);
		err = NOTIFY_OK;
		break;
	case VIRTINFO_QUOTA_GETSTAT:
		err = NOTIFY_BAD;
		if (vzquota_dstat(viq->inode, viq->qstat))
			break;
		err = NOTIFY_OK;
		break;
	case VIRTINFO_QUOTA_DISABLE:
		err = NOTIFY_OK;
		vzquota_inode_off((struct inode *)data);
		break;
	case VIRTINFO_ORPHAN_CLEAN: {
		struct virt_info_orphan *vi = (struct virt_info_orphan *)data;

		if (vzquota_on_cookie(vi->super, vi->cookie))
			err = NOTIFY_BAD;
		else
			err = NOTIFY_OK;
		break;
	}
	case VIRTINFO_ORPHAN_DONE: {
		struct virt_info_orphan *vi = (struct virt_info_orphan *)data;

		vzquota_off_cookies(vi->super);
		break;
	}
	}
	return err;
}

struct vnotifier_block quota_notifier_block = {
	.notifier_call = quota_notifier_call,
	.priority = INT_MAX,
};

/* ----------------------------------------------------------------------
 *
 * Init/exit procedures
 *
 * ---------------------------------------------------------------------*/

static int __init vzquota_init(void)
{
	int err;

	if ((err = vzquota_cache_init()) != 0)
		goto out_cache;

	if ((err = vzquota_proc_init()) != 0)
		goto out_proc;

#ifdef CONFIG_VZ_QUOTA_UGID
	if ((err = vzquota_ugid_init()) != 0)
		goto out_ugid;
#endif

	mutex_init(&vz_quota_mutex);
	vzioctl_register(&vzdqcalls);
	virtinfo_notifier_register(VITYPE_QUOTA, &quota_notifier_block);
#if defined(CONFIG_VZ_QUOTA_UGID) && defined(CONFIG_PROC_FS)
	vzaquota_init();
#endif

	return 0;

#ifdef CONFIG_VZ_QUOTA_UGID
out_ugid:
	vzquota_proc_release();
#endif
out_proc:
	vzquota_cache_release();
out_cache:
	return err;
}

#if defined(VZ_QUOTA_UNLOAD)
static void __exit vzquota_release(void)
{
	virtinfo_notifier_unregister(VITYPE_QUOTA, &quota_notifier_block);
	vzioctl_unregister(&vzdqcalls);
#ifdef CONFIG_VZ_QUOTA_UGID
#ifdef CONFIG_PROC_FS
	vzaquota_fini();
#endif
	vzquota_ugid_release();
#endif
	vzquota_proc_release();
	vzquota_cache_release();
}
#endif

MODULE_AUTHOR("Virtuozzo");
MODULE_DESCRIPTION("Virtuozzo Disk Quota");
MODULE_LICENSE("GPL v2");

module_init(vzquota_init)
#if defined(VZ_QUOTA_UNLOAD)
module_exit(vzquota_release)
#endif
