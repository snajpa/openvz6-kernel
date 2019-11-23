/*
 * Copyright (C) 2002 SWsoft
 * All rights reserved.
 * 
 * Licensing governed by "linux/COPYING.SWsoft" file.
 *
 * This file contains Virtuozzo UID/GID disk quota implementation
 */

#include <linux/string.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/smp_lock.h>
#include <linux/rcupdate.h>
#include <asm/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/quota.h>
#include "../quotaio_v2.h"
#include <linux/virtinfo.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/mnt_namespace.h>
#include <linux/vmalloc.h>
#include <linux/quotaops.h>

#include <linux/vzctl.h>
#include <linux/vzctl_quota.h>
#include <linux/vzquota.h>

/*
 * XXX
 * may be something is needed for sb->s_dquot->info[]?
 */

#define USRQUOTA_MASK		(1 << USRQUOTA)
#define GRPQUOTA_MASK		(1 << GRPQUOTA)
#define QTYPE2MASK(type)	(1 << (type))

static struct kmem_cache *vz_quota_ugid_cachep;

inline struct vz_quota_ugid *vzquota_get_ugid(struct vz_quota_ugid *qugid)
{
	if (qugid != VZ_QUOTA_UGBAD)
		atomic_inc(&qugid->qugid_count);
	return qugid;
}

/* we don't limit users with zero limits */
static inline int vzquota_fake_stat(struct dq_kstat *stat)
{
	return stat->bhardlimit == 0 && stat->bsoftlimit == 0 &&
		stat->ihardlimit == 0 && stat->isoftlimit == 0;
}

/* callback function for quotatree_free() */
static inline void vzquota_free_qugid(void *ptr)
{
	struct vz_quota_ugid *qugid = (struct vz_quota_ugid *) ptr;
	if (qugid && qugid->qugid_stat.breserved) {
		printk("VZQUOTA: quota %u still has %lld block reserved\n",
			qugid->qugid_id, qugid->qugid_stat.breserved);
		dump_stack();
	}
	kmem_cache_free(vz_quota_ugid_cachep, ptr);
}

/*
 * destroy ugid, if it have zero refcount, limits and usage
 * must be called under qmblk->dq_mutex
 */
void vzquota_put_ugid(struct vz_quota_master *qmblk,
		struct vz_quota_ugid *qugid)
{
	if (qugid == VZ_QUOTA_UGBAD)
		return;
	qmblk_data_read_lock(qmblk);
	if (atomic_dec_and_test(&qugid->qugid_count) &&
	    (qmblk->dq_flags & VZDQUG_FIXED_SET) == 0 &&
	    vzquota_fake_stat(&qugid->qugid_stat) &&
	    qugid->qugid_stat.bcurrent == 0 &&
	    qugid->qugid_stat.icurrent == 0) {
		quotatree_remove(QUGID_TREE(qmblk, qugid->qugid_type),
				qugid->qugid_id);
		qmblk->dq_ugid_count--;
		vzquota_free_qugid(qugid);
	}
	qmblk_data_read_unlock(qmblk);
}

/*
 * Get ugid block by its index, like it would present in array.
 * In reality, this is not array - this is leafs chain of the tree.
 * NULL if index is out of range.
 * qmblk semaphore is required to protect the tree.
 */
static inline struct vz_quota_ugid *
vzquota_get_byindex(struct vz_quota_master *qmblk, unsigned int index, int type)
{
	return quotatree_leaf_byindex(QUGID_TREE(qmblk, type), index);
}

/*
 * get next element from ugid "virtual array"
 * ugid must be in current array and this array may not be changed between
 * two accesses (quaranteed by "stopped" quota state and quota semaphore)
 * qmblk semaphore is required to protect the tree
 */
static inline struct vz_quota_ugid *
vzquota_get_next(struct vz_quota_master *qmblk, struct vz_quota_ugid *qugid)
{
	return quotatree_get_next(QUGID_TREE(qmblk, qugid->qugid_type),
			qugid->qugid_id);
}

/*
 * requires dq_mutex
 */
struct vz_quota_ugid *__vzquota_find_ugid(struct vz_quota_master *qmblk,
			unsigned int quota_id, int type, int flags)
{
	struct vz_quota_ugid *qugid;
	struct quotatree_tree *tree;
	struct quotatree_find_state st;

	tree = QUGID_TREE(qmblk, type);
	qugid = quotatree_find(tree, quota_id, &st);
	if (qugid)
		goto success;

	/* caller does not want alloc */
	if (flags & VZDQUG_FIND_DONT_ALLOC)
		goto fail;

	if (flags & VZDQUG_FIND_FAKE)
		goto doit;

	/* check limit */
	if (qmblk->dq_ugid_count >= qmblk->dq_ugid_max)
		goto fail;

	/* see comment at VZDQUG_FIXED_SET define */
	if (qmblk->dq_flags & VZDQUG_FIXED_SET)
		goto fail;

doit:
	/* alloc new structure */
	qugid = kmem_cache_alloc(vz_quota_ugid_cachep,
			GFP_NOFS | __GFP_NOFAIL);
	if (qugid == NULL)
		goto fail;

	/* initialize new structure */
	qugid->qugid_id = quota_id;
	memset(&qugid->qugid_stat, 0, sizeof(qugid->qugid_stat));
	qugid->qugid_type = type;
	atomic_set(&qugid->qugid_count, 0);

	/* insert in tree */
	if (quotatree_insert(tree, quota_id, &st, qugid) < 0)
		goto fail_insert;
	qmblk->dq_ugid_count++;

success:
	vzquota_get_ugid(qugid);
	return qugid;

fail_insert:
	vzquota_free_qugid(qugid);
fail:
	return VZ_QUOTA_UGBAD;
}

/*
 * takes dq_mutex, may schedule
 */
struct vz_quota_ugid *vzquota_find_ugid(struct vz_quota_master *qmblk,
			unsigned int quota_id, int type, int flags)
{
	struct vz_quota_ugid *qugid;

	mutex_lock(&qmblk->dq_mutex);
	qugid = __vzquota_find_ugid(qmblk, quota_id, type, flags);
	mutex_unlock(&qmblk->dq_mutex);

	return qugid;
}

/*
 * destroy all ugid records on given quota master
 */
void vzquota_kill_ugid(struct vz_quota_master *qmblk)
{
	BUG_ON((qmblk->dq_gid_tree == NULL && qmblk->dq_uid_tree != NULL) ||
		(qmblk->dq_uid_tree == NULL && qmblk->dq_gid_tree != NULL));

	if (qmblk->dq_uid_tree != NULL) {
		quotatree_free(qmblk->dq_uid_tree, vzquota_free_qugid);
		quotatree_free(qmblk->dq_gid_tree, vzquota_free_qugid);
	}
}


/* ----------------------------------------------------------------------
 * Management interface to ugid quota for (super)users.
 * --------------------------------------------------------------------- */

static int vzquota_initialize2(struct inode *inode, int type)
{
	return QUOTA_OK;
}

static int vzquota_drop2(struct inode *inode)
{
	return QUOTA_OK;
}

static int vzquota_alloc_space2(struct inode *inode,
			     qsize_t number, int prealloc)
{
	inode_add_bytes(inode, number);
	return QUOTA_OK;
}

static int vzquota_reserve_space2(struct inode *inode,
			     qsize_t number, int prealloc)
{
	inode_add_rsv_space(inode, number);
	return QUOTA_OK;
}

static int vzquota_claim_reserved_space2(struct inode *inode, qsize_t number)
{
	inode_claim_rsv_space(inode, number);
	return QUOTA_OK;
}

static int vzquota_alloc_inode2(const struct inode *inode, qsize_t number)
{
	return QUOTA_OK;
}

static int vzquota_free_space2(struct inode *inode, qsize_t number)
{
	inode_sub_bytes(inode, number);
	return QUOTA_OK;
}
static void vzquota_release_reserved_space2(struct inode *inode, qsize_t num)
{
	inode_sub_rsv_space(inode, num);
}

static int vzquota_free_inode2(const struct inode *inode, qsize_t number)
{
	return QUOTA_OK;
}

static int vzquota_transfer2(struct inode *inode, struct iattr *iattr)
{
	return QUOTA_OK;
}

static qsize_t *vzquota_get_reserved_space2(struct inode *inode)
{
	return inode->i_sb->s_dquot.dq_op_orig->get_reserved_space(inode);
}

struct dquot_operations vz_quota_operations2 = {
	.initialize	= vzquota_initialize2,
	.drop		= vzquota_drop2,
	.alloc_space	= vzquota_alloc_space2,
	.alloc_inode	= vzquota_alloc_inode2,
	.free_space	= vzquota_free_space2,
	.free_inode	= vzquota_free_inode2,
	.transfer	= vzquota_transfer2,
};


struct dquot_operations vz_quota_operations2_rsv = {
	.initialize	= vzquota_initialize2,
	.drop		= vzquota_drop2,
	.alloc_space	= vzquota_alloc_space2,
	.alloc_inode	= vzquota_alloc_inode2,
	.reserve_space  = vzquota_reserve_space2,
	.claim_space    = vzquota_claim_reserved_space2,
	.release_rsv    = vzquota_release_reserved_space2,
	.get_reserved_space = vzquota_get_reserved_space2,
	.free_space	= vzquota_free_space2,
	.free_inode	= vzquota_free_inode2,
	.transfer	= vzquota_transfer2,
};


asmlinkage long sys_unlink(const char __user * pathname);
asmlinkage long sys_rename(const char __user * oldname,
	       const char __user * newname);
asmlinkage long sys_symlink(const char __user * oldname,
	       const char __user * newname);

/* called under sb->s_umount semaphore */
static int vz_restore_symlink(struct super_block *sb, char *path, int type)
{
	mm_segment_t oldfs;
	char *newpath;
	char dest[64];
	const char *names[] = {
		[USRQUOTA] "aquota.user",
		[GRPQUOTA] "aquota.group"
	};
	int err;

	newpath = kmalloc(strlen(path) + sizeof(".new"), GFP_KERNEL);
	if (newpath == NULL)
		return -ENOMEM;

	strcpy(newpath, path);
	strcat(newpath, ".new");

	sprintf(dest, "/proc/vz/vzaquota/%08x/%s",
			new_encode_dev(sb->s_dev), names[type]);

	/*
	 * Lockdep will learn unneeded dependency while unlink(2):
	 *	->s_umount => ->i_mutex/1 => ->i_mutex
	 * Reverse dependency is,
	 *	open_namei() => ->i_mutex => lookup_hash() => __lookup_hash()
	 *	=> ->lookup() \eq vzdq_aquotq_lookup() => find_qmblk_by_dev()
	 *	=> user_get_super() => ->s_umount
	 *
	 * However, first set of ->i_mutex'es belong to /, second to /proc .
	 * Right fix is to get rid of vz_restore_symlink(), of course.
	 */
	up_read(&sb->s_umount);

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_unlink(newpath);
	if (err < 0 && err != -ENOENT)
		goto out_restore;
	err = sys_symlink(dest, newpath);
	if (err < 0)
		goto out_restore;
	err = sys_rename(newpath, path);
out_restore:
	set_fs(oldfs);

	down_read(&sb->s_umount);
	/* umounted meanwhile? */
	if (err == 0 && !sb->s_root)
		err = -ENODEV;

	kfree(newpath);
	return err;
}

/* called under sb->s_umount semaphore */
static int vz_quota_on(struct super_block *sb, int type,
		int format_id, char *path, int remount)
{
	struct vz_quota_master *qmblk;
	struct super_block *real_sb;
	int mask2;
	int err;

	if (remount)
		return 0;

	qmblk = vzquota_find_qmblk(sb);
	err = -ESRCH;
	if (qmblk == NULL)
		goto out;
	err = -EIO;
	if (qmblk == VZ_QUOTA_BAD)
		goto out;

	err = vz_restore_symlink(sb, path, type);
	if (err < 0)
		goto out_put;

	mutex_lock(&vz_quota_mutex);
	mask2 = 0;

	err = -EIO;
	if (!sb->s_op->get_quota_root)
		goto out_sem;
	real_sb = sb->s_op->get_quota_root(sb)->i_sb;
	if (!IS_VZ_QUOTA(real_sb))
		goto out_sem;
	if (real_sb->s_dquot.dq_op_orig->reserve_space)
		sb->dq_op = &vz_quota_operations2_rsv;
	else
		sb->dq_op = &vz_quota_operations2;

	sb->s_qcop = &vz_quotactl_operations;
	if (type == USRQUOTA)
		mask2 = VZDQ_USRQUOTA;
	if (type == GRPQUOTA)
		mask2 = VZDQ_GRPQUOTA;

	err = -EBUSY;
	if (qmblk->dq_flags & mask2)
		goto out_sem;

	err = 0;
	qmblk->dq_flags |= mask2;
	sb->s_dquot.flags |= dquot_state_flag(
			DQUOT_USAGE_ENABLED | DQUOT_LIMITS_ENABLED, type);

out_sem:
	mutex_unlock(&vz_quota_mutex);
out_put:
	qmblk_put(qmblk);
out:
	return err;
}

static int vz_quota_off(struct super_block *sb, int type, int remount)
{
	struct vz_quota_master *qmblk;
	int mask2;
	int err;

	if (remount)
		return 0;

	qmblk = vzquota_find_qmblk(sb);
	mutex_lock(&vz_quota_mutex);
	err = -ESRCH;
	if (qmblk == NULL)
		goto out;
	err = -EIO;
	if (qmblk == VZ_QUOTA_BAD)
		goto out;

	mask2 = 0;
	if (type == USRQUOTA)
		mask2 = VZDQ_USRQUOTA;
	if (type == GRPQUOTA)
		mask2 = VZDQ_GRPQUOTA;
	err = -EINVAL;
	if (!(qmblk->dq_flags & mask2))
		goto out;

	qmblk->dq_flags &= ~mask2;
	err = 0;

out:
	mutex_unlock(&vz_quota_mutex);
	if (qmblk != NULL && qmblk != VZ_QUOTA_BAD)
		qmblk_put(qmblk);
	return err;
}

static int vz_quota_sync(struct super_block *sb, int type)
{
	return 0;	/* vz quota is always uptodate */
}

static int vz_get_dqblk(struct super_block *sb, int type,
		qid_t id, struct if_dqblk *di)
{
	struct vz_quota_master *qmblk;
	struct vz_quota_ugid *ugid;
	int err;

	qmblk = vzquota_find_qmblk(sb);
	mutex_lock(&vz_quota_mutex);
	err = -ESRCH;
	if (qmblk == NULL)
		goto out;
	err = -EIO;
	if (qmblk == VZ_QUOTA_BAD)
		goto out;

	err = 0;
	ugid = vzquota_find_ugid(qmblk, id, type, VZDQUG_FIND_DONT_ALLOC);
	if (ugid != VZ_QUOTA_UGBAD) {
		qmblk_data_read_lock(qmblk);
		di->dqb_bhardlimit = ugid->qugid_stat.bhardlimit >> 10;
		di->dqb_bsoftlimit = ugid->qugid_stat.bsoftlimit >> 10;
		di->dqb_curspace = ugid->qugid_stat.bcurrent;
		di->dqb_ihardlimit = ugid->qugid_stat.ihardlimit;
		di->dqb_isoftlimit = ugid->qugid_stat.isoftlimit;
		di->dqb_curinodes = ugid->qugid_stat.icurrent;
		di->dqb_btime = ugid->qugid_stat.btime;
		di->dqb_itime = ugid->qugid_stat.itime;
		qmblk_data_read_unlock(qmblk);
		di->dqb_valid = QIF_ALL;
		vzquota_put_ugid(qmblk, ugid);
	} else {
		memset(di, 0, sizeof(*di));
		di->dqb_valid = QIF_ALL;
	}

out:
	mutex_unlock(&vz_quota_mutex);
	if (qmblk != NULL && qmblk != VZ_QUOTA_BAD)
		qmblk_put(qmblk);
	return err;
}

/* must be called under vz_quota_mutex */
static int __vz_set_dqblk(struct vz_quota_master *qmblk,
		int type, qid_t id, struct if_dqblk *di)
{
	struct vz_quota_ugid *ugid;

	ugid = vzquota_find_ugid(qmblk, id, type, 0);
	if (ugid == VZ_QUOTA_UGBAD)
		return -ESRCH;

	qmblk_data_write_lock(qmblk);
	/*
	 * Subtle compatibility breakage.
	 *
	 * Some old non-vz kernel quota didn't start grace period
	 * if the new soft limit happens to be below the usage.
	 * Non-vz kernel quota in 2.4.20 starts the grace period
	 * (if it hasn't been started).
	 * Current non-vz kernel performs even more complicated
	 * manipulations...
	 *
	 * Also, current non-vz kernels have inconsistency related to 
	 * the grace time start.  In regular operations the grace period
	 * is started if the usage is greater than the soft limit (and,
	 * strangely, is cancelled if the usage is less).
	 * However, set_dqblk starts the grace period if the usage is greater
	 * or equal to the soft limit.
	 *
	 * Here we try to mimic the behavior of the current non-vz kernel.
	 */
	if (di->dqb_valid & QIF_BLIMITS) {
		ugid->qugid_stat.bhardlimit =
			(__u64)di->dqb_bhardlimit << 10;
		ugid->qugid_stat.bsoftlimit =
			(__u64)di->dqb_bsoftlimit << 10;
		if (di->dqb_bsoftlimit == 0 ||
		    ugid->qugid_stat.bcurrent < ugid->qugid_stat.bsoftlimit)
			ugid->qugid_stat.btime = 0;
		else if (!(di->dqb_valid & QIF_BTIME))
			ugid->qugid_stat.btime = CURRENT_TIME_SECONDS
				+ qmblk->dq_ugid_info[type].bexpire;
		else
			ugid->qugid_stat.btime = di->dqb_btime;
	}
	if (di->dqb_valid & QIF_ILIMITS) {
		ugid->qugid_stat.ihardlimit = di->dqb_ihardlimit;
		ugid->qugid_stat.isoftlimit = di->dqb_isoftlimit;
		if (di->dqb_isoftlimit == 0 ||
		    ugid->qugid_stat.icurrent < ugid->qugid_stat.isoftlimit)
			ugid->qugid_stat.itime = 0;
		else if (!(di->dqb_valid & QIF_ITIME))
			ugid->qugid_stat.itime = CURRENT_TIME_SECONDS
				+ qmblk->dq_ugid_info[type].iexpire;
		else
			ugid->qugid_stat.itime = di->dqb_itime;
	}
	qmblk_data_write_unlock(qmblk);
	vzquota_put_ugid(qmblk, ugid);

	return 0;
}

static int vz_set_dqblk(struct super_block *sb, int type,
		qid_t id, struct if_dqblk *di)
{
	struct vz_quota_master *qmblk;
	int err;

	qmblk = vzquota_find_qmblk(sb);
	mutex_lock(&vz_quota_mutex);
	err = -ESRCH;
	if (qmblk == NULL)
		goto out;
	err = -EIO;
	if (qmblk == VZ_QUOTA_BAD)
		goto out;
	err = __vz_set_dqblk(qmblk, type, id, di);
out:
	mutex_unlock(&vz_quota_mutex);
	if (qmblk != NULL && qmblk != VZ_QUOTA_BAD)
		qmblk_put(qmblk);
	return err;
}

static int vz_get_dqinfo(struct super_block *sb, int type,
		struct if_dqinfo *ii)
{
	struct vz_quota_master *qmblk;
	int err;

	qmblk = vzquota_find_qmblk(sb);
	mutex_lock(&vz_quota_mutex);
	err = -ESRCH;
	if (qmblk == NULL)
		goto out;
	err = -EIO;
	if (qmblk == VZ_QUOTA_BAD)
		goto out;

	err = 0;
	ii->dqi_bgrace = qmblk->dq_ugid_info[type].bexpire;
	ii->dqi_igrace = qmblk->dq_ugid_info[type].iexpire;
	ii->dqi_flags = 0;
	ii->dqi_valid = IIF_ALL;

out:
	mutex_unlock(&vz_quota_mutex);
	if (qmblk != NULL && qmblk != VZ_QUOTA_BAD)
		qmblk_put(qmblk);
	return err;
}

/* must be called under vz_quota_mutex */
static int __vz_set_dqinfo(struct vz_quota_master *qmblk,
		int type, struct if_dqinfo *ii)
{
	if (ii->dqi_valid & IIF_FLAGS)
		if (ii->dqi_flags & DQF_MASK)
			return -EINVAL;

	if (ii->dqi_valid & IIF_BGRACE)
		qmblk->dq_ugid_info[type].bexpire = ii->dqi_bgrace;
	if (ii->dqi_valid & IIF_IGRACE)
		qmblk->dq_ugid_info[type].iexpire = ii->dqi_igrace;
	return 0;
}

static int vz_set_dqinfo(struct super_block *sb, int type,
		struct if_dqinfo *ii)
{
	struct vz_quota_master *qmblk;
	int err;

	qmblk = vzquota_find_qmblk(sb);
	mutex_lock(&vz_quota_mutex);
	err = -ESRCH;
	if (qmblk == NULL)
		goto out;
	err = -EIO;
	if (qmblk == VZ_QUOTA_BAD)
		goto out;
	err = __vz_set_dqinfo(qmblk, type, ii);
out:
	mutex_unlock(&vz_quota_mutex);
	if (qmblk != NULL && qmblk != VZ_QUOTA_BAD)
		qmblk_put(qmblk);
	return err;
}

#ifdef CONFIG_QUOTA_COMPAT

#define Q_GETQUOTI_SIZE 1024

#define UGID2DQBLK(dst, src)						\
	do {								\
		(dst)->dqb_ihardlimit = (src)->qugid_stat.ihardlimit;	\
		(dst)->dqb_isoftlimit = (src)->qugid_stat.isoftlimit;	\
		(dst)->dqb_curinodes = (src)->qugid_stat.icurrent;	\
		/* in 1K blocks */					\
		(dst)->dqb_bhardlimit = (src)->qugid_stat.bhardlimit >> 10; \
		/* in 1K blocks */					\
		(dst)->dqb_bsoftlimit = (src)->qugid_stat.bsoftlimit >> 10; \
		/* in bytes, 64 bit */					\
		(dst)->dqb_curspace = (src)->qugid_stat.bcurrent;	\
		(dst)->dqb_btime = (src)->qugid_stat.btime;		\
		(dst)->dqb_itime = (src)->qugid_stat.itime;		\
	} while (0)

static int vz_get_quoti(struct super_block *sb, int type, qid_t idx,
		struct v2_disk_dqblk __user *dqblk)
{
	struct vz_quota_master *qmblk;
	struct v2r0_disk_dqblk *data, *kbuf;
	struct vz_quota_ugid *ugid;
	int count;
	int err;

	qmblk = vzquota_find_qmblk(sb);
	err = -ESRCH;
	if (qmblk == NULL)
		goto out;
	err = -EIO;
	if (qmblk == VZ_QUOTA_BAD)
		goto out;

	err = -ENOMEM;
	kbuf = vmalloc(Q_GETQUOTI_SIZE * sizeof(*kbuf));
	if (!kbuf)
		goto out;

	mutex_lock(&vz_quota_mutex);
	mutex_lock(&qmblk->dq_mutex);
	for (ugid = vzquota_get_byindex(qmblk, idx, type), count = 0;
		ugid != NULL && count < Q_GETQUOTI_SIZE;
		count++)
	{
		data = kbuf + count;
		qmblk_data_read_lock(qmblk);
		UGID2DQBLK(data, ugid);
		qmblk_data_read_unlock(qmblk);
		data->dqb_id = ugid->qugid_id;

		/* Find next entry */
		ugid = vzquota_get_next(qmblk, ugid);
		BUG_ON(ugid != NULL && ugid->qugid_type != type);
	}
	mutex_unlock(&qmblk->dq_mutex);
	mutex_unlock(&vz_quota_mutex);

	err = count;
	if (copy_to_user(dqblk, kbuf, count * sizeof(*kbuf)))
		err = -EFAULT;

	vfree(kbuf);
out:
	if (qmblk != NULL && qmblk != VZ_QUOTA_BAD)
		qmblk_put(qmblk);

	return err;
}

#endif

struct quotactl_ops vz_quotactl_operations = {
	.quota_on	= vz_quota_on,
	.quota_off	= vz_quota_off,
	.quota_sync	= vz_quota_sync,
	.get_info	= vz_get_dqinfo,
	.set_info	= vz_set_dqinfo,
	.get_dqblk	= vz_get_dqblk,
	.set_dqblk	= vz_set_dqblk,
#ifdef CONFIG_QUOTA_COMPAT
	.get_quoti	= vz_get_quoti,
#endif
};

int vzquota_read_uginfo(struct vz_quota_master *qmblk, struct inode *ino)
{
	struct super_block *sb = ino->i_sb;
	size_t size;
	struct vz_quota_uginfo_img i;

	size = sb->s_op->quota_read_ino(sb, ino,
			(char *)&i, sizeof(i), VZQUOTA_UGINFO_OFF);
	if (size != sizeof(i))
		return -EIO;

	qmblk->dq_ugid_max = le32_to_cpu(i.ugid_max);
	qmblk->dq_flags = le32_to_cpu(i.user_flags) & VZDQF_USER_MASK;
	qmblk->dq_ugid_info[USRQUOTA].iexpire = le64_to_cpu(i.uid_iexpire);
	qmblk->dq_ugid_info[USRQUOTA].bexpire = le64_to_cpu(i.uid_bexpire);
	qmblk->dq_ugid_info[GRPQUOTA].iexpire = le64_to_cpu(i.uid_iexpire);
	qmblk->dq_ugid_info[GRPQUOTA].bexpire = le64_to_cpu(i.uid_bexpire);

	return 0;
}

static int vzquota_read_ugid_block(struct inode *ino, unsigned itemn, char *buf)
{
	struct super_block *sb = ino->i_sb;
	size_t size;

	size = sb->s_op->quota_read_ino(sb, ino, buf,
			VZQUOTA_UGID_ITEM_SIZE,
			VZQUOTA_UGID_OFF + (itemn << VZQUOTA_UGID_ITEM_BITS));
	return (size == VZQUOTA_UGID_ITEM_SIZE) ? 0 : -EIO;
}

static int vzquota_load_ugid_block(struct vz_quota_master *qmblk,
		struct vz_quota_ugid_stat_img *img, int id, int type)
{
	u32 flags;
	struct vz_quota_ugid *ugid;

	flags = le32_to_cpu(img->flags);
	if (!(flags & VZQUOTA_UGID_PRESENT))
		return 0;

	ugid = vzquota_find_ugid(qmblk, id, type, 0);
	if (ugid == VZ_QUOTA_UGBAD)
		return -ENOMEM;

	ugid->qugid_stat.bhardlimit = le64_to_cpu(img->bhardlimit);
	ugid->qugid_stat.bsoftlimit = le64_to_cpu(img->bsoftlimit);
	ugid->qugid_stat.bcurrent = le64_to_cpu(img->bcurrent);
	ugid->qugid_stat.ihardlimit = le32_to_cpu(img->ihardlimit);
	ugid->qugid_stat.isoftlimit = le32_to_cpu(img->isoftlimit);
	ugid->qugid_stat.icurrent = le32_to_cpu(img->icurrent);
	ugid->qugid_stat.btime = le64_to_cpu(img->btime);
	ugid->qugid_stat.itime = le64_to_cpu(img->itime);

	vzquota_put_ugid(qmblk, ugid);

	return 0;
}

int vzquota_read_ugid(struct vz_quota_master *qmblk, struct inode *ino)
{
	unsigned nr_items, i;
	int err;
	char *buf;

	BUILD_BUG_ON(sizeof(struct vz_quota_ugid_stat_img) > VZQUOTA_UGID_ITEM_SIZE);
	BUILD_BUG_ON(VZQUOTA_UGID_SIZE < VZQUOTA_MAX_UGID * 2 * VZQUOTA_UGID_ITEM_SIZE);
	BUG_ON(ino->i_blkbits < VZQUOTA_UGID_ITEM_BITS);

	err = -ENODATA;
	if (ino->i_size != VZQUOTA_UGID_OFF + VZQUOTA_UGID_SIZE)
		goto out;

	err = vzquota_read_uginfo(qmblk, ino);
	if (err)
		goto out;

	err = 0;
	if (qmblk->dq_ugid_max == 0)
		goto out;

	qmblk->dq_flags |= VZDQUG_ON | VZDQ_USRQUOTA | VZDQ_GRPQUOTA;

	err = -ENOMEM;
	buf = kmalloc(VZQUOTA_UGID_ITEM_SIZE, GFP_KERNEL);
	if (buf == NULL)
		goto out;

	nr_items = 1 << (VZQUOTA_UGID_BITS - VZQUOTA_UGID_ITEM_BITS);

	for (i = 0; i < nr_items; i++) {
		err = vzquota_read_ugid_block(ino, i, buf);
		if (err)
			break;

		err = vzquota_load_ugid_block(qmblk,
				(struct vz_quota_ugid_stat_img *)buf,
				i >> 1, i & 1);
		if (err)
			break;
	}

	kfree(buf);
out:
	return err;
}

void vzquota_uginfo_dump(struct vz_quota_master *qmblk,
		struct vz_quota_uginfo_img *img)
{
	img->uid_iexpire = cpu_to_le64(qmblk->dq_ugid_info[USRQUOTA].iexpire);
	img->uid_bexpire = cpu_to_le64(qmblk->dq_ugid_info[USRQUOTA].bexpire);
	img->uid_iexpire = cpu_to_le64(qmblk->dq_ugid_info[GRPQUOTA].iexpire);
	img->uid_bexpire = cpu_to_le64(qmblk->dq_ugid_info[GRPQUOTA].bexpire);
	img->user_flags = cpu_to_le32(qmblk->dq_flags & VZDQF_USER_MASK);
	img->ugid_max = cpu_to_le32(qmblk->dq_ugid_max);
}

void vzquota_ugid_dump(struct vz_quota_ugid *ugid,
		struct vz_quota_ugid_stat_img *img)
{
	img->flags = cpu_to_le32(VZQUOTA_UGID_PRESENT);
	img->bhardlimit = cpu_to_le64(ugid->qugid_stat.bhardlimit);
	img->bsoftlimit = cpu_to_le64(ugid->qugid_stat.bsoftlimit);
	img->bcurrent = cpu_to_le64(ugid->qugid_stat.bcurrent);
	img->ihardlimit = cpu_to_le32(ugid->qugid_stat.ihardlimit);
	img->isoftlimit = cpu_to_le32(ugid->qugid_stat.isoftlimit);
	img->icurrent = cpu_to_le32(ugid->qugid_stat.icurrent);
	img->btime = cpu_to_le64(ugid->qugid_stat.btime);
	img->itime = cpu_to_le64(ugid->qugid_stat.itime);
}

int vzquota_uginfo_write(struct inode *ino, struct vz_quota_uginfo_img *img)
{
	struct super_block *sb = ino->i_sb;
	size_t size;

	size = sb->s_op->quota_write_ino(sb, ino,
			(char *)img, sizeof(*img), VZQUOTA_UGINFO_OFF);
	return (size == sizeof(*img)) ? 0 : -EIO;
}

int vzquota_ugid_write(struct inode *ino, struct vz_quota_ugid_stat_img *img,
		int id, int type)
{
	struct super_block *sb = ino->i_sb;
	int itemn;
	size_t size;

	itemn = (id << 1 | type);
	size = sb->s_op->quota_write_ino(sb, ino, (char *)img,
			VZQUOTA_UGID_ITEM_SIZE,
			VZQUOTA_UGID_OFF + (itemn << VZQUOTA_UGID_ITEM_BITS));

	return (size == VZQUOTA_UGID_ITEM_SIZE) ? 0 : -EIO;
}

/* ----------------------------------------------------------------------
 * Management interface for host system admins.
 * --------------------------------------------------------------------- */

static int quota_ugid_addstat(unsigned int quota_id, unsigned int ugid_size,
		struct vz_quota_iface __user *u_ugid_buf, int compat)
{
	struct vz_quota_master *qmblk;
	int ret;

	mutex_lock(&vz_quota_mutex);

	ret = -ENOENT;
	qmblk = vzquota_find_master(quota_id);
	if (qmblk == NULL)
		goto out;

	ret = -EBUSY;
	if (qmblk->dq_state != VZDQ_STARTING)
		goto out; /* working quota doesn't accept new ugids */

	ret = 0;
	/* start to add ugids */
	for (ret = 0; ret < ugid_size; ret++) {
		struct vz_quota_iface qif;
		struct vz_quota_ugid *ugid;

		if (!compat) {
			if (copy_from_user(&qif, u_ugid_buf, sizeof(qif)))
				break;
			u_ugid_buf++; /* next user buffer */
		} else {
#ifdef CONFIG_COMPAT
			struct compat_vz_quota_iface oqif;
			if (copy_from_user(&oqif, u_ugid_buf,
							sizeof(oqif)))
				break;
			qif.qi_id = oqif.qi_id;
			qif.qi_type = oqif.qi_type;
			compat_dqstat2dqstat(&oqif.qi_stat, &qif.qi_stat);
			u_ugid_buf = (struct vz_quota_iface __user *)
					(((void *)u_ugid_buf) + sizeof(oqif));
#endif
		}

		if (qif.qi_type >= MAXQUOTAS)
			break; /* bad quota type - this is the only check */

		ugid = vzquota_find_ugid(qmblk,
				qif.qi_id, qif.qi_type, 0);
		if (ugid == VZ_QUOTA_UGBAD) {
			qmblk->dq_flags |= VZDQUG_FIXED_SET;
			break; /* limit reached */
		}

		/* update usage/limits
		 * we can copy the data without the lock, because the data
		 * cannot be modified in VZDQ_STARTING state */
		user_dqstat2dqstat(&qif.qi_stat, &ugid->qugid_stat);
		vzquota_put_ugid(qmblk, ugid);
	}
out:
	mutex_unlock(&vz_quota_mutex);

	return ret;
}

static int quota_ugid_setgrace(unsigned int quota_id,
		struct dq_info __user u_dq_info[], int compat)
{
	struct vz_quota_master *qmblk;
	struct dq_info udq_info[MAXQUOTAS];
	struct dq_kinfo *target;
	int err, type;

	mutex_lock(&vz_quota_mutex);

	err = -ENOENT;
	qmblk = vzquota_find_master(quota_id);
	if (qmblk == NULL)
		goto out;

	err = -EBUSY;
	if (qmblk->dq_state != VZDQ_STARTING)
		goto out; /* working quota doesn't accept changing options */

	err = -EFAULT;
	if (!compat) {
		if (copy_from_user(udq_info, u_dq_info, sizeof(udq_info)))
			goto out;
	} else {
#ifdef CONFIG_COMPAT
		struct compat_dq_info odqi[MAXQUOTAS];
		if (copy_from_user(odqi, u_dq_info, sizeof(odqi)))
			goto out;
		for (type = 0; type < MAXQUOTAS; type++)
			compat_dqinfo2dqinfo(&odqi[type], &udq_info[type]);
#endif
	}
	err = 0;

	/* update in qmblk */
	for (type = 0; type < MAXQUOTAS; type++) {
		target = &qmblk->dq_ugid_info[type];
		target->bexpire = udq_info[type].bexpire;
		target->iexpire = udq_info[type].iexpire;
	}
out:
	mutex_unlock(&vz_quota_mutex);

	return err;
}

static int do_quota_ugid_getstat(struct vz_quota_master *qmblk, int index, int size,
		struct vz_quota_iface *ugid_buf)
{
	int type, count;
	struct vz_quota_ugid *ugid;

	if (QTREE_LEAFNUM(qmblk->dq_uid_tree) +
	    QTREE_LEAFNUM(qmblk->dq_gid_tree)
	    		<= index)
		return 0;

	count = 0;

	type = index < QTREE_LEAFNUM(qmblk->dq_uid_tree) ? USRQUOTA : GRPQUOTA;
	if (type == GRPQUOTA)
		index -= QTREE_LEAFNUM(qmblk->dq_uid_tree);

	/* loop through ugid and then qgid quota */
repeat:
	for (ugid = vzquota_get_byindex(qmblk, index, type);
		ugid != NULL && count < size;
		ugid = vzquota_get_next(qmblk, ugid), count++)
	{
		struct vz_quota_iface qif;
		/* form interface buffer and send in to user-level */
		qmblk_data_read_lock(qmblk);
		dqstat2user_dqstat(&ugid->qugid_stat, &qif.qi_stat);
		qmblk_data_read_unlock(qmblk);
		qif.qi_id = ugid->qugid_id;
		qif.qi_type = ugid->qugid_type;
		memcpy(ugid_buf, &qif, sizeof(qif));
		ugid_buf++; /* next portion of user buffer */
	}

	if (type == USRQUOTA && count < size) {
		type = GRPQUOTA;
		index = 0;
		goto repeat;
	}

	return count;
}

static int quota_ugid_getstat(unsigned int quota_id,
		int index, int size, struct vz_quota_iface __user *u_ugid_buf,
		int compat)
{
	struct vz_quota_master *qmblk;
	struct vz_quota_iface *k_ugid_buf;
	int err;

	if (index < 0 || size < 0)
		return -EINVAL;

	if (size > INT_MAX / sizeof(struct vz_quota_iface))
		return -EINVAL;

	k_ugid_buf = vmalloc(size * sizeof(struct vz_quota_iface));
	if (k_ugid_buf == NULL)
		return -ENOMEM;

	mutex_lock(&vz_quota_mutex);

	err = -ENOENT;
	qmblk = vzquota_find_master(quota_id);
	if (qmblk == NULL)
		goto out;

	mutex_lock(&qmblk->dq_mutex);
	err = do_quota_ugid_getstat(qmblk, index, size, k_ugid_buf);
	mutex_unlock(&qmblk->dq_mutex);
	if (err < 0)
		goto out;

	if (!compat) {
		if (copy_to_user(u_ugid_buf, k_ugid_buf,
					err * sizeof(struct vz_quota_iface)))
			err = -EFAULT;
	} else {
#ifdef CONFIG_COMPAT
		struct compat_vz_quota_iface oqif;
		int i;
		for (i = 0; i < err; i++) {
			oqif.qi_id = k_ugid_buf[i].qi_id;
			oqif.qi_type = k_ugid_buf[i].qi_type;
			dqstat2compat_dqstat(&k_ugid_buf[i].qi_stat,
					  &oqif.qi_stat);
			if (copy_to_user(u_ugid_buf, &oqif, sizeof(oqif)))
				err = -EFAULT;
			u_ugid_buf = (struct vz_quota_iface __user *)
					(((void *)u_ugid_buf) + sizeof(oqif));
		}
#endif
	}

out:
	mutex_unlock(&vz_quota_mutex);
	vfree(k_ugid_buf);
	return err;
}

static int quota_ugid_getgrace(unsigned int quota_id,
		struct dq_info __user u_dq_info[], int compat)
{
	struct vz_quota_master *qmblk;
	struct dq_info dq_info[MAXQUOTAS];
	struct dq_kinfo *target;
	int err, type;

	mutex_lock(&vz_quota_mutex);

	err = -ENOENT;
	qmblk = vzquota_find_master(quota_id);
	if (qmblk == NULL)
		goto out;
	
	err = 0;
	/* update from qmblk */
	for (type = 0; type < MAXQUOTAS; type ++) {
		target = &qmblk->dq_ugid_info[type];
		dq_info[type].bexpire = target->bexpire;
		dq_info[type].iexpire = target->iexpire;
		dq_info[type].flags = target->flags;
	}

	if (!compat) {
		if (copy_to_user(u_dq_info, dq_info, sizeof(dq_info)))
			err = -EFAULT;
	} else {
#ifdef CONFIG_COMPAT
		struct compat_dq_info odqi[MAXQUOTAS];
		for (type = 0; type < MAXQUOTAS; type ++)
			dqinfo2compat_dqinfo(&dq_info[type], &odqi[type]);
		if (copy_to_user(u_dq_info, odqi, sizeof(odqi)))
			err = -EFAULT;
#endif
	}
out:
	mutex_unlock(&vz_quota_mutex);

	return err;
}

static int quota_ugid_getconfig(unsigned int quota_id, 
		struct vz_quota_ugid_stat __user *info)
{
	struct vz_quota_master *qmblk;
	struct vz_quota_ugid_stat kinfo;
	int err;

	mutex_lock(&vz_quota_mutex);

	err = -ENOENT;
	qmblk = vzquota_find_master(quota_id);
	if (qmblk == NULL)
		goto out;
	
	err = 0;
	kinfo.limit = qmblk->dq_ugid_max;
	kinfo.count = qmblk->dq_ugid_count;
	kinfo.flags = qmblk->dq_flags;
	if (qmblk->qfile == NULL)
		kinfo.flags &= ~VZDQF_USER_MASK;

	if (copy_to_user(info, &kinfo, sizeof(kinfo)))
		err = -EFAULT;
out:
	mutex_unlock(&vz_quota_mutex);

	return err;
}

static int quota_ugid_setconfig(unsigned int quota_id,
		struct vz_quota_ugid_stat __user *info)
{
	struct vz_quota_master *qmblk;
	struct vz_quota_ugid_stat kinfo;
	int err;

	mutex_lock(&vz_quota_mutex);

	err = -ENOENT;
	qmblk = vzquota_find_master(quota_id);
	if (qmblk == NULL)
		goto out;

	err = -EFAULT;
	if (copy_from_user(&kinfo, info, sizeof(kinfo)))
		goto out;

	err = 0;
	qmblk->dq_ugid_max = kinfo.limit;
	if (qmblk->qfile != NULL) {
		if (kinfo.flags & ~VZDQF_USER_MASK) {
			err = -EINVAL;
			goto out;
		}

		qmblk->dq_flags = (qmblk->dq_flags & ~VZDQF_USER_MASK) |
					(kinfo.flags & VZDQF_USER_MASK);
	} else if (qmblk->dq_state == VZDQ_STARTING) {
		if (kinfo.flags & VZDQF_USER_MASK) {
			printk("VZDQ: API misuse!\n");
			err = -EINVAL;
			goto out;
		}

		qmblk->dq_flags = kinfo.flags;
		if (qmblk->dq_flags & VZDQUG_ON)
			qmblk->dq_flags |= VZDQ_USRQUOTA | VZDQ_GRPQUOTA;
	}

out:
	mutex_unlock(&vz_quota_mutex);

	return err;
}

static int quota_ugid_setlimit(unsigned int quota_id,
		struct vz_quota_ugid_setlimit __user *u_lim)
{
	struct vz_quota_master *qmblk;
	struct vz_quota_ugid_setlimit lim;
	int err;

	mutex_lock(&vz_quota_mutex);

	err = -ESRCH;
	qmblk = vzquota_find_master(quota_id);
	if (qmblk == NULL)
		goto out;

	err = -EFAULT;
	if (copy_from_user(&lim, u_lim, sizeof(lim)))
		goto out;

	err = __vz_set_dqblk(qmblk, lim.type, lim.id, &lim.dqb);

out:
	mutex_unlock(&vz_quota_mutex);

	return err;
}

static int quota_ugid_setinfo(unsigned int quota_id,
		struct vz_quota_ugid_setinfo __user *u_info)
{
	struct vz_quota_master *qmblk;
	struct vz_quota_ugid_setinfo info;
	int err;

	mutex_lock(&vz_quota_mutex);

	err = -ESRCH;
	qmblk = vzquota_find_master(quota_id);
	if (qmblk == NULL)
		goto out;

	err = -EFAULT;
	if (copy_from_user(&info, u_info, sizeof(info)))
		goto out;

	err = __vz_set_dqinfo(qmblk, info.type, &info.dqi);

out:
	mutex_unlock(&vz_quota_mutex);

	return err;
}

/*
 * This is a system call to maintain UGID quotas
 * Note this call is allowed to run ONLY from VE0
 */
long do_vzquotaugidctl(int cmd, unsigned int quota_id,
		unsigned int ugid_index, unsigned int ugid_size,
		void *addr, int compat)
{
	int ret;

	ret = -EPERM;
	/* access allowed only from root of VE0 */
	if (!capable(CAP_SYS_RESOURCE) ||
	    !capable(CAP_SYS_ADMIN))
		goto out;

	switch (cmd) {
		case VZ_DQ_UGID_GETSTAT:
			ret = quota_ugid_getstat(quota_id,
					ugid_index, ugid_size,
				       	(struct vz_quota_iface __user *)addr,
					compat);
			break;
		case VZ_DQ_UGID_ADDSTAT:
			ret = quota_ugid_addstat(quota_id, ugid_size,
					(struct vz_quota_iface __user *) addr,
					compat);
			break;
		case VZ_DQ_UGID_GETGRACE:
			ret = quota_ugid_getgrace(quota_id,
					(struct dq_info __user *)addr, compat);
			break;
		case VZ_DQ_UGID_SETGRACE:
			ret = quota_ugid_setgrace(quota_id,
					(struct dq_info __user *)addr, compat);
			break;
		case VZ_DQ_UGID_GETCONFIG:
			ret = quota_ugid_getconfig(quota_id,
					(struct vz_quota_ugid_stat __user *)
								addr);
			break;
		case VZ_DQ_UGID_SETCONFIG:
			ret = quota_ugid_setconfig(quota_id,
					(struct vz_quota_ugid_stat __user *)
								addr);
			break;
		case VZ_DQ_UGID_SETLIMIT:
			ret = quota_ugid_setlimit(quota_id,
					(struct vz_quota_ugid_setlimit __user *)
								addr);
			break;
		case VZ_DQ_UGID_SETINFO:
			ret = quota_ugid_setinfo(quota_id,
					(struct vz_quota_ugid_setinfo __user *)
								addr);
			break;
		default:
			ret = -EINVAL;
			goto out;
	}
out:
	return ret;
}

static void ugid_quota_on_sb(struct super_block *sb)
{
	struct super_block *real_sb;
	struct vz_quota_master *qmblk;

	if (!sb->s_op->get_quota_root)
		return;

	real_sb = sb->s_op->get_quota_root(sb)->i_sb;
	if (!IS_VZ_QUOTA(real_sb))
		return;

	sb->dq_op = &vz_quota_operations2;
	sb->s_qcop = &vz_quotactl_operations;
	INIT_LIST_HEAD(&sb->s_dquot.info[USRQUOTA].dqi_dirty_list);
	INIT_LIST_HEAD(&sb->s_dquot.info[GRPQUOTA].dqi_dirty_list);
	sb->s_dquot.info[USRQUOTA].dqi_format = &vz_quota_empty_v2_format;
	sb->s_dquot.info[GRPQUOTA].dqi_format = &vz_quota_empty_v2_format;

	qmblk = vzquota_find_qmblk(sb);
	if ((qmblk == NULL) || (qmblk == VZ_QUOTA_BAD))
		return;
	mutex_lock(&vz_quota_mutex);
	if (qmblk->dq_flags & VZDQ_USRQUOTA)
		sb->s_dquot.flags |= dquot_state_flag(DQUOT_USAGE_ENABLED |
				DQUOT_LIMITS_ENABLED, USRQUOTA);
	if (qmblk->dq_flags & VZDQ_GRPQUOTA)
		sb->s_dquot.flags |= dquot_state_flag(DQUOT_USAGE_ENABLED |
				DQUOT_LIMITS_ENABLED, GRPQUOTA);
	mutex_unlock(&vz_quota_mutex);
	qmblk_put(qmblk);
}

static void ugid_quota_off_sb(struct super_block *sb)
{
	/* can't make quota off on mounted super block */
	BUG_ON(sb->s_root != NULL);
}

static int ugid_notifier_call(struct vnotifier_block *self,
		unsigned long n, void *data, int old_ret)
{
	struct virt_info_quota *viq;

	viq = (struct virt_info_quota *)data;

	switch (n) {
	case VIRTINFO_QUOTA_ON:
		ugid_quota_on_sb(viq->super);
		break;
	case VIRTINFO_QUOTA_OFF:
		ugid_quota_off_sb(viq->super);
		break;
	case VIRTINFO_QUOTA_GETSTAT:
		break;
	default:
		return old_ret;
	}
	return NOTIFY_OK;
}

static struct vnotifier_block ugid_notifier_block = {
	.notifier_call = ugid_notifier_call,
};

/* ----------------------------------------------------------------------
 * Init/exit.
 * --------------------------------------------------------------------- */

int vzquota_ugid_init(void)
{
	int err;

	vz_quota_ugid_cachep = kmem_cache_create("vz_quota_ugid",
				      sizeof(struct vz_quota_ugid),
				      0, SLAB_HWCACHE_ALIGN, NULL);
	if (vz_quota_ugid_cachep == NULL)
		goto err_slab;

	err = register_quota_format(&vz_quota_empty_v2_format);
	if (err)
		goto err_reg;

	virtinfo_notifier_register(VITYPE_QUOTA, &ugid_notifier_block);
	return 0;

err_reg:
	kmem_cache_destroy(vz_quota_ugid_cachep);
	return err;

err_slab:
	printk(KERN_ERR "Cannot create VZ_QUOTA SLAB cache\n");
	return -ENOMEM;
}

void vzquota_ugid_release(void)
{
	virtinfo_notifier_unregister(VITYPE_QUOTA, &ugid_notifier_block);
	unregister_quota_format(&vz_quota_empty_v2_format);

	kmem_cache_destroy(vz_quota_ugid_cachep);
}
