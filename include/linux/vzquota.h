/*
 *
 * Copyright (C) 2001-2005 SWsoft
 * All rights reserved.
 * 
 * Licensing governed by "linux/COPYING.SWsoft" file.
 *
 * This file contains Virtuozzo disk quota implementation
 */

#ifndef _VZDQUOTA_H
#define _VZDQUOTA_H

#include <linux/types.h>
#include <linux/quota.h>
#include <linux/sched.h>

/* vzquotactl syscall commands */
#define VZ_DQ_CREATE		5 /* create quota master block */
#define VZ_DQ_DESTROY		6 /* destroy qmblk */
#define VZ_DQ_ON		7 /* mark dentry with already created qmblk */
#define VZ_DQ_OFF		8 /* remove mark, don't destroy qmblk */
#define VZ_DQ_SETLIMIT		9 /* set new limits */
#define VZ_DQ_GETSTAT		10 /* get usage statistic */
#define VZ_DQ_OFF_FORCED	11 /* forced off */
#define VZ_DQ_ON_FILE		12 /* on with data in file */
#define VZ_DQ_OFF_FILE		13 /* off and sync data to file */
#define VZ_DQ_STATUS		14 /* report general info (see VZDQ_XXX below) */

/* set of syscalls to maintain UGID quotas */
#define VZ_DQ_UGID_GETSTAT	1 /* get usage/limits for ugid(s) */
#define VZ_DQ_UGID_ADDSTAT	2 /* set usage/limits statistic for ugid(s) */
#define VZ_DQ_UGID_GETGRACE	3 /* get expire times */
#define VZ_DQ_UGID_SETGRACE	4 /* set expire times */
#define VZ_DQ_UGID_GETCONFIG	5 /* get ugid_max limit, cnt, flags of qmblk */
#define VZ_DQ_UGID_SETCONFIG	6 /* set ugid_max limit, flags of qmblk */
#define VZ_DQ_UGID_SETLIMIT	7 /* set ugid B/I limits */
#define VZ_DQ_UGID_SETINFO	8 /* set ugid info */

/* common structure for vz and ugid quota */
struct dq_stat {
	/* blocks limits */
	__u64	bhardlimit;	/* absolute limit in bytes */
	__u64	bsoftlimit;	/* preferred limit in bytes */
	time_t	btime;		/* time limit for excessive disk use */
	__u64	bcurrent;	/* current bytes count */
	/* inodes limits */
	__u32	ihardlimit;	/* absolute limit on allocated inodes */
	__u32	isoftlimit;	/* preferred inode limit */
	time_t	itime;		/* time limit for excessive inode use */
	__u32	icurrent;	/* current # allocated inodes */
};

/* One second resolution for grace times */
#define CURRENT_TIME_SECONDS	(get_seconds())

/* Values for dq_info->flags */
#define VZ_QUOTA_INODES 0x01       /* inodes limit warning printed */
#define VZ_QUOTA_SPACE  0x02       /* space limit warning printed */

struct dq_info {
	time_t		bexpire;   /* expire timeout for excessive disk use */
	time_t		iexpire;   /* expire timeout for excessive inode use */
	unsigned	flags;	   /* see previos defines */
};

struct vz_quota_stat  {
	struct dq_stat dq_stat;
	struct dq_info dq_info;
};

struct vz_quota_hdr {
	__le32	magic;
	__le32	version;
};

#define VZQUOTA_MAGIC		0x31031982
#define VZQUOTA_VERSION_0	0
#define VZQUOTA_STAT_OFF	sizeof(struct vz_quota_hdr)
#define VZQUOTA_ROOT_FILE	".vzdq.%d"

struct vz_quota_stat_img {
	__le64	btime;
	__le64	bexpire;
	__le64	itime;
	__le64	iexpire;

	__le64	bhardlimit;
	__le64	bsoftlimit;
	__le64	bcurrent;

	__le32	ihardlimit;
	__le32	isoftlimit;
	__le32	icurrent;
	__le32	flags;
};

#define VZQUOTA_UGINFO_OFF	(VZQUOTA_STAT_OFF + \
				sizeof(struct vz_quota_stat_img))

struct vz_quota_uginfo_img {
	__le32	ugid_max;
	__le32	user_flags;
	__le64	uid_bexpire;
	__le64	uid_iexpire;
	__le64	gid_bexpire;
	__le64	gid_iexpire;
};

#define VZQUOTA_UGID_OFF	4096

struct vz_quota_ugid_stat_img {
	__le32	flags;

	__le32	ihardlimit;
	__le32	isoftlimit;
	__le32	icurrent;

	__le64	bhardlimit;
	__le64	bsoftlimit;
	__le64	bcurrent;

	__le64	btime;
	__le64	itime;
};

#define VZQUOTA_UGID_ITEM_BITS	6
#define VZQUOTA_UGID_ITEM_SIZE	(1 << VZQUOTA_UGID_ITEM_BITS)
#define VZQUOTA_UGID_BITS	23
#define VZQUOTA_UGID_SIZE	(1 << VZQUOTA_UGID_BITS)
#define VZQUOTA_MAX_UGID	0xffff
#define VZQUOTA_UGID_PRESENT	0x1

/* UID/GID interface record - for user-kernel level exchange */
struct vz_quota_iface {
	unsigned int	qi_id;	   /* UID/GID this applies to */
	unsigned int	qi_type;   /* USRQUOTA|GRPQUOTA */
	struct dq_stat	qi_stat;   /* limits, options, usage stats */
};

#ifdef CONFIG_COMPAT
#include <linux/compat.h>
struct compat_dq_stat {
	/* blocks limits */
	__u64	bhardlimit;	/* absolute limit in bytes */
	__u64	bsoftlimit;	/* preferred limit in bytes */
	compat_time_t btime;	/* time limit for excessive disk use */
	__u64	bcurrent;	/* current bytes count */
	/* inodes limits */
	__u32	ihardlimit;	/* absolute limit on allocated inodes */
	__u32	isoftlimit;	/* preferred inode limit */
	compat_time_t itime;	/* time limit for excessive inode use */
	__u32	icurrent;	/* current # allocated inodes */
};

struct compat_dq_info {
	compat_time_t	bexpire;   /* expire timeout for excessive disk use */
	compat_time_t	iexpire;   /* expire timeout for excessive inode use */
	unsigned	flags;	   /* see previos defines */
};

struct compat_vz_quota_stat  {
	struct compat_dq_stat dq_stat;
	struct compat_dq_info dq_info;
};

struct compat_vz_quota_iface {
	unsigned int	qi_id;	   /* UID/GID this applies to */
	unsigned int	qi_type;   /* USRQUOTA|GRPQUOTA */
	struct compat_dq_stat qi_stat;   /* limits, options, usage stats */
};

static inline void compat_dqstat2dqstat(struct compat_dq_stat *odqs,
				struct dq_stat *dqs)
{
	dqs->bhardlimit = odqs->bhardlimit;
	dqs->bsoftlimit = odqs->bsoftlimit;
	dqs->bcurrent = odqs->bcurrent;
	dqs->btime = odqs->btime;

	dqs->ihardlimit = odqs->ihardlimit;
	dqs->isoftlimit = odqs->isoftlimit;
	dqs->icurrent = odqs->icurrent;
	dqs->itime = odqs->itime;
}

static inline void compat_dqinfo2dqinfo(struct compat_dq_info *odqi,
				struct dq_info *dqi)
{
	dqi->bexpire = odqi->bexpire;
	dqi->iexpire = odqi->iexpire;
	dqi->flags = odqi->flags;
}

static inline void dqstat2compat_dqstat(struct dq_stat *dqs,
				struct compat_dq_stat *odqs)
{
	odqs->bhardlimit = dqs->bhardlimit;
	odqs->bsoftlimit = dqs->bsoftlimit;
	odqs->bcurrent = dqs->bcurrent;
	odqs->btime = (compat_time_t)dqs->btime;

	odqs->ihardlimit = dqs->ihardlimit;
	odqs->isoftlimit = dqs->isoftlimit;
	odqs->icurrent = dqs->icurrent;
	odqs->itime = (compat_time_t)dqs->itime;
}

static inline void dqinfo2compat_dqinfo(struct dq_info *dqi,
				struct compat_dq_info *odqi)
{
	odqi->bexpire = (compat_time_t)dqi->bexpire;
	odqi->iexpire = (compat_time_t)dqi->iexpire;
	odqi->flags = dqi->flags;
}
#endif

/* values for flags and dq_flags */
/* this flag is set if the userspace has been unable to provide usage
 * information about all ugids
 * if the flag is set, we don't allocate new UG quota blocks (their
 * current usage is unknown) or free existing UG quota blocks (not to
 * lose information that this block is ok) */
#define VZDQUG_FIXED_SET	0x01
/* permit to use ugid quota */
#define VZDQUG_ON		0x02
#define VZDQ_USRQUOTA		0x10
#define VZDQ_GRPQUOTA		0x20
#define VZDQ_NOACT		0x1000	/* not actual */
#define VZDQ_NOQUOT		0x2000	/* not under quota tree */
#define VZDQF_USER_MASK		0xFFFF0000 /* for user_flags above */

struct vz_quota_ugid_stat {
	unsigned int	limit;	/* max amount of ugid records */
	unsigned int	count;	/* amount of ugid records */
	unsigned int	flags;	
};

struct vz_quota_ugid_setlimit {
	unsigned int	type;	/* quota type (USR/GRP) */
	unsigned int	id;	/* ugid */
	struct if_dqblk dqb;	/* limits info */
};

struct vz_quota_ugid_setinfo {
	unsigned int	type;	/* quota type (USR/GRP) */
	struct if_dqinfo dqi;	/* grace info */
};

/* values for dq_state */
#define VZDQ_STARTING		0 /* created, not turned on yet */
#define VZDQ_WORKING		1 /* quota created, turned on */
#define VZDQ_STOPING		2 /* created, turned on and off */
#define VZDQ_ORPHAN_CLEANUP	3 /* cleaning out orphans */
#define VZDQ_WORKING_JOURNAL	4 /* quota created, turned on with journal */

#ifdef __KERNEL__
#include <linux/list.h>
#include <asm/atomic.h>
#include <linux/time.h>
#include <linux/vzquota_qlnk.h>
#include <linux/vzdq_tree.h>
#include <linux/semaphore.h>

/* Values for dq_info flags */
#define VZ_QUOTA_INODES	0x01	   /* inodes limit warning printed */
#define VZ_QUOTA_SPACE	0x02	   /* space limit warning printed */

/* Kernel space data structures */
struct dq_kstat {
	/* blocks limits */
	__u64   bhardlimit;     /* absolute limit in bytes */
	__u64   bsoftlimit;     /* preferred limit in bytes */
	time_t  btime;	  /* time limit for excessive disk use */
	__u64   bcurrent;       /* current bytes count */
	__u64   breserved;      /* reserved bytes count */
	/* inodes limits */
	__u32   ihardlimit;     /* absolute limit on allocated inodes */
	__u32   isoftlimit;     /* preferred inode limit */
	time_t  itime;	  /* time limit for excessive inode use */
	__u32   icurrent;       /* current # allocated inodes */
};

struct dq_kinfo {
	time_t	  bexpire;   /* expire timeout for excessive disk use */
	time_t	  iexpire;   /* expire timeout for excessive inode use */
	unsigned	flags;     /* see previos defines */
};

struct vz_quota_kstat {
	struct dq_kstat dq_stat;
	struct dq_kinfo dq_info;
};

static inline void user_dqstat2dqstat(struct dq_stat *odqs,
				struct dq_kstat *dqs)
{
	dqs->bhardlimit = odqs->bhardlimit;
	dqs->bsoftlimit = odqs->bsoftlimit;
	dqs->bcurrent = odqs->bcurrent;
	dqs->breserved = 0;
	dqs->btime = odqs->btime;

	dqs->ihardlimit = odqs->ihardlimit;
	dqs->isoftlimit = odqs->isoftlimit;
	dqs->icurrent = odqs->icurrent;
	dqs->itime = odqs->itime;
}

static inline void user_dqinfo2dqinfo(struct dq_info *odqi,
				struct dq_kinfo *dqi)
{
	dqi->bexpire = odqi->bexpire;
	dqi->iexpire = odqi->iexpire;
	dqi->flags = odqi->flags;
}

static inline void dqstat2user_dqstat(struct dq_kstat *dqs,
				struct dq_stat *odqs)
{
	odqs->bhardlimit = dqs->bhardlimit;
	odqs->bsoftlimit = dqs->bsoftlimit;
	odqs->bcurrent = dqs->bcurrent;
	odqs->btime = dqs->btime;

	odqs->ihardlimit = dqs->ihardlimit;
	odqs->isoftlimit = dqs->isoftlimit;
	odqs->icurrent = dqs->icurrent;
	odqs->itime = dqs->itime;
}

static inline void dqinfo2user_dqinfo(struct dq_kinfo *dqi,
				struct dq_info *odqi)
{
	odqi->bexpire = dqi->bexpire;
	odqi->iexpire = dqi->iexpire;
	odqi->flags = dqi->flags;
}

/* master quota record - one per veid */
struct vz_quota_master {
	struct list_head	dq_hash;	/* next quota in hash list */
	atomic_t		dq_count;	/* inode reference count */
	unsigned int		dq_flags;	/* see VZDQUG_FIXED_SET */
	unsigned int		dq_state;	/* see values above */
	unsigned int		dq_id;		/* VEID this applies to */
	struct dq_kstat	 dq_stat;	/* limits, grace, usage stats */
	struct dq_kinfo	 dq_info;	/* grace times and flags */
	spinlock_t		dq_data_lock;	/* for dq_stat */

	struct mutex		dq_mutex;	/* mutex to protect
						   ugid tree */

	struct list_head	dq_ilink_list;	/* list of vz_quota_ilink */
	struct quotatree_tree	*dq_uid_tree;	/* vz_quota_ugid tree for UIDs */
	struct quotatree_tree	*dq_gid_tree;	/* vz_quota_ugid tree for GIDs */
	unsigned int		dq_ugid_count;	/* amount of ugid records */
	unsigned int		dq_ugid_max;	/* max amount of ugid records */
	struct dq_kinfo	 dq_ugid_info[MAXQUOTAS]; /* ugid grace times */

	struct inode		*qfile;
	struct mutex		dq_write_lock;

	struct path		dq_root_path;	/* path of fs tree */
	struct super_block	*dq_sb;	      /* superblock of our quota root */
	void			*dq_snap;       /* pointer to vzsnap struct */
};

/* UID/GID quota record - one per pair (quota_master, uid or gid) */
struct vz_quota_ugid {
	unsigned int		qugid_id;     /* UID/GID this applies to */
	struct dq_kstat	 qugid_stat;   /* limits, options, usage stats */
	int			qugid_type;   /* USRQUOTA|GRPQUOTA */
	atomic_t		qugid_count;  /* reference count */
};

#define VZ_QUOTA_UGBAD		((struct vz_quota_ugid *)0xfeafea11)

struct vz_quota_datast {
	struct vz_quota_ilink qlnk;
};

#define VIRTINFO_QUOTA_GETSTAT	0
#define VIRTINFO_QUOTA_ON	1
#define VIRTINFO_QUOTA_OFF	2
#define VIRTINFO_QUOTA_DISABLE	3
#define VIRTINFO_ORPHAN_CLEAN	4
#define VIRTINFO_ORPHAN_DONE	5

struct virt_info_quota {
	struct super_block *super;
	struct inode *inode;
	struct dq_kstat *qstat;
};

struct virt_info_orphan {
	struct super_block *super;
	unsigned int cookie;
};

void __vzquota_mark_dirty(struct vz_quota_master *qmblk,
		struct vz_quota_ugid **ugid);
void vzquota_cur_qmblk_orphan_set(struct vz_quota_master *qmblk);
int vzquota_on_cookie(struct super_block *sb, unsigned int cookie);
void vzquota_off_cookies(struct super_block *sb);
int vzquota_read_ugid(struct vz_quota_master *qmblk, struct inode *ino);
void vzquota_ugid_dump(struct vz_quota_ugid *ugid,
		struct vz_quota_ugid_stat_img *img);
int vzquota_ugid_write(struct inode *ino, struct vz_quota_ugid_stat_img *img,
		int id, int type);
int vzquota_read_uginfo(struct vz_quota_master *, struct inode *);
int vzquota_uginfo_write(struct inode *ino, struct vz_quota_uginfo_img *img);
void vzquota_uginfo_dump(struct vz_quota_master *qmblk,
		struct vz_quota_uginfo_img *img);

static inline void vzquota_mark_dirty(struct vz_quota_master *qmblk,
		struct vz_quota_ugid **ugid)
{
	/* FIXME - race with vzquota_off */
	if (qmblk->qfile != NULL)
		__vzquota_mark_dirty(qmblk, ugid);
}

void __vzquota_mark_dirty_ugids(struct vz_quota_master *qmblk,
		struct vz_quota_ugid **dirty);

static inline struct vz_quota_ugid *__vzquota_get_ugid(struct vz_quota_ugid *qugid)
{
	atomic_inc(&qugid->qugid_count);
	return qugid;
}

/*
 * Interface to VZ quota core
 */
#define INODE_QLNK(inode)	(&(inode)->i_qlnk)
#define QLNK_INODE(qlnk)	container_of((qlnk), struct inode, i_qlnk)

#define VZ_QUOTA_BAD		((struct vz_quota_master *)0xefefefef)

#define VZ_QUOTAO_SETE		1
#define VZ_QUOTAO_INIT		2
#define VZ_QUOTAO_DESTR		3
#define VZ_QUOTAO_SWAP		4
#define VZ_QUOTAO_INICAL	5
#define VZ_QUOTAO_DRCAL		6
#define VZ_QUOTAO_QSET		7
#define VZ_QUOTAO_TRANS		8
#define VZ_QUOTAO_ACT		9
#define VZ_QUOTAO_DTREE		10
#define VZ_QUOTAO_DET		11
#define VZ_QUOTAO_ON		12
#define VZ_QUOTAO_RE_LOCK	13

extern struct mutex vz_quota_mutex;

void inode_qmblk_lock(struct super_block *sb);
void inode_qmblk_unlock(struct super_block *sb);
void qmblk_data_read_lock(struct vz_quota_master *qmblk);
void qmblk_data_read_unlock(struct vz_quota_master *qmblk);
void qmblk_data_write_lock(struct vz_quota_master *qmblk);
void qmblk_data_write_unlock(struct vz_quota_master *qmblk);

/* for quota operations */
void vzquota_inode_init_call(struct inode *inode);
void vzquota_inode_swap_call(struct inode *, struct inode *);
void vzquota_inode_drop_call(struct inode *inode);
int vzquota_inode_transfer_call(struct inode *, struct iattr *);
struct vz_quota_master *vzquota_inode_data(struct inode *inode,
		struct vz_quota_datast *);
void vzquota_data_unlock(struct inode *inode, struct vz_quota_datast *);
int vzquota_rename_check(struct inode *inode,
		struct inode *old_dir, struct inode *new_dir);
struct vz_quota_master *vzquota_inode_qmblk(struct inode *inode);
/* for second-level quota */
struct vz_quota_master *vzquota_find_qmblk(struct super_block *);
/* for management operations */
struct vz_quota_master *vzquota_alloc_master(unsigned int quota_id,
		struct vz_quota_kstat *qstat);
void vzquota_free_master(struct vz_quota_master *);
struct vz_quota_master *vzquota_find_master(unsigned int quota_id);
int vzquota_on_qmblk(struct super_block *sb, struct inode *inode,
		struct vz_quota_master *qmblk, char __user *buf);
int vzquota_off_qmblk(struct super_block *sb, struct vz_quota_master *qmblk,
		char __user *buf, int force);
int vzquota_get_super(struct super_block *sb);
void vzquota_put_super(struct super_block *sb);

/* ----------------------------------------------------------------------
 *
 * Passing quota information through current
 *
 * Used in inode -> qmblk lookup at inode creation stage (since at that
 * time there are no links between the inode being created and its parent
 * directory).
 *
 * Used also in NFS - when one opens inode by its i_ino the inode is
 * actually detached and vzquota can't find qmblk for it. However the
 * export's root is a good candidate for this.
 *
 * --------------------------------------------------------------------- */

#define VZDQ_CUR_MAGIC		0x57d0fee2
#define VZDQ_CUR_CLEANUP	0x56d2def4

static inline void vzquota_cur_qmblk_set(struct inode *data)
{
	struct task_struct *tsk;

	tsk = current;

	WARN_ON(tsk->magic == VZDQ_CUR_CLEANUP);
	tsk->magic = VZDQ_CUR_MAGIC;
	tsk->ino = data;
}

static inline struct vz_quota_master *qmblk_get(struct vz_quota_master *qmblk)
{
	if (!atomic_read(&qmblk->dq_count))
		BUG();
	atomic_inc(&qmblk->dq_count);
	return qmblk;
}

static inline void __qmblk_put(struct vz_quota_master *qmblk)
{
	atomic_dec(&qmblk->dq_count);
}

static inline void qmblk_put(struct vz_quota_master *qmblk)
{
	if (!atomic_dec_and_test(&qmblk->dq_count))
		return;
	vzquota_free_master(qmblk);
}

extern struct list_head vzquota_hash_table[];
extern int vzquota_hash_size;

/*
 * Interface to VZ UGID quota
 */
extern struct quotactl_ops vz_quotactl_operations;
extern struct dquot_operations vz_quota_operations2;
extern struct dquot_operations vz_quota_operations2_rsv;
extern struct quota_format_type vz_quota_empty_v2_format;

#define QUGID_TREE(qmblk, type)	(((type) == USRQUOTA) ?		\
					qmblk->dq_uid_tree :	\
					qmblk->dq_gid_tree)

#define VZDQUG_FIND_DONT_ALLOC	1
#define VZDQUG_FIND_FAKE	2
struct vz_quota_ugid *vzquota_find_ugid(struct vz_quota_master *qmblk,
		unsigned int quota_id, int type, int flags);
struct vz_quota_ugid *__vzquota_find_ugid(struct vz_quota_master *qmblk,
		unsigned int quota_id, int type, int flags);
struct vz_quota_ugid *vzquota_get_ugid(struct vz_quota_ugid *qugid);
void vzquota_put_ugid(struct vz_quota_master *qmblk,
		struct vz_quota_ugid *qugid);
void vzquota_kill_ugid(struct vz_quota_master *qmblk);
int vzquota_ugid_init(void);
void vzquota_ugid_release(void);
int vzquota_transfer_usage(struct inode *inode, int mask,
		struct vz_quota_ilink *qlnk, struct vz_quota_ugid **dirty);
void vzquota_inode_off(struct inode *inode);

long do_vzquotaugidctl(int cmd, unsigned int quota_id,
		unsigned int ugid_index, unsigned int ugid_size,
		void *addr, int compat);

/*
 * Other VZ quota parts
 */
extern struct dquot_operations vz_quota_operations;
extern struct dquot_operations vz_quota_operations_rsv;

#define IS_VZ_QUOTA(sb) ((sb)->dq_op == &vz_quota_operations ||		\
				(sb)->dq_op == &vz_quota_operations_rsv)

long do_vzquotactl(int cmd, unsigned int quota_id,
		struct vz_quota_stat __user *qstat, const char __user *ve_root,
		int compat);
int vzquota_proc_init(void);
void vzquota_proc_release(void);
struct vz_quota_master *vzquota_find_qmblk(struct super_block *);

void vzaquota_init(void);
void vzaquota_fini(void);

struct vzsnap_struct;
extern int vzquota_snap_init(struct super_block *, void *, struct path *);
extern int vzquota_snap_stop(struct super_block *, void *);


/* This is the ugliest hack of the release, we have to fixup filesystem type
 * in order to support quota tools.
 */
static inline int vzquota_fake_fstype(const struct task_struct *tsk)
{
	const char **p;
	const char *comm;
	const char *comm_list[] = {
		"convertquota",
		"edquota",
		"quota",
		"quot",
		"quotacheck",
		"quotadebug",
		"quotaon",
		"quotaoff",
		"quotastats",
		"quota_nld",
		"repquota",
		"rpc.rquotad",
		"setquota",
		"setup_quota_group",
		"xqmstats"
		"warnquota",
		NULL,
	};
	comm = strrchr(tsk->comm, '/');
	if (comm)
		comm++;
	else
		comm = tsk->comm;

	p = comm_list;
	while (*p != NULL) {
		if (!strcmp(*p, comm))
			return 1;
		p++;
	}
	return 0;
}

/* quotacheck uses direct scan mode for ext2/ext3 */
#define VZQUOTA_FAKE_FSTYPE "reiserfs"

#endif /* __KERNEL__ */

#endif /* _VZDQUOTA_H */
