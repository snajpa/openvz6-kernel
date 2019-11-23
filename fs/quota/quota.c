/*
 * Quota code necessary even when VFS quota support is not compiled
 * into the kernel.  The interesting stuff is over in dquot.c, here
 * we have symbols for initial quotactl(2) handling, the sysctl(2)
 * variables, etc - things needed even when quota support disabled.
 */

#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <asm/current.h>
#include <asm/uaccess.h>
#include <linux/compat.h>
#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/buffer_head.h>
#include <linux/capability.h>
#include <linux/device_cgroup.h>
#include <linux/quotaops.h>
#include <linux/types.h>
#include <linux/nospec.h>
#include <net/netlink.h>
#include <net/genetlink.h>

/* Check validity of generic quotactl commands */
static int generic_quotactl_valid(struct super_block *sb, int type, int cmd,
				  qid_t id)
{
	if (type >= MAXQUOTAS)
		return -EINVAL;
	if (!sb && cmd != Q_SYNC)
		return -ENODEV;
	/* Is operation supported? */
	if (sb && !sb->s_qcop)
		return -ENOSYS;

	switch (cmd) {
		case Q_GETFMT:
			break;
		case Q_QUOTAON:
			if (!sb->s_qcop->quota_on)
				return -ENOSYS;
			break;
		case Q_QUOTAOFF:
			if (!sb->s_qcop->quota_off)
				return -ENOSYS;
			break;
		case Q_SETINFO:
			if (!sb->s_qcop->set_info)
				return -ENOSYS;
			break;
		case Q_GETINFO:
			if (!sb->s_qcop->get_info)
				return -ENOSYS;
			break;
		case Q_SETQUOTA:
			if (!sb->s_qcop->set_dqblk)
				return -ENOSYS;
			break;
		case Q_GETQUOTA:
			if (!sb->s_qcop->get_dqblk)
				return -ENOSYS;
			break;
		case Q_SYNC:
			if (sb && !sb->s_qcop->quota_sync)
				return -ENOSYS;
			break;
		default:
			return -EINVAL;
	}

	/* Is quota turned on for commands which need it? */
	switch (cmd) {
		case Q_GETFMT:
		case Q_GETINFO:
		case Q_SETINFO:
		case Q_SETQUOTA:
		case Q_GETQUOTA:
			/* This is just an informative test so we are satisfied
			 * without the lock */
			if (!sb_has_quota_active(sb, type))
				return -ESRCH;
	}

	/* Check privileges */
	if (cmd == Q_GETQUOTA) {
		if (((type == USRQUOTA && current_euid() != id) ||
		     (type == GRPQUOTA && !in_egroup_p(id))) &&
		    !capable(CAP_VE_SYS_ADMIN))
			return -EPERM;
	}
	else if (cmd != Q_GETFMT && cmd != Q_SYNC && cmd != Q_GETINFO)
		if (!capable(CAP_VE_SYS_ADMIN))
			return -EPERM;

	return 0;
}

/* Check validity of XFS Quota Manager commands */
static int xqm_quotactl_valid(struct super_block *sb, int type, int cmd,
			      qid_t id)
{
	if (type >= XQM_MAXQUOTAS)
		return -EINVAL;
	if (!sb)
		return -ENODEV;
	if (!sb->s_qcop)
		return -ENOSYS;

	switch (cmd) {
		case Q_XQUOTAON:
		case Q_XQUOTAOFF:
		case Q_XQUOTARM:
			if (!sb->s_qcop->set_xstate)
				return -ENOSYS;
			break;
		case Q_XGETQSTAT:
			if (!sb->s_qcop->get_xstate)
				return -ENOSYS;
			break;
		case Q_XSETQLIM:
			if (!sb->s_qcop->set_xquota)
				return -ENOSYS;
			break;
		case Q_XGETQUOTA:
			if (!sb->s_qcop->get_xquota)
				return -ENOSYS;
			break;
		case Q_XQUOTASYNC:
			if (!sb->s_qcop->quota_sync)
				return -ENOSYS;
			break;
		default:
			return -EINVAL;
	}

	/* Check privileges */
	if (cmd == Q_XGETQUOTA) {
		if (((type == XQM_USRQUOTA && current_euid() != id) ||
		     (type == XQM_GRPQUOTA && !in_egroup_p(id))) &&
		     !capable(CAP_VE_SYS_ADMIN))
			return -EPERM;
	} else if (cmd != Q_XGETQSTAT && cmd != Q_XQUOTASYNC) {
		if (!capable(CAP_VE_SYS_ADMIN))
			return -EPERM;
	}

	return 0;
}

static int check_quotactl_valid(struct super_block *sb, int type, int cmd,
				qid_t id)
{
	int error;

	if (XQM_COMMAND(cmd))
		error = xqm_quotactl_valid(sb, type, cmd, id);
	else
		error = generic_quotactl_valid(sb, type, cmd, id);
	if (!error)
		error = security_quotactl(cmd, type, id, sb);

	barrier_nospec();
	return error;
}

#ifdef CONFIG_QUOTA
void sync_quota_sb(struct super_block *sb, int type)
{
	int cnt;

	if (!sb->s_qcop || !sb->s_qcop->quota_sync)
		return;

	sb->s_qcop->quota_sync(sb, type);

	if (sb_dqopt(sb)->flags & DQUOT_QUOTA_SYS_FILE)
		return;
	/* This is not very clever (and fast) but currently I don't know about
	 * any other simple way of getting quota data to disk and we must get
	 * them there for userspace to be visible... */
	if (sb->s_op->sync_fs)
		sb->s_op->sync_fs(sb, 1);
	sync_blockdev(sb->s_bdev);

	/*
	 * Now when everything is written we can discard the pagecache so
	 * that userspace sees the changes.
	 */
	mutex_lock(&sb_dqopt(sb)->dqonoff_mutex);
	for (cnt = 0; cnt < MAXQUOTAS; cnt++) {
		if (type != -1 && cnt != type)
			continue;
		if (!sb_has_quota_active(sb, cnt))
			continue;
		if (!sb_dqopt(sb)->files[cnt])
			continue;
		mutex_lock_nested(&sb_dqopt(sb)->files[cnt]->i_mutex,
				  I_MUTEX_QUOTA);
		truncate_inode_pages(&sb_dqopt(sb)->files[cnt]->i_data, 0);
		mutex_unlock(&sb_dqopt(sb)->files[cnt]->i_mutex);
	}
	mutex_unlock(&sb_dqopt(sb)->dqonoff_mutex);
}
#endif

static void sync_dquots(int type)
{
	struct super_block *sb;
	int cnt;

	spin_lock(&sb_lock);
restart:
	list_for_each_entry(sb, &super_blocks, s_list) {
		/* This test just improves performance so it needn't be
		 * reliable... */
		for (cnt = 0; cnt < MAXQUOTAS; cnt++) {
			if (type != -1 && type != cnt)
				continue;
			if (!sb_has_quota_active(sb, cnt))
				continue;
			if (!info_dirty(&sb_dqopt(sb)->info[cnt]) &&
			   list_empty(&sb_dqopt(sb)->info[cnt].dqi_dirty_list))
				continue;
			break;
		}
		if (cnt == MAXQUOTAS)
			continue;
		sb->s_count++;
		spin_unlock(&sb_lock);
		down_read(&sb->s_umount);
		if (sb->s_root)
			sync_quota_sb(sb, type);
		up_read(&sb->s_umount);
		spin_lock(&sb_lock);
		if (__put_super_and_need_restart(sb))
			goto restart;
	}
	spin_unlock(&sb_lock);
}

/* Copy parameters and call proper function */
static int do_quotactl(struct super_block *sb, int type, int cmd, qid_t id,
		       void __user *addr)
{
	int ret;

	switch (cmd) {
		case Q_QUOTAON: {
			struct filename *pathname;

			pathname = getname(addr);
			if (IS_ERR(pathname))
				return PTR_ERR(pathname);
			ret = sb->s_qcop->quota_on(sb, type, id, (char *)pathname->name, 0);
			putname(pathname);
			return ret;
		}
		case Q_QUOTAOFF:
			return sb->s_qcop->quota_off(sb, type, 0);

		case Q_GETFMT: {
			__u32 fmt;

			down_read(&sb_dqopt(sb)->dqptr_sem);
			if (!sb_has_quota_active(sb, type)) {
				up_read(&sb_dqopt(sb)->dqptr_sem);
				return -ESRCH;
			}
			type = array_index_nospec(type, MAXQUOTAS);
			fmt = sb_dqopt(sb)->info[type].dqi_format->qf_fmt_id;
			up_read(&sb_dqopt(sb)->dqptr_sem);
			if (copy_to_user(addr, &fmt, sizeof(fmt)))
				return -EFAULT;
			return 0;
		}
		case Q_GETINFO: {
			struct if_dqinfo info;

			ret = sb->s_qcop->get_info(sb, type, &info);
			if (ret)
				return ret;
			if (copy_to_user(addr, &info, sizeof(info)))
				return -EFAULT;
			return 0;
		}
		case Q_SETINFO: {
			struct if_dqinfo info;

			if (copy_from_user(&info, addr, sizeof(info)))
				return -EFAULT;
			return sb->s_qcop->set_info(sb, type, &info);
		}
		case Q_GETQUOTA: {
			struct if_dqblk idq;

			ret = sb->s_qcop->get_dqblk(sb, type, id, &idq);
			if (ret)
				return ret;
			if (copy_to_user(addr, &idq, sizeof(idq)))
				return -EFAULT;
			return 0;
		}
		case Q_SETQUOTA: {
			struct if_dqblk idq;

			if (copy_from_user(&idq, addr, sizeof(idq)))
				return -EFAULT;
			return sb->s_qcop->set_dqblk(sb, type, id, &idq);
		}
		case Q_SYNC:
			if (sb)
				sync_quota_sb(sb, type);
			else
				sync_dquots(type);
			return 0;

		case Q_XQUOTAON:
		case Q_XQUOTAOFF:
		case Q_XQUOTARM: {
			__u32 flags;

			if (copy_from_user(&flags, addr, sizeof(flags)))
				return -EFAULT;
			return sb->s_qcop->set_xstate(sb, flags, cmd);
		}
		case Q_XGETQSTAT: {
			struct fs_quota_stat fqs;
		
			if ((ret = sb->s_qcop->get_xstate(sb, &fqs)))
				return ret;
			if (copy_to_user(addr, &fqs, sizeof(fqs)))
				return -EFAULT;
			return 0;
		}
		case Q_XSETQLIM: {
			struct fs_disk_quota fdq;

			if (copy_from_user(&fdq, addr, sizeof(fdq)))
				return -EFAULT;
		       return sb->s_qcop->set_xquota(sb, type, id, &fdq);
		}
		case Q_XGETQUOTA: {
			struct fs_disk_quota fdq;

			ret = sb->s_qcop->get_xquota(sb, type, id, &fdq);
			if (ret)
				return ret;
			if (copy_to_user(addr, &fdq, sizeof(fdq)))
				return -EFAULT;
			return 0;
		}
		case Q_XQUOTASYNC:
			return sb->s_qcop->quota_sync(sb, type);
		/* We never reach here unless validity check is broken */
		default:
			BUG();
	}
	return 0;
}

/* Return 1 if 'cmd' will block on frozen filesystem */
static int quotactl_cmd_write(int cmd)
{
	switch (cmd) {
	case Q_GETFMT:
	case Q_GETINFO:
	case Q_SYNC:
	case Q_XGETQSTAT:
	case Q_XGETQUOTA:
	case Q_XQUOTASYNC:
		return 0;
	}
	return 1;
}

/*
 * look up a superblock on which quota ops will be performed
 * - use the name of a block device to find the superblock thereon
 */
static struct super_block *quotactl_block(const char __user *special, int cmd)
{
#ifdef CONFIG_BLOCK
	struct block_device *bdev;
	struct super_block *sb;
	struct filename *tmp = getname(special);
	int error;

	if (IS_ERR(tmp))
		return ERR_CAST(tmp);
	bdev = lookup_bdev(tmp->name);
	putname(tmp);
	if (IS_ERR(bdev))
		return ERR_CAST(bdev);

	error = devcgroup_inode_permission(bdev->bd_inode, MAY_QUOTACTL);
	if (error) {
		bdput(bdev);
		return ERR_PTR(error);
	}

	if (quotactl_cmd_write(cmd))
		sb = get_super_thawed(bdev);
	else
		sb = get_super(bdev);
	bdput(bdev);
	if (!sb)
		return ERR_PTR(-ENODEV);

	return sb;
#else
	return ERR_PTR(-ENODEV);
#endif
}

#ifdef CONFIG_QUOTA_COMPAT

#define QC_QUOTAON  0x0100	/* enable quotas */
#define QC_QUOTAOFF 0x0200	/* disable quotas */
/* GETQUOTA, SETQUOTA and SETUSE which were at 0x0300-0x0500 has now other parameteres */
#define QC_SYNC     0x0600	/* sync disk copy of a filesystems quotas */
#define QC_SETQLIM  0x0700	/* set limits */
/* GETSTATS at 0x0800 is now longer... */
#define QC_GETINFO  0x0900	/* get info about quotas - graces, flags... */
#define QC_SETINFO  0x0A00	/* set info about quotas */
#define QC_SETGRACE 0x0B00	/* set inode and block grace */
#define QC_SETFLAGS 0x0C00	/* set flags for quota */
#define QC_GETQUOTA 0x0D00	/* get limits and usage */
#define QC_SETQUOTA 0x0E00	/* set limits and usage */
#define QC_SETUSE   0x0F00	/* set usage */
/* 0x1000 used by old RSQUASH */
#define QC_GETSTATS 0x1100	/* get collected stats */

struct compat_dqblk {
	unsigned int dqb_ihardlimit;
	unsigned int dqb_isoftlimit;
	unsigned int dqb_curinodes;
	unsigned int dqb_bhardlimit;
	unsigned int dqb_bsoftlimit;
	qsize_t dqb_curspace;
	__kernel_time_t dqb_btime;
	__kernel_time_t dqb_itime;
};

#ifdef CONFIG_COMPAT

struct compat_compat_dqblk {
	compat_uint_t	dqb_ihardlimit;
	compat_uint_t	dqb_isoftlimit;
	compat_uint_t	dqb_curinodes;
	compat_uint_t	dqb_bhardlimit;
	compat_uint_t	dqb_bsoftlimit;
	compat_u64	dqb_curspace;
	compat_time_t	dqb_btime;
	compat_time_t	dqb_itime;
};

#endif

struct compat_dqinfo {
	unsigned int dqi_bgrace;
	unsigned int dqi_igrace;
	unsigned int dqi_flags;
	unsigned int dqi_blocks;
	unsigned int dqi_free_blk;
	unsigned int dqi_free_entry;
};

struct compat_dqstats {
	__u32 lookups;
	__u32 drops;
	__u32 reads;
	__u32 writes;
	__u32 cache_hits;
	__u32 allocated_dquots;
	__u32 free_dquots;
	__u32 syncs;
	__u32 version;
};

asmlinkage long sys_quotactl(unsigned int cmd, const char __user *special, qid_t id, void __user *addr);

static long compat_quotactl(unsigned int cmds, unsigned int type,
		const char __user *special, qid_t id,
		void __user *addr)
{
	struct super_block *sb;
	long ret;

	sb = NULL;
	switch (cmds) {
		case QC_QUOTAON:
			return sys_quotactl(QCMD(Q_QUOTAON, type),
					special, id, addr);

		case QC_QUOTAOFF:
			return sys_quotactl(QCMD(Q_QUOTAOFF, type),
					special, id, addr);

		case QC_SYNC:
			return sys_quotactl(QCMD(Q_SYNC, type),
					special, id, addr);

		case QC_GETQUOTA: {
			struct if_dqblk idq;
			struct compat_dqblk cdq;

			sb = quotactl_block(special, cmds);
			ret = PTR_ERR(sb);
			if (IS_ERR(sb))
				break;
			ret = check_quotactl_valid(sb, type, Q_GETQUOTA, id);
			if (ret)
				break;
			ret = sb->s_qcop->get_dqblk(sb, type, id, &idq);
			if (ret)
				break;
			cdq.dqb_ihardlimit = idq.dqb_ihardlimit;
			cdq.dqb_isoftlimit = idq.dqb_isoftlimit;
			cdq.dqb_curinodes = idq.dqb_curinodes;
			cdq.dqb_bhardlimit = idq.dqb_bhardlimit;
			cdq.dqb_bsoftlimit = idq.dqb_bsoftlimit;
			cdq.dqb_curspace = idq.dqb_curspace;
			cdq.dqb_btime = idq.dqb_btime;
			cdq.dqb_itime = idq.dqb_itime;
			ret = 0;
			if (copy_to_user(addr, &cdq, sizeof(cdq)))
				ret = -EFAULT;
			break;
		}

		case QC_SETQUOTA:
		case QC_SETUSE:
		case QC_SETQLIM: {
			struct if_dqblk idq = {};
			struct compat_dqblk cdq;

			sb = quotactl_block(special, cmds);
			ret = PTR_ERR(sb);
			if (IS_ERR(sb))
				break;
			ret = check_quotactl_valid(sb, type, Q_SETQUOTA, id);
			if (ret)
				break;
			ret = -EFAULT;
			if (copy_from_user(&cdq, addr, sizeof(cdq)))
				break;
			idq.dqb_ihardlimit = cdq.dqb_ihardlimit;
			idq.dqb_isoftlimit = cdq.dqb_isoftlimit;
			idq.dqb_curinodes = cdq.dqb_curinodes;
			idq.dqb_bhardlimit = cdq.dqb_bhardlimit;
			idq.dqb_bsoftlimit = cdq.dqb_bsoftlimit;
			idq.dqb_curspace = cdq.dqb_curspace;
			idq.dqb_valid = 0;
			if (cmds == QC_SETQUOTA || cmds == QC_SETQLIM)
				idq.dqb_valid |= QIF_LIMITS;
			if (cmds == QC_SETQUOTA || cmds == QC_SETUSE)
				idq.dqb_valid |= QIF_USAGE;
			ret = sb->s_qcop->set_dqblk(sb, type, id, &idq);
			break;
		}

		case QC_GETINFO: {
			struct if_dqinfo iinf;
			struct compat_dqinfo cinf;

			sb = quotactl_block(special, cmds);
			ret = PTR_ERR(sb);
			if (IS_ERR(sb))
				break;
			ret = check_quotactl_valid(sb, type, Q_GETQUOTA, id);
			if (ret)
				break;
			ret = sb->s_qcop->get_info(sb, type, &iinf);
			if (ret)
				break;
			cinf.dqi_bgrace = iinf.dqi_bgrace;
			cinf.dqi_igrace = iinf.dqi_igrace;
			cinf.dqi_flags = 0;
			if (iinf.dqi_flags & DQF_INFO_DIRTY)
				cinf.dqi_flags |= 0x0010;
			cinf.dqi_blocks = 0;
			cinf.dqi_free_blk = 0;
			cinf.dqi_free_entry = 0;
			ret = 0;
			if (copy_to_user(addr, &cinf, sizeof(cinf)))
				ret = -EFAULT;
			break;
		}

		case QC_SETINFO:
		case QC_SETGRACE:
		case QC_SETFLAGS: {
			struct if_dqinfo iinf;
			struct compat_dqinfo cinf;

			sb = quotactl_block(special, cmds);
			ret = PTR_ERR(sb);
			if (IS_ERR(sb))
				break;
			ret = check_quotactl_valid(sb, type, Q_SETINFO, id);
			if (ret)
				break;
			ret = -EFAULT;
			if (copy_from_user(&cinf, addr, sizeof(cinf)))
				break;
			iinf.dqi_bgrace = cinf.dqi_bgrace;
			iinf.dqi_igrace = cinf.dqi_igrace;
			iinf.dqi_flags = cinf.dqi_flags;
			iinf.dqi_valid = 0;
			if (cmds == QC_SETINFO || cmds == QC_SETGRACE)
				iinf.dqi_valid |= IIF_BGRACE | IIF_IGRACE;
			if (cmds == QC_SETINFO || cmds == QC_SETFLAGS)
				iinf.dqi_valid |= IIF_FLAGS;
			ret = sb->s_qcop->set_info(sb, type, &iinf);
			break;
		}

		case QC_GETSTATS: {
			struct compat_dqstats stat;

			memset(&stat, 0, sizeof(stat));
			stat.version = 6*10000+5*100+0;
			ret = 0;
			if (copy_to_user(addr, &stat, sizeof(stat)))
				ret = -EFAULT;
			break;
		}

		default:
			ret = -ENOSYS;
			break;
	}
	if (sb && !IS_ERR(sb))
		drop_super(sb);
	return ret;
}

#endif

/*
 * This is the system call interface. This communicates with
 * the user-level programs. Currently this only supports diskquota
 * calls. Maybe we need to add the process quotas etc. in the future,
 * but we probably should use rlimits for that.
 */
SYSCALL_DEFINE4(quotactl, unsigned int, cmd, const char __user *, special,
		qid_t, id, void __user *, addr)
{
	uint cmds, type;
	struct super_block *sb = NULL;
	int ret;

	cmds = cmd >> SUBCMDSHIFT;
	type = cmd & SUBCMDMASK;

#ifdef CONFIG_QUOTA_COMPAT
	if (cmds >= 0x0100 && cmds < 0x3000)
		return compat_quotactl(cmds, type, special, id, addr);
#endif

	if (cmds != Q_SYNC || special) {
		sb = quotactl_block(special, cmds);
		if (IS_ERR(sb))
			return PTR_ERR(sb);
	}

	ret = check_quotactl_valid(sb, type, cmds, id);
	if (ret >= 0)
		ret = do_quotactl(sb, type, cmds, id, addr);
	if (sb)
		drop_super(sb);

	return ret;
}

#if defined(CONFIG_COMPAT_FOR_U64_ALIGNMENT)
/*
 * This code works only for 32 bit quota tools over 64 bit OS (x86_64, ia64)
 * and is necessary due to alignment problems.
 */
struct compat_if_dqblk {
	compat_u64 dqb_bhardlimit;
	compat_u64 dqb_bsoftlimit;
	compat_u64 dqb_curspace;
	compat_u64 dqb_ihardlimit;
	compat_u64 dqb_isoftlimit;
	compat_u64 dqb_curinodes;
	compat_u64 dqb_btime;
	compat_u64 dqb_itime;
	compat_uint_t dqb_valid;
};

/* XFS structures */
struct compat_fs_qfilestat {
	compat_u64 dqb_bhardlimit;
	compat_u64 qfs_nblks;
	compat_uint_t qfs_nextents;
};

struct compat_fs_quota_stat {
	__s8		qs_version;
	__u16		qs_flags;
	__s8		qs_pad;
	struct compat_fs_qfilestat	qs_uquota;
	struct compat_fs_qfilestat	qs_gquota;
	compat_uint_t	qs_incoredqs;
	compat_int_t	qs_btimelimit;
	compat_int_t	qs_itimelimit;
	compat_int_t	qs_rtbtimelimit;
	__u16		qs_bwarnlimit;
	__u16		qs_iwarnlimit;
};

asmlinkage long sys32_quotactl(unsigned int cmd, const char __user *special,
						qid_t id, void __user *addr)
{
	unsigned int cmds;
	struct if_dqblk __user *dqblk;
	struct compat_if_dqblk __user *compat_dqblk;
	struct fs_quota_stat __user *fsqstat;
	struct compat_fs_quota_stat __user *compat_fsqstat;
	compat_uint_t data;
	u16 xdata;
	long ret;
#ifdef CONFIG_QUOTA_COMPAT
	struct compat_dqblk __user *cdq;
	struct compat_compat_dqblk __user *compat_cdq;
	compat_time_t time;
#endif

	cmds = cmd >> SUBCMDSHIFT;

	switch (cmds) {
	case Q_GETQUOTA:
		dqblk = compat_alloc_user_space(sizeof(struct if_dqblk));
		compat_dqblk = addr;
		ret = sys_quotactl(cmd, special, id, dqblk);
		if (ret)
			break;
		if (copy_in_user(compat_dqblk, dqblk, sizeof(*compat_dqblk)) ||
			get_user(data, &dqblk->dqb_valid) ||
			put_user(data, &compat_dqblk->dqb_valid))
			ret = -EFAULT;
		break;
	case Q_SETQUOTA:
		dqblk = compat_alloc_user_space(sizeof(struct if_dqblk));
		compat_dqblk = addr;
		ret = -EFAULT;
		if (copy_in_user(dqblk, compat_dqblk, sizeof(*compat_dqblk)) ||
			get_user(data, &compat_dqblk->dqb_valid) ||
			put_user(data, &dqblk->dqb_valid))
			break;
		ret = sys_quotactl(cmd, special, id, dqblk);
		break;
	case Q_XGETQSTAT:
		fsqstat = compat_alloc_user_space(sizeof(struct fs_quota_stat));
		compat_fsqstat = addr;
		ret = sys_quotactl(cmd, special, id, fsqstat);
		if (ret)
			break;
		ret = -EFAULT;
		/* Copying qs_version, qs_flags, qs_pad */
		if (copy_in_user(compat_fsqstat, fsqstat,
			offsetof(struct compat_fs_quota_stat, qs_uquota)))
			break;
		/* Copying qs_uquota */
		if (copy_in_user(&compat_fsqstat->qs_uquota,
			&fsqstat->qs_uquota,
			sizeof(compat_fsqstat->qs_uquota)) ||
			get_user(data, &fsqstat->qs_uquota.qfs_nextents) ||
			put_user(data, &compat_fsqstat->qs_uquota.qfs_nextents))
			break;
		/* Copying qs_gquota */
		if (copy_in_user(&compat_fsqstat->qs_gquota,
			&fsqstat->qs_gquota,
			sizeof(compat_fsqstat->qs_gquota)) ||
			get_user(data, &fsqstat->qs_gquota.qfs_nextents) ||
			put_user(data, &compat_fsqstat->qs_gquota.qfs_nextents))
			break;
		/* Copying the rest */
		if (copy_in_user(&compat_fsqstat->qs_incoredqs,
			&fsqstat->qs_incoredqs,
			sizeof(struct compat_fs_quota_stat) -
			offsetof(struct compat_fs_quota_stat, qs_incoredqs)) ||
			get_user(xdata, &fsqstat->qs_iwarnlimit) ||
			put_user(xdata, &compat_fsqstat->qs_iwarnlimit))
			break;
		ret = 0;
		break;
#ifdef CONFIG_QUOTA_COMPAT
	case QC_GETQUOTA:
		cdq = compat_alloc_user_space(sizeof(struct compat_dqblk));
		compat_cdq = addr;
		ret = sys_quotactl(cmd, special, id, cdq);
		if (ret)
			break;
		ret = -EFAULT;
		if (copy_in_user(compat_cdq, cdq, sizeof(struct compat_compat_dqblk) -
				offsetof(struct compat_compat_dqblk, dqb_curspace)) ||
			copy_in_user(&compat_cdq->dqb_curspace, &cdq->dqb_curspace,
				sizeof(cdq->dqb_curspace)) ||
			get_user(time, &cdq->dqb_btime) ||
			put_user(time, &compat_cdq->dqb_btime) ||
			get_user(time, &cdq->dqb_itime) ||
			put_user(time, &compat_cdq->dqb_itime))
			break;
		ret = 0;
		break;
	case QC_SETQUOTA:
	case QC_SETUSE:
	case QC_SETQLIM:
		cdq = compat_alloc_user_space(sizeof(struct compat_dqblk));
		compat_cdq = addr;
		ret = -EFAULT;
		if (copy_in_user(cdq, compat_cdq, sizeof(struct compat_compat_dqblk) -
				offsetof(struct compat_compat_dqblk, dqb_curspace)) ||
			copy_in_user(&cdq->dqb_curspace, &compat_cdq->dqb_curspace,
				sizeof(cdq->dqb_curspace)) ||
			get_user(time, &compat_cdq->dqb_btime) ||
			put_user(time, &cdq->dqb_btime) ||
			get_user(time, &compat_cdq->dqb_itime) ||
			put_user(time, &cdq->dqb_itime))
			break;
		ret = sys_quotactl(cmd, special, id, cdq);
		break;
#endif
	default:
		ret = sys_quotactl(cmd, special, id, addr);
	}
	return ret;
}
#endif


#ifdef CONFIG_QUOTA_NETLINK_INTERFACE

/* Netlink family structure for quota */
static struct genl_family quota_genl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	.name = "VFS_DQUOT",
	.version = 1,
	.maxattr = QUOTA_NL_A_MAX,
};

/**
 * quota_send_warning - Send warning to userspace about exceeded quota
 * @type: The quota type: USRQQUOTA, GRPQUOTA,...
 * @id: The user or group id of the quota that was exceeded
 * @dev: The device on which the fs is mounted (sb->s_dev)
 * @warntype: The type of the warning: QUOTA_NL_...
 *
 * This can be used by filesystems (including those which don't use
 * dquot) to send a message to userspace relating to quota limits.
 *
 */

void quota_send_warning(short type, unsigned int id, dev_t dev,
			const char warntype)
{
	static atomic_t seq;
	struct sk_buff *skb;
	void *msg_head;
	int ret;
	int msg_size = 4 * nla_total_size(sizeof(u32)) +
		       2 * nla_total_size(sizeof(u64));

	/* We have to allocate using GFP_NOFS as we are called from a
	 * filesystem performing write and thus further recursion into
	 * the fs to free some data could cause deadlocks. */
	skb = genlmsg_new(msg_size, GFP_NOFS);
	if (!skb) {
		printk(KERN_ERR
		  "VFS: Not enough memory to send quota warning.\n");
		return;
	}
	msg_head = genlmsg_put(skb, 0, atomic_add_return(1, &seq),
			&quota_genl_family, 0, QUOTA_NL_C_WARNING);
	if (!msg_head) {
		printk(KERN_ERR
		  "VFS: Cannot store netlink header in quota warning.\n");
		goto err_out;
	}
	ret = nla_put_u32(skb, QUOTA_NL_A_QTYPE, type);
	if (ret)
		goto attr_err_out;
	ret = nla_put_u64(skb, QUOTA_NL_A_EXCESS_ID, id);
	if (ret)
		goto attr_err_out;
	ret = nla_put_u32(skb, QUOTA_NL_A_WARNING, warntype);
	if (ret)
		goto attr_err_out;
	ret = nla_put_u32(skb, QUOTA_NL_A_DEV_MAJOR, MAJOR(dev));
	if (ret)
		goto attr_err_out;
	ret = nla_put_u32(skb, QUOTA_NL_A_DEV_MINOR, MINOR(dev));
	if (ret)
		goto attr_err_out;
	ret = nla_put_u64(skb, QUOTA_NL_A_CAUSED_ID, current_uid());
	if (ret)
		goto attr_err_out;
	genlmsg_end(skb, msg_head);

	genlmsg_multicast(skb, 0, quota_genl_family.id, GFP_NOFS);
	return;
attr_err_out:
	printk(KERN_ERR "VFS: Not enough space to compose quota message!\n");
err_out:
	kfree_skb(skb);
}
EXPORT_SYMBOL(quota_send_warning);

static int __init quota_init(void)
{
	if (genl_register_family(&quota_genl_family) != 0)
		printk(KERN_ERR
		       "VFS: Failed to create quota netlink interface.\n");
	return 0;
};

module_init(quota_init);
#endif

