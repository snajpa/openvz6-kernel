/*
 *  include/linux/vzctl_quota.h
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#ifndef __LINUX_VZCTL_QUOTA_H__
#define __LINUX_VZCTL_QUOTA_H__

#include <linux/compat.h>

#ifndef __KERNEL__
#define __user
#endif

/*
 * Quota management ioctl
 */

struct vz_quota_stat;
struct vzctl_quotactl {
	int cmd;
	unsigned int quota_id;
	struct vz_quota_stat __user *qstat;
	char __user *ve_root;
};

struct vzctl_quotaugidctl {
	int cmd;		/* subcommand */
	unsigned int quota_id;	/* quota id where it applies to */
	unsigned int ugid_index;/* for reading statistic. index of first
				    uid/gid record to read */
	unsigned int ugid_size;	/* size of ugid_buf array */
	void *addr; 		/* user-level buffer */
};

#define VZDQCTLTYPE '+'
#define VZCTL_QUOTA_DEPR_CTL	_IOWR(VZDQCTLTYPE, 1,			\
					struct vzctl_quotactl)
#define VZCTL_QUOTA_NEW_CTL	_IOWR(VZDQCTLTYPE, 2,			\
					struct vzctl_quotactl)
#define VZCTL_QUOTA_UGID_CTL	_IOWR(VZDQCTLTYPE, 3,			\
					struct vzctl_quotaugidctl)

#ifdef __KERNEL__
#ifdef CONFIG_COMPAT
struct compat_vzctl_quotactl {
	int cmd;
	unsigned int quota_id;
	compat_uptr_t qstat;
	compat_uptr_t ve_root;
};

struct compat_vzctl_quotaugidctl {
	int cmd;		/* subcommand */
	unsigned int quota_id;	/* quota id where it applies to */
	unsigned int ugid_index;/* for reading statistic. index of first
				    uid/gid record to read */
	unsigned int ugid_size;	/* size of ugid_buf array */
	compat_uptr_t addr; 	/* user-level buffer */
};

#define VZCTL_COMPAT_QUOTA_CTL	_IOWR(VZDQCTLTYPE, 2,			\
					struct compat_vzctl_quotactl)
#define VZCTL_COMPAT_QUOTA_UGID_CTL _IOWR(VZDQCTLTYPE, 3,		\
					struct compat_vzctl_quotaugidctl)
#endif
#endif

#endif /* __LINUX_VZCTL_QUOTA_H__ */
