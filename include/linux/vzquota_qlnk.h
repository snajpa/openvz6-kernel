/*
 *  include/linux/vzquota_qlnk.h
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#ifndef _VZDQUOTA_QLNK_H
#define _VZDQUOTA_QLNK_H

struct vz_quota_master;
struct vz_quota_ugid;

/* inode link, used to track inodes using quota via dq_ilink_list */
struct vz_quota_ilink {
	struct vz_quota_master *qmblk;
	struct vz_quota_ugid *qugid[MAXQUOTAS];
	struct list_head list;
	unsigned char origin[2];
};

#endif /* _VZDQUOTA_QLNK_H */
