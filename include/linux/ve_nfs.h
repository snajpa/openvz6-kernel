/*
 * linux/include/ve_nfs.h
 *
 * VE context for NFS
 *
 * Copyright (C) 2007 SWsoft
 */

extern int ve_nfs_sync(struct ve_struct *env, int wait);
extern void nfs_change_server_params(void *data, int timeo, int retrans);
extern int is_nfs_automount(struct vfsmount *mnt);

extern int nfs_enable_v4_in_ct;
