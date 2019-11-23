/*
 * fs/nfs/ve.h
 *
 * VE context for NFS
 *
 * Copyright (C) 2007 SWsoft
 */

#ifndef __VE_NFS_H__
#define __VE_NFS_H__

#ifdef CONFIG_NFS_V4
#include <linux/nfs4.h>

#define nfs_callback_tcpport	NFS_CTX_FIELD(nfs_callback_tcpport)
#define nfs_callback_tcpport6	NFS_CTX_FIELD(nfs_callback_tcpport6)

struct nfs_callback_data {
	unsigned int users;
	struct svc_serv *serv;
	struct svc_rqst *rqst;
	struct task_struct *task;
};
#endif

struct ve_nfs_data {
	struct workqueue_struct *_nfsiod_workqueue;
	atomic_t		_users;
#ifdef CONFIG_NFS_V4
	struct nfs_callback_data _nfs_callback_info[NFS4_MAX_MINOR_VERSION + 1];
	struct mutex		_nfs_callback_mutex;

	unsigned short		_nfs_callback_tcpport;
	unsigned short		_nfs_callback_tcpport6;
#endif
};

#ifdef CONFIG_VE

#include <linux/ve.h>

#define NFS_CTX_FIELD(arg)	(get_exec_env()->nfs_data->_##arg)

static inline void ve_nfs_data_init(struct ve_nfs_data *data)
{
	atomic_set(&data->_users, 1);
#ifdef CONFIG_NFS_V4
	mutex_init(&data->_nfs_callback_mutex);
#endif
	get_exec_env()->nfs_data = data;
}

static inline void ve_nfs_data_get(void)
{
	atomic_inc(&get_exec_env()->nfs_data->_users);
}

extern inline void ve_nfs_data_put(struct ve_struct *ve);
extern void ve0_nfs_data_init(void);
extern void ve_register_nfs_hooks(void);
extern void ve_unregister_nfs_hooks(void);

static inline struct workqueue_struct *inode_nfsiod_wq(struct inode *inode)
{
	return NFS_SERVER(inode)->nfs_client->owner_env->nfs_data->_nfsiod_workqueue;
}

#else /* CONFIG_VE */

#define NFS_CTX_FIELD(arg)	_##arg

static void ve_nfs_data_init(void)
{}
static void ve_nfs_data_get(void)
{}
static void ve_nfs_data_put(struct ve_struct *ve)
{}
static void ve0_nfs_data_init(struct ve_struct *ve)
{}
static void ve_register_nfs_hooks(struct ve_struct *ve)
{}
static void ve_unregister_nfs_hooks(struct ve_struct *ve)
{}

extern struct workqueue_struct *nfsiod_workqueue;
#define inode_nfsiod_wq(inode)	nfsiod_workqueue

#endif /* CONFIG_VE */

#define nfsiod_workqueue	NFS_CTX_FIELD(nfsiod_workqueue)
#define nfs_callback_info	NFS_CTX_FIELD(nfs_callback_info)
#define nfs_callback_mutex	NFS_CTX_FIELD(nfs_callback_mutex)

#endif
