/*
 * linux/include/ve_nfs.h
 *
 * VE context for SUNRPC
 *
 * Copyright (C) 2007 SWsoft
 */

#ifndef __VE_SUNRPC_H__
#define __VE_SUNRPC_H__

struct ve_rpc_data {
	struct proc_dir_entry	*_proc_net_rpc;
	struct cache_detail	*_ip_map_cache;
	struct file_system_type	*_rpc_pipefs_fstype;
	struct rpc_clnt		*_rpcb_local;
	struct rpc_clnt		*_rpcb_local4;
	spinlock_t		_rpcb_clnt_lock;
	int			_rpcb_users;
	struct workqueue_struct *_rpciod_workqueue;
	atomic_t		_users;
};

#ifdef CONFIG_VE
extern void rpcb_put_local(void);
extern void rpciod_stop(void);

static void destroy_rpc_data(struct work_struct *work)
{
	struct ve_struct *ve = container_of(work, struct ve_struct, rpc_destroy_work);

	BUG_ON(!ve_is_super(get_exec_env()));

	set_exec_env(ve);

	rpciod_stop();
	kfree(ve->ve_rpc_data);
	ve->ve_rpc_data = NULL;

	set_exec_env(&ve0);
}

static inline bool ve_rpc_data_put(struct ve_struct *ve)
{
	if (atomic_dec_and_test(&ve->ve_rpc_data->_users)) {
		/*
		 * RPC data usage counter have reached zero, and we
		 * have to stop rpciod queue and release virtualized
		 * data. But why we release this data in async queue?
		 * Becuase we can come here from rpciod workqueue:
		 * rpc_async_schedule -> __rpc_execute ->
		 * rpc_release_task -> rpc_final_put_task ->
		 * rpc_free_task -> rpc_release_calldata ->
		 * rpcb_map_release -> xprt_put -> xprt_destroy ->
		 * xs_destroy -> xprt_free -> ve_rpc_data_put ->
		 * rpciod_stop
		 * The only simple solution here is to schedule the same task
		 * in another workqueue.
		 */
		queue_work(ve0.khelper_wq, &ve->rpc_destroy_work);
		return true;
	}
	return false;
}

static inline void ve_rpc_data_init(void)
{
	atomic_set(&get_exec_env()->ve_rpc_data->_users, 1);
	spin_lock_init(&get_exec_env()->ve_rpc_data->_rpcb_clnt_lock);
	INIT_WORK(&get_exec_env()->rpc_destroy_work, destroy_rpc_data);
}

static inline void ve_rpc_data_get(void)
{
	atomic_inc(&get_exec_env()->ve_rpc_data->_users);
}

#define RPC_CTX_FIELD(arg)	(get_exec_env()->ve_rpc_data->_##arg)

#else /* CONFIG_VE */

#define RPC_CTX_FIELD(arg)	_##arg

static void ve_rpc_data_init(void)
{}
static void ve_rpc_data_get(void)
{}
static void ve_rpc_data_put(struct ve_struct *ve)
{ return true; }

#endif /* CONFIG_VE */


#define ip_map_cache		RPC_CTX_FIELD(ip_map_cache)
#define proc_net_rpc		RPC_CTX_FIELD(proc_net_rpc)
#define rpciod_workqueue	RPC_CTX_FIELD(rpciod_workqueue)
#define rpc_pipefs_fstype	RPC_CTX_FIELD(rpc_pipefs_fstype)
#define rpcb_local_clnt		RPC_CTX_FIELD(rpcb_local)
#define rpcb_local_clnt4	RPC_CTX_FIELD(rpcb_local4)
#define rpcb_clnt_lock		RPC_CTX_FIELD(rpcb_clnt_lock)
#define rpcb_users		RPC_CTX_FIELD(rpcb_users)

#endif /* __VE_SUNRPC_H__ */
