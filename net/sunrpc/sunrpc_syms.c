/*
 * linux/net/sunrpc/sunrpc_syms.c
 *
 * Symbols exported by the sunrpc module.
 *
 * Copyright (C) 1997 Olaf Kirch <okir@monad.swb.de>
 */

#include <linux/module.h>

#include <linux/types.h>
#include <linux/uio.h>
#include <linux/unistd.h>
#include <linux/init.h>

#include <linux/sunrpc/sched.h>
#include <linux/sunrpc/clnt.h>
#include <linux/sunrpc/svc.h>
#include <linux/sunrpc/svcsock.h>
#include <linux/sunrpc/auth.h>
#include <linux/workqueue.h>
#include <linux/sunrpc/rpc_pipe_fs.h>
#include <linux/sunrpc/xprtsock.h>

#include "ve.h"

extern struct cache_detail unix_gid_cache;

extern void ve_sunrpc_hook_register(void);
extern void ve_sunrpc_hook_unregister(void);
extern int ve_ip_map_init(void);
extern void ve_ip_map_exit(void);

static struct ve_rpc_data ve0_rpcd;

static int __init
init_sunrpc(void)
{
	int err;

	get_ve0()->ve_rpc_data = &ve0_rpcd;
	ve_rpc_data_init();

	err = register_rpc_pipefs();
	if (err)
		goto out;
	err = rpc_init_mempool();
	if (err)
		goto out2;
	err = rpcauth_init_module();
	if (err)
		goto out3;
#ifdef CONFIG_PROC_FS
	if (rpc_proc_init() == NULL)
		goto out4;
#endif
#ifdef RPC_DEBUG
	rpc_register_sysctl();
#endif
	cache_initialize();
	ve_ip_map_init();
	cache_register(&unix_gid_cache);
	svc_init_xprt_sock();	/* svc sock transport */
	init_socket_xprt();	/* clnt sock transport */
	ve_sunrpc_hook_register();
	return 0;
out4:
	rpcauth_remove_module();
out3:
	rpc_destroy_mempool();
out2:
	unregister_rpc_pipefs();
out:
	return err;
}

static void __exit
cleanup_sunrpc(void)
{
	ve_sunrpc_hook_unregister();
	rpcauth_remove_module();
	cleanup_socket_xprt();
	svc_cleanup_xprt_sock();
	unregister_rpc_pipefs();
	rpc_destroy_mempool();
	ve_ip_map_exit();
	cache_unregister(&unix_gid_cache);
#ifdef RPC_DEBUG
	rpc_unregister_sysctl();
#endif
#ifdef CONFIG_PROC_FS
	rpc_proc_exit();
#endif
	rcu_barrier(); /* Wait for completion of call_rcu()'s */
}
MODULE_LICENSE("GPL");
fs_initcall(init_sunrpc); /* Ensure we're initialised before nfs */
module_exit(cleanup_sunrpc);
