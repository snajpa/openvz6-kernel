/*
 * fs/nfsd/ve.h
 *
 * VE context for NFSd
 *
 */

#ifndef __VE_NFSD_H__
#define __VE_NFSD_H__

#define VE_RAPARM_SIZE	2048

struct ve_nfsd_data {
	struct file_system_type *nfsd_fs;
	struct cache_detail *_svc_export_cache;
	struct cache_detail *_svc_expkey_cache;
	struct svc_serv *_nfsd_serv;
	struct nfsd_stats _nfsdstats;
	struct svc_stat *svc_stat;
	char _raparm_hash[VE_RAPARM_SIZE];
	struct completion _nfsd_exited;
	bool _nfsd_up;
	atomic_t _nfsd_ntf_refcnt;
	wait_queue_head_t _nfsd_ntf_wq;
};

#ifdef CONFIG_VE

#include <linux/ve.h>

#define NFSD_CTX_FIELD(arg)	(get_exec_env()->nfsd_data->_##arg)
#define NFSD_CTX_TEST		(get_exec_env()->nfsd_data)

#else

#define NFSD_CTX_FIELD(arg)	_##arg
#define NFSD_CTX_TEST		true

#endif

#define svc_export_cache	NFSD_CTX_FIELD(svc_export_cache)
#define svc_expkey_cache	NFSD_CTX_FIELD(svc_expkey_cache)

#define nfsd_ntf_refcnt		NFSD_CTX_FIELD(nfsd_ntf_refcnt)
#define nfsd_ntf_wq		NFSD_CTX_FIELD(nfsd_ntf_wq)

#define nfsd_serv		NFSD_CTX_FIELD(nfsd_serv)
#define nfsd_up			NFSD_CTX_FIELD(nfsd_up)
#define nfsd_exited		NFSD_CTX_FIELD(nfsd_exited)
#define nfsdstats		NFSD_CTX_FIELD(nfsdstats)
struct raparm_hbucket;
#define raparm_hash		((struct raparm_hbucket *)NFSD_CTX_FIELD(raparm_hash))


#endif /* __VE_NFSD_H__ */
