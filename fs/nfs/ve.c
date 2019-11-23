#include <linux/module.h>
#include <linux/list.h>
#include <linux/ve.h>
#include <linux/ve_proto.h>
#include <linux/vzcalluser.h>
#include <linux/nfs_fs.h>
#include <linux/nfs_mount.h>

#include "internal.h"

static int ve_nfs_init(void *data)
{
	int err;
	struct ve_nfs_data *nfs_data;
	struct ve_struct *ve = (struct ve_struct *) data;

	if (!(ve->features & VE_FEATURE_NFS))
		return 0;

	nfs_data = kzalloc(sizeof(struct ve_nfs_data), GFP_KERNEL);
	if (nfs_data == NULL)
		return -ENOMEM;
	ve_nfs_data_init(nfs_data);
	err = nfsiod_start();
	if (err)
		goto err_nfsiod;
	__module_get(THIS_MODULE);
	return 0;

err_nfsiod:
	kfree(ve->nfs_data);
	return err;
}

void ve_nfs_data_put(struct ve_struct *ve)
{
	struct ve_struct *curr_ve;

	curr_ve = set_exec_env(ve);
	if (atomic_dec_and_test(&ve->nfs_data->_users)) {
		nfsiod_stop();
		kfree(ve->nfs_data);
		ve->nfs_data = NULL;
		module_put(THIS_MODULE);
	}
	(void)set_exec_env(curr_ve);
}

static void ve_nfs_fini(void *data)
{
	struct ve_struct *ve = data;

	if (ve->nfs_data == NULL)
		return;

	umount_ve_fs_type(&nfs_fs_type, ve->veid);
	umount_ve_fs_type(&nfs4_fs_type, ve->veid);

	ve_nfs_data_put(ve);
	if (ve->nfs_data)
		printk(KERN_WARNING "CT%d: NFS mounts used outside CT. Release "
				"all external references to CT's NFS mounts to "
				"continue shutdown.\n", ve->veid);
}

inline int is_nfs_automount(struct vfsmount *mnt)
{
	struct vfsmount *submnt;

	spin_lock(&vfsmount_lock);
	list_for_each_entry(submnt, &nfs_automount_list, mnt_expire) {
		if (mnt == submnt) {
			spin_unlock(&vfsmount_lock);
			return 1;
		}
	}
	spin_unlock(&vfsmount_lock);

	return 0;
}
EXPORT_SYMBOL(is_nfs_automount);

static int ve_nfs_sync_fs(struct file_system_type *fs, struct ve_struct *env, int wait)
{
	struct super_block *sb;
	int ret = 0;

	spin_lock(&sb_lock);
rescan:
	list_for_each_entry(sb, &fs->fs_supers, s_instances) {
		sb->s_count++;
		spin_unlock(&sb_lock);

		down_read(&sb->s_umount);
		if (sb->s_root && !(sb->s_flags & MS_RDONLY)) {
			struct rpc_clnt *clnt = NFS_SB(sb)->client;
			struct ve_struct *owner_env = clnt->cl_xprt->owner_env;
			if (ve_accessible_strict(owner_env, env)) {
				ret = __sync_filesystem(sb, NULL, wait);
				if (ret < 0) {
					up_read(&sb->s_umount);
					put_super(sb);
					return ret;
				}
			}
		}
		up_read(&sb->s_umount);

		spin_lock(&sb_lock);

		/* This logic is taken from sync_inodes()  */
		if (__put_super_and_need_restart(sb))
			goto rescan;
	}

	spin_unlock(&sb_lock);
	return ret;
}

int ve_nfs_sync(struct ve_struct *env, int wait)
{
	int ret;

	ret = ve_nfs_sync_fs(&nfs_fs_type, env, wait);
	if (!ret)
		ret = ve_nfs_sync_fs(&nfs4_fs_type, env, wait);
	return ret;
}
EXPORT_SYMBOL(ve_nfs_sync);

static void ve_nfs_umount_begin(struct ve_struct *ve, struct file_system_type *nfs)
{
	struct super_block *sb;

	spin_lock(&sb_lock);
	list_for_each_entry(sb, &nfs->fs_supers, s_instances)
		if (ve_accessible_strict(NFS_SB(sb)->nfs_client->owner_env, ve))
			sb->s_op->umount_begin(sb);
	spin_unlock(&sb_lock);
}

static void ve_nfs_stop(void *data)
{
	struct ve_struct *ve = data;

	if (ve->nfs_data == NULL)
		return;

	ve_nfs_umount_begin(ve, &nfs_fs_type);
	ve_nfs_umount_begin(ve, &nfs4_fs_type);
}

static struct ve_hook nfs_ss_hook = {
	.init	  = ve_nfs_init,
	.fini	  = ve_nfs_fini,
	.owner	  = THIS_MODULE,
	.priority = HOOK_PRIO_NET_POST,
};

static struct ve_hook nfs_hook = {
	.fini	  = ve_nfs_stop,
	.owner	  = THIS_MODULE,
	.priority = HOOK_PRIO_NET_POST,
};

void ve_register_nfs_hooks(void)
{
	ve_hook_register(VE_SS_CHAIN, &nfs_ss_hook);
	ve_hook_register(VE_INIT_EXIT_CHAIN, &nfs_hook);
}

void ve_unregister_nfs_hooks(void)
{
	ve_hook_unregister(&nfs_hook);
	ve_hook_unregister(&nfs_ss_hook);
}

static void nfs_client_update_params(struct nfs_client *nfs_client,
				     const struct rpc_timeout *timeparams)
{
	struct rpc_clnt *clnt = nfs_client->cl_rpcclient;

	spin_lock_bh(&clnt->cl_xprt->transport_lock);
	clnt->cl_timeout_default = *timeparams;
	spin_unlock_bh(&clnt->cl_xprt->transport_lock);
}

static void nfs_update_one_server(struct nfs_server *nfs_server,
				  const struct rpc_timeout *timeparams)
{
	struct rpc_clnt *clnt = nfs_server->client;

	nfs_server->flags &= ~NFS_MOUNT_RESTORE;
	if (!(nfs_server->flags & NFS_MOUNT_SOFT))
		clnt->cl_softrtry = 0;

	spin_lock_bh(&clnt->cl_xprt->transport_lock);
	clnt->cl_timeout_default = *timeparams;
	rpc_init_rtt(&clnt->cl_rtt_default, timeparams->to_initval);
	spin_unlock_bh(&clnt->cl_xprt->transport_lock);
}

void nfs_change_server_params(void *data, int timeo, int retrans)
{
	struct nfs_server *nfs_server = data;
	struct nfs_client *nfs_client = nfs_server->nfs_client;
	int proto = (nfs_server->flags & NFS_MOUNT_TCP) ? IPPROTO_TCP 
							: IPPROTO_UDP;
	struct rpc_timeout timeparams;

	nfs_init_timeout_values(&timeparams, proto, timeo, retrans);

	spin_lock(&nfs_client_lock);
	nfs_client_update_params(nfs_server->nfs_client, &timeparams);
	list_for_each_entry(nfs_server, &nfs_client->cl_superblocks, client_link) {
		nfs_update_one_server(nfs_server, &timeparams);
	}
	spin_unlock(&nfs_client_lock);
}
EXPORT_SYMBOL(nfs_change_server_params);

void ve0_nfs_data_init(void)
{
	static struct ve_nfs_data ve0_nfs_data;

	ve_nfs_data_init(&ve0_nfs_data);
}
