#include <linux/sched.h>
#include <linux/module.h>
#include <linux/ve.h>
#include <linux/ve_proto.h>
#include "sysfs.h"

static struct dentry * sysfs_dirlink_lookup(struct inode *dir, struct dentry *dentry,
				struct nameidata *nd)
{
	struct sysfs_dirent *parent_sd = dentry->d_parent->d_fsdata;
	return __sysfs_lookup_at(parent_sd->s_dir_link.target_sd, dentry, nd);
}

const struct inode_operations sysfs_dirlink_inode_operations = {
	.lookup		= sysfs_dirlink_lookup,
};

static int sysfs_dirlink_readdir(struct file * filp, void * dirent, filldir_t filldir)
{
	struct dentry *dentry = filp->f_path.dentry;
	struct sysfs_dirent * parent_sd = dentry->d_fsdata;
	return __sysfs_readdir_at(parent_sd->s_dir_link.target_sd, filp, dirent, filldir);
}

const struct file_operations sysfs_dirlink_operations = {
	.read		= generic_read_dir,
	.readdir	= sysfs_dirlink_readdir,
	.llseek		= generic_file_llseek,
};

struct sysfs_dirent *sysfs_create_dirlink(struct sysfs_dirent *parent_sd,
		struct kobject *target)
{
	struct sysfs_dirent *sd, *tgt;
	struct sysfs_addrm_cxt acxt;
	int rc;

	tgt = target->sd;
	if (tgt == NULL)
		return ERR_PTR(-EINVAL);
	if (!S_ISDIR(tgt->s_mode))
		return ERR_PTR(-ENOTDIR);

	sd = sysfs_new_dirent(tgt->s_name, tgt->s_mode, SYSFS_DIR_LINK);
	if (sd == NULL)
		return ERR_PTR(-ENOMEM);

	sd->owner_env = parent_sd->owner_env;
	sd->s_dir_link.target_sd = sysfs_get(tgt);

	sysfs_addrm_start(&acxt, parent_sd);
	rc = sysfs_add_one(&acxt, sd);
	sysfs_addrm_finish(&acxt);

	if (rc) {
		sysfs_put(tgt);
		sysfs_put(sd);
		sd = ERR_PTR(rc);
	}

	return sd;
}
EXPORT_SYMBOL(sysfs_create_dirlink);

void sysfs_remove_dirlink(struct sysfs_dirent *sd)
{
	struct sysfs_addrm_cxt acxt;

	sysfs_addrm_start(&acxt, sd->s_parent);
	sysfs_remove_one(&acxt, sd);
	sysfs_addrm_finish(&acxt);
}
EXPORT_SYMBOL(sysfs_remove_dirlink);
