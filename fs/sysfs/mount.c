/*
 * fs/sysfs/symlink.c - operations for initializing and mounting sysfs
 *
 * Copyright (c) 2001-3 Patrick Mochel
 * Copyright (c) 2007 SUSE Linux Products GmbH
 * Copyright (c) 2007 Tejun Heo <teheo@suse.de>
 *
 * This file is released under the GPLv2.
 *
 * Please see Documentation/filesystems/sysfs.txt for more information.
 */

#define DEBUG 

#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/pagemap.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/magic.h>

#include "sysfs.h"


#ifndef CONFIG_VE
struct vfsmount *sysfs_mount;
struct super_block * sysfs_sb = NULL;
#endif

struct kmem_cache *sysfs_dir_cachep;

#ifdef CONFIG_SYSFS_DEPRECATED_DYN
unsigned _sysfs_deprecated __read_mostly;
EXPORT_SYMBOL(_sysfs_deprecated);

static int __init sysfs_init_deprecated(char *str)
{
	_sysfs_deprecated = simple_strtoul(str, NULL, 10);
	return 1;
}
early_param("sysfs.deprecated", sysfs_init_deprecated);
#endif

static const struct super_operations sysfs_ops = {
	.statfs		= simple_statfs,
	.drop_inode	= generic_delete_inode,
	.delete_inode	= sysfs_delete_inode,
};

struct sysfs_dirent sysfs_root = {
	.s_name		= "",
	.s_count	= ATOMIC_INIT(1),
	.s_flags	= SYSFS_DIR,
	.s_mode		= S_IFDIR | S_IRWXU | S_IRUGO | S_IXUGO,
	.s_ino		= 1,
	.owner_env	= &ve0,
};

static void init_ve0_sysfs_root(void)
{
#ifdef CONFIG_VE
	get_ve0()->_sysfs_root = &sysfs_root;
#endif
}

static int sysfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct inode *inode;
	struct dentry *root;

	sb->s_blocksize = PAGE_CACHE_SIZE;
	sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
	sb->s_magic = SYSFS_MAGIC;
	sb->s_op = &sysfs_ops;
	sb->s_time_gran = 1;
	sysfs_sb = sb;

	/* get root inode, initialize and unlock it */
	mutex_lock(&sysfs_mutex);
	inode = sysfs_get_inode(ve_sysfs_root);
	mutex_unlock(&sysfs_mutex);
	if (!inode) {
		pr_debug("sysfs: could not get root inode\n");
		return -ENOMEM;
	}

	/* instantiate and link root dentry */
	root = d_alloc_root(inode);
	if (!root) {
		pr_debug("%s: could not get root dentry!\n",__func__);
		iput(inode);
		return -ENOMEM;
	}
	root->d_fsdata = ve_sysfs_root;
	sb->s_root = root;
	return 0;
}

static int sysfs_get_sb(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data, struct vfsmount *mnt)
{
	return get_sb_single(fs_type, flags, data, sysfs_fill_super, mnt);
}

struct file_system_type sysfs_fs_type = {
	.name		= "sysfs",
	.get_sb		= sysfs_get_sb,
	.kill_sb	= kill_anon_super,
};

EXPORT_SYMBOL(sysfs_fs_type);

int __init sysfs_init(void)
{
	int err = -ENOMEM;

	init_ve0_sysfs_root();
	sysfs_dir_cachep = kmem_cache_create("sysfs_dir_cache",
					      sizeof(struct sysfs_dirent),
					      0, 0, NULL);
	if (!sysfs_dir_cachep)
		goto out;

	err = sysfs_inode_init();
	if (err)
		goto out_err;

	err = register_filesystem(&sysfs_fs_type);
	if (!err) {
		sysfs_mount = kern_mount(&sysfs_fs_type);
		if (IS_ERR(sysfs_mount)) {
			printk(KERN_ERR "sysfs: could not mount!\n");
			err = PTR_ERR(sysfs_mount);
			sysfs_mount = NULL;
			unregister_filesystem(&sysfs_fs_type);
			goto out_err;
		}
	} else
		goto out_err;
out:
	return err;
out_err:
	kmem_cache_destroy(sysfs_dir_cachep);
	sysfs_dir_cachep = NULL;
	goto out;
}

#undef sysfs_get
struct sysfs_dirent *sysfs_get(struct sysfs_dirent *sd)
{
	return __sysfs_get(sd);
}
EXPORT_SYMBOL_GPL(sysfs_get);

#undef sysfs_put
void sysfs_put(struct sysfs_dirent *sd)
{
	__sysfs_put(sd);
}
EXPORT_SYMBOL_GPL(sysfs_put);
