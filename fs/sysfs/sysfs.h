/*
 * fs/sysfs/sysfs.h - sysfs internal header file
 *
 * Copyright (c) 2001-3 Patrick Mochel
 * Copyright (c) 2007 SUSE Linux Products GmbH
 * Copyright (c) 2007 Tejun Heo <teheo@suse.de>
 *
 * This file is released under the GPLv2.
 */

#include <linux/fs.h>
#include <linux/rbtree.h>

#ifndef CONFIG_VE
extern struct vfsmount *sysfs_mount;
extern struct super_block *sysfs_sb;
#define sd_sysfs_sb(sd) sysfs_sb
#define ve_sysfs_alowed()	1
#else
#include <linux/sched.h>
#include <linux/ve.h>
#define sysfs_mount		(get_exec_env()->sysfs_mnt)
#define sysfs_sb		(get_exec_env()->_sysfs_sb)
#define sd_sysfs_sb(sd)		((sd)->owner_env->_sysfs_sb)
#define ve_sysfs_alowed()	(sysfs_sb != NULL)
#endif

static inline unsigned int sysfs_type(struct sysfs_dirent *sd)
{
	return sd->s_flags & SYSFS_TYPE_MASK;
}

/*
 * Context structure to be used while adding/removing nodes.
 */
struct sysfs_addrm_cxt {
	struct sysfs_dirent	*parent_sd;
	struct inode		*parent_inode;
	struct sysfs_dirent	*removed;
	int			cnt;
};

/*
 * mount.c
 */
#ifdef CONFIG_VE
#define ve_sysfs_root	(get_exec_env()->_sysfs_root)
#else
extern struct sysfs_dirent sysfs_root;
#define ve_sysfs_root	(&sysfs_root)
#endif
extern struct kmem_cache *sysfs_dir_cachep;

/*
 * dir.c
 */
extern struct mutex sysfs_mutex;
extern struct mutex sysfs_rename_mutex;
extern spinlock_t sysfs_assoc_lock;

extern const struct file_operations sysfs_dir_operations;
extern const struct inode_operations sysfs_dir_inode_operations;

extern const struct file_operations sysfs_dirlink_operations;
extern const struct inode_operations sysfs_dirlink_inode_operations;

struct dentry *sysfs_get_dentry(struct sysfs_dirent *sd);
struct sysfs_dirent *sysfs_get_active_two(struct sysfs_dirent *sd);
void sysfs_put_active_two(struct sysfs_dirent *sd);
void sysfs_addrm_start(struct sysfs_addrm_cxt *acxt,
		       struct sysfs_dirent *parent_sd);
int __sysfs_add_one(struct sysfs_addrm_cxt *acxt, struct sysfs_dirent *sd);
int sysfs_add_one(struct sysfs_addrm_cxt *acxt, struct sysfs_dirent *sd);
void sysfs_remove_one(struct sysfs_addrm_cxt *acxt, struct sysfs_dirent *sd);
void sysfs_addrm_finish(struct sysfs_addrm_cxt *acxt);

struct sysfs_dirent *sysfs_find_dirent(struct sysfs_dirent *parent_sd,
				       const unsigned char *name);
struct sysfs_dirent *sysfs_get_dirent(struct sysfs_dirent *parent_sd,
				      const unsigned char *name);
struct sysfs_dirent *sysfs_new_dirent(const char *name, umode_t mode, int type);

void release_sysfs_dirent(struct sysfs_dirent *sd);

int sysfs_create_subdir(struct kobject *kobj, const char *name,
			struct sysfs_dirent **p_sd);
void sysfs_remove_subdir(struct sysfs_dirent *sd);

static inline struct sysfs_dirent *__sysfs_get(struct sysfs_dirent *sd)
{
	if (sd) {
		WARN_ON(!atomic_read(&sd->s_count));
		atomic_inc(&sd->s_count);
	}
	return sd;
}
#define sysfs_get(sd) __sysfs_get(sd)

static inline void __sysfs_put(struct sysfs_dirent *sd)
{
	if (sd && atomic_dec_and_test(&sd->s_count))
		release_sysfs_dirent(sd);
}
#define sysfs_put(sd) __sysfs_put(sd)

struct dentry * __sysfs_lookup_at(struct sysfs_dirent *parent_sd, struct dentry *dentry,
		struct nameidata *nd);
int __sysfs_readdir_at(struct sysfs_dirent *parent_sd, struct file * filp,
		void * dirent, filldir_t filldir);

/*
 * inode.c
 */
struct inode *sysfs_get_inode(struct sysfs_dirent *sd);
void sysfs_delete_inode(struct inode *inode);
int sysfs_setattr(struct dentry *dentry, struct iattr *iattr);
int sysfs_setxattr(struct dentry *dentry, const char *name, const void *value,
		size_t size, int flags);
int sysfs_getattr(struct vfsmount *mnt, struct dentry *dentry,
		struct kstat *stat);
int sysfs_hash_and_remove(struct sysfs_dirent *dir_sd, const char *name);
int sysfs_inode_init(void);

/*
 * file.c
 */
extern const struct file_operations sysfs_file_operations;

int sysfs_add_file(struct sysfs_dirent *dir_sd,
		   const struct attribute *attr, int type);

int sysfs_add_file_mode(struct sysfs_dirent *dir_sd,
			const struct attribute *attr, int type, mode_t amode);
/*
 * bin.c
 */
extern const struct file_operations bin_fops;
void unmap_bin_file(struct sysfs_dirent *attr_sd);

/*
 * symlink.c
 */
extern const struct inode_operations sysfs_symlink_inode_operations;
