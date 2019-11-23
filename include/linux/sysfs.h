/*
 * sysfs.h - definitions for the device driver filesystem
 *
 * Copyright (c) 2001,2002 Patrick Mochel
 * Copyright (c) 2004 Silicon Graphics, Inc.
 * Copyright (c) 2007 SUSE Linux Products GmbH
 * Copyright (c) 2007 Tejun Heo <teheo@suse.de>
 *
 * Please see Documentation/filesystems/sysfs.txt for more information.
 */

#ifndef _SYSFS_H_
#define _SYSFS_H_

#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/lockdep.h>
#include <asm/atomic.h>

#ifdef CONFIG_SYSFS_DEPRECATED_DYN
extern unsigned _sysfs_deprecated;
#ifdef CONFIG_VE
#define sysfs_deprecated (ve_is_super(get_exec_env()) && _sysfs_deprecated)
#else
#define sysfs_deprecated (_sysfs_deprecated)
#endif
#else

/* static deprecation */

#ifdef CONFIG_SYSFS_DEPRECATED
#define sysfs_deprecated 1
#else
#define sysfs_deprecated 0
#endif

#endif

struct kobject;
struct module;
struct sysfs_open_dirent;

/* FIXME
 * The *owner field is no longer used.
 * x86 tree has been cleaned up. The owner
 * attribute is still left for other arches.
 */
struct attribute {
	const char		*name;
	struct module		*owner;
	mode_t			mode;
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lock_class_key	*key;
	struct lock_class_key	skey;
#endif
};

#ifdef CONFIG_DEBUG_LOCK_ALLOC
#define sysfs_attr_init(attr)				\
do {							\
	static struct lock_class_key __key;		\
							\
	(attr)->key = &__key;				\
} while(0)
#else
#define sysfs_attr_init(attr) do {} while(0)
#endif

struct attribute_group {
	const char		*name;
	mode_t			(*is_visible)(struct kobject *,
					      struct attribute *, int);
	struct attribute	**attrs;
};

#include <linux/fs.h>
#include <linux/rbtree.h>

/**
 * Use these macros to make defining attributes easier. See include/linux/device.h
 * for examples..
 */

#define __ATTR(_name,_mode,_show,_store) { \
	.attr = {.name = __stringify(_name), .mode = _mode },	\
	.show	= _show,					\
	.store	= _store,					\
}

#define __ATTR_RO(_name) { \
	.attr	= { .name = __stringify(_name), .mode = 0444 },	\
	.show	= _name##_show,					\
}

#define __ATTR_WO(_name) {						\
	.attr	= { .name = __stringify(_name), .mode = S_IWUSR },	\
	.store	= _name##_store,					\
}

#define __ATTR_RW(_name) __ATTR(_name, 0644, _name##_show, _name##_store)

#define __ATTR_NULL { .attr = { .name = NULL } }

#define attr_name(_attr) (_attr).attr.name

struct file;
struct vm_area_struct;

struct bin_attribute {
	struct attribute	attr;
	size_t			size;
	void			*private;
	ssize_t (*read)(struct file *, struct kobject *, struct bin_attribute *,
			char *, loff_t, size_t);
	ssize_t (*write)(struct file *,struct kobject *, struct bin_attribute *,
			 char *, loff_t, size_t);
	int (*mmap)(struct file *, struct kobject *, struct bin_attribute *attr,
		    struct vm_area_struct *vma);
};

#define sysfs_bin_attr_init(bin_attr) sysfs_attr_init(&bin_attr->attr)

struct sysfs_ops {
	ssize_t	(*show)(struct kobject *, struct attribute *,char *);
	ssize_t	(*store)(struct kobject *,struct attribute *,const char *, size_t);
};

struct sysfs_dirent;

/* type-specific structures for sysfs_dirent->s_* union members */
struct sysfs_elem_dir {
	struct kobject		*kobj;
#ifdef __GENKSYMS__
	struct sysfs_dirent	*children;
#endif

#ifndef __GENKSYMS__
	unsigned long           subdirs;

	struct rb_root          inode_tree;
	struct rb_root          name_tree;
#endif
};

struct sysfs_elem_symlink {
	struct sysfs_dirent	*target_sd;
};

struct sysfs_elem_attr {
	struct attribute	*attr;
	struct sysfs_open_dirent *open;
};

struct sysfs_elem_bin_attr {
	struct bin_attribute	*bin_attr;
	struct hlist_head	buffers;
};

struct sysfs_elem_dir_link {
	struct sysfs_dirent	*target_sd;
};

struct sysfs_inode_attrs {
	struct iattr	ia_iattr;
	void		*ia_secdata;
	u32		ia_secdata_len;
};

/*
 * sysfs_dirent - the building block of sysfs hierarchy.  Each and
 * every sysfs node is represented by single sysfs_dirent.
 *
 * As long as s_count reference is held, the sysfs_dirent itself is
 * accessible.  Dereferencing s_elem or any other outer entity
 * requires s_active reference.
 */
struct sysfs_dirent {
	atomic_t		s_count;
	atomic_t		s_active;
	struct sysfs_dirent	*s_parent;
#ifdef __GENKSYMS__
	struct sysfs_dirent	*s_sibling;
#endif
	const char		*s_name;

#ifndef __GENKSYMS__
	struct rb_node          inode_node;
	struct rb_node          name_node;

	union {
		struct completion       *completion;
		struct sysfs_dirent     *removed_list;
	} u;
#endif

	union {
		struct sysfs_elem_dir		s_dir;
		struct sysfs_elem_symlink	s_symlink;
		struct sysfs_elem_attr		s_attr;
		struct sysfs_elem_bin_attr	s_bin_attr;
		struct sysfs_elem_dir_link	s_dir_link;
	};

	unsigned int		s_flags;
	ino_t			s_ino;
	umode_t			s_mode;
	struct sysfs_inode_attrs *s_iattr;

	struct ve_struct	*owner_env;
};

#define SD_DEACTIVATED_BIAS		INT_MIN

#define SYSFS_TYPE_MASK			0x00ff
#define SYSFS_DIR			0x0001
#define SYSFS_KOBJ_ATTR			0x0002
#define SYSFS_KOBJ_BIN_ATTR		0x0004
#define SYSFS_KOBJ_LINK			0x0008
#define SYSFS_DIR_LINK			0x0010
#define SYSFS_COPY_NAME			(SYSFS_DIR | SYSFS_KOBJ_LINK | SYSFS_DIR_LINK)

#define SYSFS_FLAG_MASK			~SYSFS_TYPE_MASK
#define SYSFS_FLAG_REMOVED		0x0200

#ifdef CONFIG_SYSFS

int sysfs_schedule_callback(struct kobject *kobj, void (*func)(void *),
			    void *data, struct module *owner);

int __must_check sysfs_create_dir(struct kobject *kobj);
void sysfs_remove_dir(struct kobject *kobj);
int __must_check sysfs_rename_dir(struct kobject *kobj, const char *new_name);
int __must_check sysfs_move_dir(struct kobject *kobj,
				struct kobject *new_parent_kobj);

int __must_check sysfs_create_file(struct kobject *kobj,
				   const struct attribute *attr);
int __must_check sysfs_create_files(struct kobject *kobj,
				   const struct attribute **attr);
int __must_check sysfs_chmod_file(struct kobject *kobj, struct attribute *attr,
				  mode_t mode);
void sysfs_remove_file(struct kobject *kobj, const struct attribute *attr);
void sysfs_remove_files(struct kobject *kobj, const struct attribute **attr);

int __must_check sysfs_create_bin_file(struct kobject *kobj,
				       struct bin_attribute *attr);
void sysfs_remove_bin_file(struct kobject *kobj, struct bin_attribute *attr);

int __must_check sysfs_create_link(struct kobject *kobj, struct kobject *target,
				   const char *name);
int __must_check sysfs_create_link_nowarn(struct kobject *kobj,
					  struct kobject *target,
					  const char *name);
void sysfs_remove_link(struct kobject *kobj, const char *name);

int __must_check sysfs_create_group(struct kobject *kobj,
				    const struct attribute_group *grp);
int __must_check sysfs_create_groups(struct kobject *kobj,
				     const struct attribute_group **groups);
int sysfs_update_group(struct kobject *kobj,
		       const struct attribute_group *grp);
void sysfs_remove_group(struct kobject *kobj,
			const struct attribute_group *grp);
void sysfs_remove_groups(struct kobject *kobj,
			 const struct attribute_group **groups);
int sysfs_add_file_to_group(struct kobject *kobj,
			const struct attribute *attr, const char *group);
void sysfs_remove_file_from_group(struct kobject *kobj,
			const struct attribute *attr, const char *group);
int sysfs_merge_group(struct kobject *kobj,
		       const struct attribute_group *grp);
void sysfs_unmerge_group(struct kobject *kobj,
		       const struct attribute_group *grp);
extern struct sysfs_dirent *sysfs_create_dirlink(struct sysfs_dirent *parent_sd,
			struct kobject *target);
extern void sysfs_remove_dirlink(struct sysfs_dirent *sd);

void sysfs_notify(struct kobject *kobj, const char *dir, const char *attr);
void sysfs_notify_dirent(struct sysfs_dirent *sd);
struct sysfs_dirent *sysfs_get_dirent(struct sysfs_dirent *parent_sd,
				      const unsigned char *name);
struct sysfs_dirent *sysfs_get(struct sysfs_dirent *sd);
void sysfs_put(struct sysfs_dirent *sd);
void sysfs_printk_last_file(void);
int __must_check sysfs_init(void);

extern int init_ve_sysfs_root(struct ve_struct *ve);

extern struct file_system_type sysfs_fs_type;

#else /* CONFIG_SYSFS */

static inline int sysfs_schedule_callback(struct kobject *kobj,
		void (*func)(void *), void *data, struct module *owner)
{
	return -ENOSYS;
}

static inline int sysfs_create_dir(struct kobject *kobj)
{
	return 0;
}

static inline void sysfs_remove_dir(struct kobject *kobj)
{
}

static inline int sysfs_rename_dir(struct kobject *kobj, const char *new_name)
{
	return 0;
}

static inline int sysfs_move_dir(struct kobject *kobj,
				 struct kobject *new_parent_kobj)
{
	return 0;
}

static inline int sysfs_create_file(struct kobject *kobj,
				    const struct attribute *attr)
{
	return 0;
}

static inline int sysfs_create_files(struct kobject *kobj,
				    const struct attribute **attr)
{
	return 0;
}

static inline int sysfs_chmod_file(struct kobject *kobj,
				   struct attribute *attr, mode_t mode)
{
	return 0;
}

static inline void sysfs_remove_file(struct kobject *kobj,
				     const struct attribute *attr)
{
}

static inline void sysfs_remove_files(struct kobject *kobj,
				     const struct attribute **attr)
{
}

static inline int sysfs_create_bin_file(struct kobject *kobj,
					struct bin_attribute *attr)
{
	return 0;
}

static inline void sysfs_remove_bin_file(struct kobject *kobj,
					 struct bin_attribute *attr)
{
}

static inline int sysfs_create_link(struct kobject *kobj,
				    struct kobject *target, const char *name)
{
	return 0;
}

static inline int sysfs_create_link_nowarn(struct kobject *kobj,
					   struct kobject *target,
					   const char *name)
{
	return 0;
}

static inline void sysfs_remove_link(struct kobject *kobj, const char *name)
{
}

static inline int sysfs_create_group(struct kobject *kobj,
				     const struct attribute_group *grp)
{
	return 0;
}

static inline int sysfs_create_groups(struct kobject *kobj,
				      const struct attribute_group **groups)
{
	return 0;
}

static inline int sysfs_update_group(struct kobject *kobj,
				const struct attribute_group *grp)
{
	return 0;
}

static inline void sysfs_remove_group(struct kobject *kobj,
				      const struct attribute_group *grp)
{
}

static inline void sysfs_remove_groups(struct kobject *kobj,
				       const struct attribute_group **groups)
{
}

static inline int sysfs_add_file_to_group(struct kobject *kobj,
		const struct attribute *attr, const char *group)
{
	return 0;
}

static inline void sysfs_remove_file_from_group(struct kobject *kobj,
		const struct attribute *attr, const char *group)
{
}

static inline int sysfs_merge_group(struct kobject *kobj,
		       const struct attribute_group *grp)
{
	return 0;
}

static inline void sysfs_unmerge_group(struct kobject *kobj,
		       const struct attribute_group *grp)
{
}

static inline void sysfs_notify(struct kobject *kobj, const char *dir,
				const char *attr)
{
}
static inline void sysfs_notify_dirent(struct sysfs_dirent *sd)
{
}
static inline
struct sysfs_dirent *sysfs_get_dirent(struct sysfs_dirent *parent_sd,
				      const unsigned char *name)
{
	return NULL;
}
static inline struct sysfs_dirent *sysfs_get(struct sysfs_dirent *sd)
{
	return NULL;
}
static inline void sysfs_put(struct sysfs_dirent *sd)
{
}

static inline int __must_check sysfs_init(void)
{
	return 0;
}

static inline void sysfs_printk_last_file(void)
{
}

#endif /* CONFIG_SYSFS */

#endif /* _SYSFS_H_ */
