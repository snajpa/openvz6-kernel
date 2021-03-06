/*
 *
 * Definitions for mount interface. This describes the in the kernel build 
 * linkedlist with mounted filesystems.
 *
 * Author:  Marco van Wieringen <mvw@planets.elm.net>
 *
 */
#ifndef _LINUX_MOUNT_H
#define _LINUX_MOUNT_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/nodemask.h>
#include <linux/spinlock.h>
#include <asm/atomic.h>

struct super_block;
struct vfsmount;
struct dentry;
struct mnt_namespace;

#define MNT_NOSUID	0x01
#define MNT_NODEV	0x02
#define MNT_NOEXEC	0x04
#define MNT_NOATIME	0x08
#define MNT_NODIRATIME	0x10
#define MNT_RELATIME	0x20
#define MNT_READONLY	0x40	/* does the user want this to be r/o? */
#define MNT_STRICTATIME 0x80

#define MNT_SHRINKABLE	0x100
#define MNT_WRITE_HOLD	0x200

#define MNT_SHARED	0x1000	/* if the vfsmount is a shared mount */
#define MNT_UNBINDABLE	0x2000	/* if the vfsmount is a unbindable mount */
#define MNT_PNODE_MASK	0x3000	/* propagation flag mask */

#define MNT_CPT		0x1000000

#define MNT_BEHAVIOR_FLAGS	(MNT_NOSUID | MNT_NODEV | MNT_NOEXEC |		\
				MNT_NOATIME | MNT_NODIRATIME | MNT_RELATIME |	\
				MNT_READONLY | MNT_STRICTATIME | MNT_SHRINKABLE)

/*
 * Remounts, which change any flags except for following ones,
 * are forbidden inside containers.
 */
#define MNT_VE_RMT_MASK	MNT_READONLY

struct vfsmount {
	struct list_head mnt_hash;
	struct vfsmount *mnt_parent;	/* fs we are mounted on */
	struct dentry *mnt_mountpoint;	/* dentry of mountpoint */
	struct dentry *mnt_root;	/* root of the mounted tree */
	struct super_block *mnt_sb;	/* pointer to superblock */
	struct list_head mnt_mounts;	/* list of children, anchored here */
	struct list_head mnt_child;	/* and going through their mnt_child */
	int mnt_flags;
	__u32 rh_reserved;		/* for use with fanotify */
	struct hlist_head rh_reserved2;	/* for use with fanotify */
	const char *mnt_devname;	/* Name of device e.g. /dev/dsk/hda1 */
	struct list_head mnt_list;
	struct list_head mnt_expire;	/* link in fs-specific expiry list */
	struct list_head mnt_share;	/* circular list of shared mounts */
	struct list_head mnt_slave_list;/* list of slave mounts */
	struct list_head mnt_slave;	/* slave list entry */
	struct vfsmount *mnt_master;	/* slave is on master->mnt_slave_list */
	struct mnt_namespace *mnt_ns;	/* containing namespace */
	int mnt_id;			/* mount identifier */
	int mnt_group_id;		/* peer group identifier */
	/*
	 * We put mnt_count & mnt_expiry_mark at the end of struct vfsmount
	 * to let these frequently modified fields in a separate cache line
	 * (so that reads of mnt_flags wont ping-pong on SMP machines)
	 */
	atomic_t mnt_count;
	int mnt_expiry_mark;		/* true if marked for expiry */
	int mnt_pinned;
	int mnt_ghosts;
#ifdef CONFIG_SMP
	int *mnt_writers;
#else
	int mnt_writers;
#endif
	unsigned owner;
};

static inline int *get_mnt_writers_ptr(struct vfsmount *mnt)
{
#ifdef CONFIG_SMP
	return mnt->mnt_writers;
#else
	return &mnt->mnt_writers;
#endif
}

static inline struct vfsmount *mntget(struct vfsmount *mnt)
{
	if (mnt)
		atomic_inc(&mnt->mnt_count);
	return mnt;
}

struct file; /* forward dec */

extern struct vfsmount *next_mnt(struct vfsmount *p, struct vfsmount *root);
extern int mnt_want_write(struct vfsmount *mnt);
extern int mnt_want_write_file(struct file *file);
extern int mnt_clone_write(struct vfsmount *mnt);
extern void mnt_drop_write(struct vfsmount *mnt);
extern void mnt_drop_write_file(struct file *file);
extern void mntput_no_expire(struct vfsmount *mnt);
extern void mnt_pin(struct vfsmount *mnt);
extern void mnt_unpin(struct vfsmount *mnt);
extern int __mnt_is_readonly(struct vfsmount *mnt);

static inline void mntput(struct vfsmount *mnt)
{
	if (mnt) {
		mnt->mnt_expiry_mark = 0;
		mntput_no_expire(mnt);
	}
}

extern struct vfsmount *do_kern_mount(const char *fstype, int flags,
				      const char *name, void *data);

struct file_system_type;
extern struct vfsmount *vfs_kern_mount(struct file_system_type *type,
				      int flags, const char *name,
				      void *data);
extern struct vfsmount *vfs_bind_mount_private(struct vfsmount *, struct dentry *);
extern struct vfsmount *vfs_bind_mount(struct vfsmount *, struct dentry *);

struct nameidata;

struct path;
extern int do_add_mount(struct vfsmount *newmnt, struct path *path,
			int mnt_flags, struct list_head *fslist);

extern void mnt_set_expiry(struct vfsmount *mnt, struct list_head *expiry_list);
extern void mark_mounts_for_expiry(struct list_head *mounts);
extern void replace_mount(struct vfsmount *src_mnt, struct vfsmount *dst_mnt);

extern spinlock_t vfsmount_lock;
extern dev_t name_to_dev_t(char *name);

#endif /* _LINUX_MOUNT_H */
