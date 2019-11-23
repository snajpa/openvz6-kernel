#ifndef _NAMESPACE_H_
#define _NAMESPACE_H_
#ifdef __KERNEL__

#include <linux/path.h>
#include <linux/seq_file.h>
#include <linux/wait.h>

struct mnt_namespace {
	atomic_t		count;
	struct vfsmount *	root;
	struct list_head	list;
	wait_queue_head_t poll;
	int event;
#ifndef __GENKSYMS__
	u64 seq; /* Sequence number to prevent loops */
	unsigned int		proc_inum;
#endif
};

struct proc_mounts {
	struct seq_file m; /* must be the first element */
	struct mnt_namespace *ns;
	struct path root;
	int event;
	struct list_head *iter;
	loff_t iter_pos;
	int iter_advanced;
	struct list_head reader;
};

extern unsigned int sysctl_ve_mount_nr;

extern void register_mounts_reader(struct proc_mounts *p);
extern void unregister_mounts_reader(struct proc_mounts *p);

struct fs_struct;

extern struct mnt_namespace *create_mnt_ns(struct vfsmount *mnt);
extern struct mnt_namespace *copy_mnt_ns(unsigned long, struct mnt_namespace *,
		struct fs_struct *);
extern void put_mnt_ns(struct mnt_namespace *ns);
static inline void get_mnt_ns(struct mnt_namespace *ns)
{
	atomic_inc(&ns->count);
}

extern const struct seq_operations mounts_op;
extern const struct seq_operations mountinfo_op;
extern const struct seq_operations mountstats_op;

#ifdef CONFIG_VE
extern void get_mnt_poll(struct mnt_namespace *ns,
		wait_queue_head_t **ppoll, int **pevent);
#else
static inline void get_mnt_poll(struct mnt_namespace *ns,
		wait_queue_head_t **ppoll, int **pevent)
{
	*ppoll = &ns->poll;
	*pevent = &ns->event;
}
#endif

extern struct rw_semaphore namespace_sem;

#endif
#endif
