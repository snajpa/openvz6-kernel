/*
 *  include/linux/ve.h
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#ifndef _LINUX_VE_H
#define _LINUX_VE_H

#include <linux/types.h>
#include <linux/capability.h>
#include <linux/sysctl.h>
#include <linux/net.h>
#include <linux/vzstat.h>
#include <linux/kobject.h>
#include <linux/pid.h>
#include <linux/socket.h>
#include <linux/idr.h>
#include <linux/spinlock.h>
#include <net/inet_frag.h>

#ifdef VZMON_DEBUG
#  define VZTRACE(fmt,args...) \
	printk(KERN_DEBUG fmt, ##args)
#else
#  define VZTRACE(fmt,args...)
#endif /* VZMON_DEBUG */

struct tty_driver;
struct task_struct;
struct new_utsname;
struct file_system_type;
struct icmp_mib;
struct ip_mib;
struct tcp_mib;
struct udp_mib;
struct linux_mib;
struct fib_info;
struct fib_rule;
struct veip_struct;
struct ve_monitor;
struct nsproxy;

struct ve_ipt_recent;
struct ve_xt_hashlimit;
struct svc_rqst;

struct cgroup;
struct css_set;

struct ve_struct {
	struct list_head	ve_list;
	wait_queue_head_t	ve_list_wait;

	envid_t			veid;
	/*
	 * this one is NOT rcu-protected
	 */
	struct list_head	vetask_lh;
	/* capability bounding set */
	kernel_cap_t		ve_cap_bset;
	unsigned int		pcounter;
	/* ref counter to ve from ipc */
	atomic_t		counter;
	unsigned int		class_id;
	struct rw_semaphore	op_sem;
	int			is_running;
	int			is_locked;
	atomic_t		suspend;
	unsigned long		flags;
	/* see vzcalluser.h for VE_FEATURE_XXX definitions */
	__u64			features;

/* VE's root */
	struct path		root_path;

	struct file_system_type *proc_fstype;
	struct vfsmount		*proc_mnt;
	struct proc_dir_entry	*proc_root;

/* BSD pty's */
#ifdef CONFIG_LEGACY_PTYS
	struct tty_driver       *pty_driver;
	struct tty_driver       *pty_slave_driver;
#endif
#ifdef CONFIG_UNIX98_PTYS
	struct vfsmount		*devpts_mnt;
#endif

#define	MAX_NR_VTTY		12
	struct tty_struct	*vtty[MAX_NR_VTTY];

	struct file_system_type *shmem_fstype;
	struct vfsmount		*shmem_mnt;
#ifdef CONFIG_DEVTMPFS
	struct file_system_type	*devtmpfs_fstype;
	struct vfsmount		*devtmpfs_mnt;
#endif
#ifdef CONFIG_SYSFS
	struct file_system_type *sysfs_fstype;
	struct vfsmount		*sysfs_mnt;
	struct super_block	*_sysfs_sb;
	struct sysfs_dirent	*_sysfs_root;
	struct kobject		*fs_kobj;
	struct kobject		*cgroup_kobj;
#if defined(CONFIG_HOTPLUG)
	struct kobject		*kernel_kobj;
#endif
	struct kobject		*smod_kobj;
	struct kobject		*smct_kobj;
#endif
	struct kobject		*_virtual_dir;
	struct kobject		*_system_dir;
	struct kset		*cpu_kset;
	struct kset		*class_kset;
	struct kset		*devices_kset;
	struct kobject		*dev_kobj;
	struct kobject		*dev_char_kobj;
	struct kobject		*dev_block_kobj;
	struct kobject		*block_kobj;
	struct class		*tty_class;
	struct class		*mem_class;
	struct list_head	devices;

#ifdef CONFIG_NET
	struct class		*net_class;
#ifdef CONFIG_INET
 	unsigned long		rt_flush_required;
#endif
#endif
#if defined(CONFIG_VE_NETDEV) || defined (CONFIG_VE_NETDEV_MODULE)
	struct veip_struct	*veip;
	struct net_device	*_venet_dev;
#endif

/* per VE CPU stats*/
	struct timespec		start_timespec;		/* monotonic time */
	struct timespec		real_start_timespec;	/* boot based time */
	u64			start_jiffies;	/* Deprecated */

	struct kstat_lat_pcpu_struct	sched_lat_ve;

#ifdef CONFIG_INET
	struct venet_stat       *stat;
#ifdef CONFIG_VE_IPTABLES
/* core/netfilter.c virtualization */
	__u64			ipt_mask;
	struct ve_ipt_recent	*_ipt_recent;
	struct ve_xt_hashlimit	*_xt_hashlimit;
#endif /* CONFIG_VE_IPTABLES */
#endif
	wait_queue_head_t	*_log_wait;
	unsigned		*_log_start;
	unsigned		*_log_end;
	unsigned		*_logged_chars;
	char			*log_buf;
#define VE_DEFAULT_LOG_BUF_LEN	4096

	unsigned long		down_at;
	struct list_head	cleanup_list;
#if defined(CONFIG_FUSE_FS) || defined(CONFIG_FUSE_FS_MODULE)
	struct list_head	_fuse_conn_list;
	struct super_block	*_fuse_control_sb;

	struct file_system_type	*fuse_fs_type;
	struct file_system_type	*fuse_ctl_fs_type;
#endif
	unsigned long		jiffies_fixup;
	unsigned char		disable_net;
	struct ve_monitor	*monitor;
	struct proc_dir_entry	*monitor_proc;
	unsigned long		meminfo_val;
	int _randomize_va_space;

	int 			odirect_enable;
	int			fsync_enable;

#if defined(CONFIG_LOCKD) || defined(CONFIG_LOCKD_MODULE)
	struct ve_nlm_data	*nlm_data;
#endif
#if defined(CONFIG_NFS_FS) || defined(CONFIG_NFS_FS_MODULE)
	struct ve_nfs_data	*nfs_data;
#endif
#if defined(CONFIG_NFSD) || defined(CONFIG_NFSD_MODULE)
	struct ve_nfsd_data	*nfsd_data;
#endif
#if defined(CONFIG_SUNRPC) || defined(CONFIG_SUNRPC_MODULE)
	struct ve_rpc_data	*ve_rpc_data;
	struct work_struct	rpc_destroy_work;
#endif
#if defined(CONFIG_BINFMT_MISC) || defined(CONFIG_BINFMT_MISC_MODULE)
	struct file_system_type	*bm_fs_type;
	struct vfsmount		*bm_mnt;
	int			bm_enabled;
	int			bm_entry_count;
	struct list_head	bm_entries;
#endif

	struct nsproxy		*ve_ns;
	struct user_namespace	*user_ns;
	struct cred		*init_cred;
	struct net		*ve_netns;
	struct cgroup		*ve_cgroup;
	struct list_head	vetask_auxlist;
#if defined(CONFIG_HOTPLUG)
	u64 _uevent_seqnum;
#endif
	struct list_head	_kthread_create_list;
	struct task_struct	*_kthreadd_task;
	struct workqueue_struct *khelper_wq;
	struct mutex		sync_mutex;

	struct idr		_posix_timers_id;
	spinlock_t		posix_timers_lock;

	struct list_head	devmnt_list;
	struct mutex		devmnt_mutex;

	atomic_t		arp_neigh_entries;
	atomic_t		nd_neigh_entries;
	atomic_t		mnt_nr;

	atomic_t		netns_nr;

	wait_queue_head_t	mnt_poll;
	int			mnt_event;

	void			*lve;

	spinlock_t		aio_nr_lock;
	unsigned long		aio_nr;
	unsigned long		aio_max_nr;
	struct rcu_head		rcu;
};

#define VE_MEMINFO_NR_SPECIAL	3	/* if above or equal treat at nr_pages */
#define VE_MEMINFO_COMPLETE	2	/* show complete information */
#define VE_MEMINFO_DEFAULT      1       /* default behaviour */
#define VE_MEMINFO_SYSTEM       0       /* disable meminfo virtualization */

enum {
	VE_REBOOT,
	VE_RESTORE,
};

extern int nr_ve;
extern struct proc_dir_entry *proc_vz_dir;
extern struct proc_dir_entry *glob_proc_vz_dir;

#ifdef CONFIG_VE

/*
 * Each host block device visible from CT can have no more than one struct
 * ve_devmnt linked in ve->devmnt_list. If ve_devmnt is present, it can be
 * found by 'dev' field.
 */
struct ve_devmnt {
	struct list_head	link;

	dev_t	                dev;
	char	               *allowed_options;
	char	               *hidden_options; /* balloon_ino, etc. */
};

void do_update_load_avg_ve(void);
void do_env_free(struct ve_struct *ptr);

static inline struct ve_struct *get_ve(struct ve_struct *ptr)
{
	if (ptr != NULL)
		atomic_inc(&ptr->counter);
	return ptr;
}

static inline void put_ve(struct ve_struct *ptr)
{
	if (ptr && atomic_dec_and_test(&ptr->counter))
		do_env_free(ptr);
}

void ve_cleanup_schedule(struct ve_struct *);

extern spinlock_t ve_cleanup_lock;
extern struct list_head ve_cleanup_list;
extern struct task_struct *ve_cleanup_thread;

extern int (*do_ve_enter_hook)(struct ve_struct *ve, unsigned int flags);
extern void (*do_env_free_hook)(struct ve_struct *ve);

extern unsigned long long ve_relative_clock(struct timespec * ts);
extern void monotonic_abs_to_ve(clockid_t which_clock, struct timespec *tp);
extern void monotonic_ve_to_abs(clockid_t which_clock, struct timespec *tp);

#ifdef CONFIG_VTTYS
extern int vtty_open_master(int veid, int idx);
extern struct tty_driver *vtty_driver;
#else
static inline int vtty_open_master(int veid, int idx) { return -ENODEV; }
#endif

#define restoring_ve(ve)	test_bit(VE_RESTORE, &(ve)->flags)

#else	/* CONFIG_VE */
#define ve_utsname	system_utsname
#define get_ve(ve)	(NULL)
#define put_ve(ve)	do { } while (0)
#define pget_ve(ve)	do { } while (0)
#define pput_ve(ve)	do { } while (0)
#define restoring_ve(ve) (0)
#endif	/* CONFIG_VE */

#endif /* _LINUX_VE_H */
