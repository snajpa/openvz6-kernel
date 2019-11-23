/*
 *  linux/kernel/ve/vecalls.c
 *
 *  Copyright (C) 2000-2005  SWsoft
 *  All rights reserved.
 *
 */

/*
 * 'vecalls.c' is file with basic VE support. It provides basic primities
 * along with initialization script
 */

#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/capability.h>
#include <linux/ve.h>
#include <linux/smp_lock.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/sys.h>
#include <linux/fs_struct.h>
#include <linux/fs.h>
#include <linux/mnt_namespace.h>
#include <linux/termios.h>
#include <linux/tty_driver.h>
#include <linux/netdevice.h>
#include <linux/wait.h>
#include <linux/inetdevice.h>
#include <net/addrconf.h>
#include <linux/utsname.h>
#include <linux/sysctl.h>
#include <linux/proc_fs.h>
#include <linux/devpts_fs.h>
#include <linux/shmem_fs.h>
#include <linux/user_namespace.h>
#include <linux/sysfs.h>
#include <linux/seq_file.h>
#include <linux/kernel_stat.h>
#include <linux/module.h>
#include <linux/suspend.h>
#include <linux/rcupdate.h>
#include <linux/in.h>
#include <linux/idr.h>
#include <linux/inetdevice.h>
#include <linux/pid.h>
#include <net/pkt_sched.h>
#include <bc/beancounter.h>
#include <linux/nsproxy.h>
#include <linux/kobject.h>
#include <linux/freezer.h>
#include <linux/pid_namespace.h>
#include <linux/tty.h>
#include <linux/mount.h>
#include <linux/kthread.h>
#include <linux/oom.h>
#include <linux/aio.h>
#include <linux/kthread.h>
#include <linux/workqueue.h>
#include <linux/audit.h>

#include <net/route.h>
#include <net/ip_fib.h>
#include <net/ip6_route.h>
#include <net/arp.h>
#include <net/ipv6.h>

#include <linux/ve_proto.h>
#include <linux/venet.h>
#include <linux/vzctl.h>
#include <linux/vzcalluser.h>
#include <linux/fairsched.h>

#include <linux/virtinfo.h>
#include <linux/utsrelease.h>
#include <linux/major.h>

#include <bc/dcache.h>

int nr_ve = 1;	/* One VE always exists. Compatibility with vestat */
EXPORT_SYMBOL(nr_ve);

static int	do_env_enter(struct ve_struct *ve, unsigned int flags);
static int	alloc_ve_tty_drivers(struct ve_struct* ve);
static void	free_ve_tty_drivers(struct ve_struct* ve);
static int	register_ve_tty_drivers(struct ve_struct* ve);
static void	unregister_ve_tty_drivers(struct ve_struct* ve);
static int	init_ve_tty_drivers(struct ve_struct *);
static void	fini_ve_tty_drivers(struct ve_struct *);
static int	init_ve_vtty(struct ve_struct *ve);
static void	fini_ve_vtty(struct ve_struct *ve);
static void	clear_termios(struct tty_driver* driver );

static void vecalls_exit(void);

static int alone_in_pgrp(struct task_struct *tsk);

/*
 * real_put_ve() MUST be used instead of put_ve() inside vecalls.
 */
static void real_do_env_free(struct ve_struct *ve);
static inline void real_put_ve(struct ve_struct *ve)
{
	if (ve && atomic_dec_and_test(&ve->counter)) {
		BUG_ON(ve->pcounter > 0);
		BUG_ON(ve->is_running);
		real_do_env_free(ve);
	}
}

static s64 ve_get_uptime(struct ve_struct *ve)
{
	struct timespec uptime;
	do_posix_clock_monotonic_gettime(&uptime);
	monotonic_to_bootbased(&uptime);
	uptime = timespec_sub(uptime, ve->real_start_timespec);
	return timespec_to_ns(&uptime);
}

static int ve_get_cpu_stat(envid_t veid, struct vz_cpu_stat __user *buf)
{
	struct ve_struct *ve;
	struct vz_cpu_stat *vstat;
	int retval;
	int i;
	unsigned long tmp;
	unsigned long avenrun[3];
	struct kernel_cpustat kstat;

	if (!ve_is_super(get_exec_env()) && (veid != get_exec_env()->veid))
		return -EPERM;
	if (veid == 0)
		return -ESRCH;

	vstat = kzalloc(sizeof(*vstat), GFP_KERNEL);
	if (!vstat)
		return -ENOMEM;

	retval = fairsched_get_cpu_stat(veid, &kstat);
	if (retval)
		goto out_free;

	retval = fairsched_get_cpu_avenrun(veid, avenrun);
	if (retval)
		goto out_free;

	retval = -ESRCH;
	mutex_lock(&ve_list_lock);
	ve = __find_ve_by_id(veid);
	if (ve == NULL)
		goto out_unlock;

	vstat->user_jif += (unsigned long)cputime64_to_clock_t(kstat.cpustat[USER]);
	vstat->nice_jif += (unsigned long)cputime64_to_clock_t(kstat.cpustat[NICE]);
	vstat->system_jif += (unsigned long)cputime64_to_clock_t(kstat.cpustat[SYSTEM]);
	vstat->idle_clk += kstat.cpustat[IDLE];

	vstat->uptime_clk = ve_get_uptime(ve);

	vstat->uptime_jif = (unsigned long)cputime64_to_clock_t(
				get_jiffies_64() - ve->start_jiffies);
	for (i = 0; i < 3; i++) {
		tmp = avenrun[i] + (FIXED_1/200);
		vstat->avenrun[i].val_int = LOAD_INT(tmp);
		vstat->avenrun[i].val_frac = LOAD_FRAC(tmp);
	}
	mutex_unlock(&ve_list_lock);

	retval = 0;
	if (copy_to_user(buf, vstat, sizeof(*vstat)))
		retval = -EFAULT;
out_free:
	kfree(vstat);
	return retval;

out_unlock:
	mutex_unlock(&ve_list_lock);
	goto out_free;
}

extern int ve_devt_add(struct ve_struct *ve, unsigned type, dev_t devt,
		       unsigned mask);

static int real_setdevperms(envid_t veid, unsigned type,
		dev_t dev, unsigned mask)
{
	struct ve_struct *ve;
	int err;

	if (!capable_setveid() || veid == 0)
		return -EPERM;

	if ((ve = get_ve_by_id(veid)) == NULL)
		return -ESRCH;

	down_read(&ve->op_sem);
	err = -ESRCH;
	if (ve->is_running)
		err = ve_devt_add(ve, type, dev, mask);
	up_read(&ve->op_sem);
	real_put_ve(ve);
	return err;
}

/**********************************************************************
 **********************************************************************
 *
 * VE start: subsystems
 *
 **********************************************************************
 **********************************************************************/

static int prepare_proc_root(struct ve_struct *ve)
{
	struct proc_dir_entry *de;

	de = kzalloc(sizeof(struct proc_dir_entry) + 6, GFP_KERNEL);
	if (de == NULL)
		return -ENOMEM;

	memcpy(de + 1, "/proc", 6);
	de->name = (char *)(de + 1);
	de->namelen = 5;
	de->mode = S_IFDIR | S_IRUGO | S_IXUGO;
	de->nlink = 2;
	atomic_set(&de->count, 1);

	ve->proc_root = de;
	return 0;
}

#ifdef CONFIG_PROC_FS
static int init_ve_proc(struct ve_struct *ve)
{
	int err;

	err = prepare_proc_root(ve);
	if (err)
		goto out_root;

	err = register_ve_fs_type(ve, &proc_fs_type,
			&ve->proc_fstype, NULL);
	if (err)
		goto out_reg;

	err = pid_ns_prepare_proc(ve->ve_ns->pid_ns);
	if (err)
		goto out_prep_proc;

	ve->proc_mnt = mntget(ve->ve_ns->pid_ns->proc_mnt);

#ifdef CONFIG_PRINTK
	if (proc_create("kmsg", S_IRUSR, ve->proc_root,
				&proc_kmsg_operations) == NULL)
		goto out_kmsg;
#endif
	if (proc_mkdir("vz", ve->proc_root) == NULL)
		goto out_vz;

	if (proc_mkdir("fs", ve->proc_root) == NULL)
		goto out_fs;

	if (proc_create("partitions", 0, ve->proc_root, NULL) == NULL)
		goto out_parts;

	return 0;

out_parts:
	remove_proc_entry("fs", ve->proc_root);
out_fs:
	remove_proc_entry("vz", ve->proc_root);
out_vz:
	remove_proc_entry("kmsg", ve->proc_root);
out_kmsg:
	mntput(ve->proc_mnt);
	ve->proc_mnt = NULL;

	pid_ns_release_proc(ve->ve_ns->pid_ns);
out_prep_proc:
	unregister_ve_fs_type(ve->proc_fstype, NULL);
out_reg:
	/* proc_fstype and proc_root are freed in real_put_ve -> free_ve_proc */
	;
out_root:
	return err;
}

static LIST_HEAD(ve_proc_entries);
static DECLARE_MUTEX(ve_proc_entries_lock);

struct ve_proc_dir_entry
{
	struct list_head list;
	struct proc_dir_entry *de;
	struct ve_struct *ve;
};

static void cleanup_ve_proc_entries(struct ve_struct *ve, struct list_head *list)
{
	struct ve_proc_dir_entry *ve_de, *t;
	list_for_each_entry_safe(ve_de, t, list, list) {
		if (ve_de->ve != ve)
			continue;
		remove_proc_entry(ve_de->de->name, ve_de->de->parent);
	}
}

static void fini_ve_proc_entries(struct ve_struct *ve)
{

	down(&ve_proc_entries_lock);
	cleanup_ve_proc_entries(ve, &ve_proc_entries);
	up(&ve_proc_entries_lock);
}

static void fini_ve_proc(struct ve_struct *ve)
{
	remove_proc_entry("partitions", ve->proc_root);
	remove_proc_entry("fs", ve->proc_root);
	remove_proc_entry("vz", ve->proc_root);
	remove_proc_entry("kmsg", ve->proc_root);
	fini_ve_proc_entries(ve);
	unregister_ve_fs_type(ve->proc_fstype, ve->proc_mnt);
	ve->proc_mnt = NULL;
}

static void free_ve_proc(struct ve_struct *ve)
{
	/* proc filesystem frees proc_dir_entries on remove_proc_entry() only,
	   so we check that everything was removed and not lost */
	if (ve->proc_root && ve->proc_root->subdir) {
		struct proc_dir_entry *p = ve->proc_root;
		printk(KERN_WARNING "CT: %d: proc entry /proc", ve->veid);
		while ((p = p->subdir) != NULL)
			printk("/%s", p->name);
		printk(" is not removed!\n");
	}

	kfree(ve->proc_root);
	kfree(ve->proc_fstype);

	ve->proc_fstype = NULL;
	ve->proc_root = NULL;
}
#else
#define init_ve_proc(ve)	(0)
#define fini_ve_proc(ve)	do { } while (0)
#define free_ve_proc(ve)	do { } while (0)
#endif

#ifdef CONFIG_UNIX98_PTYS
#include <linux/devpts_fs.h>

/*
 * DEVPTS needs a virtualization: each environment should see each own list of
 * pseudo-terminals.
 * To implement it we need to have separate devpts superblocks for each
 * VE, and each VE should mount its own one.
 * Thus, separate vfsmount structures are required.
 * To minimize intrusion into vfsmount lookup code, separate file_system_type
 * structures are created.
 *
 * In addition to this, patch fo character device itself is required, as file
 * system itself is used only for MINOR/MAJOR lookup.
 */

static int init_ve_devpts(struct ve_struct *ve)
{
	ve->devpts_mnt = kern_mount(&devpts_fs_type);
	if (IS_ERR(ve->devpts_mnt))
		return PTR_ERR(ve->devpts_mnt);
	return 0;
}

static void fini_ve_devpts(struct ve_struct *ve)
{
	kern_umount(ve->devpts_mnt);
}
#else
#define init_ve_devpts(ve)	(0)
#define fini_ve_devpts(ve)	do { } while (0)
#endif

static int init_ve_shmem(struct ve_struct *ve)
{
	return register_ve_fs_type_data_flags(ve,
					      &shmem_fs_type,
					      &ve->shmem_fstype,
					      &ve->shmem_mnt,
					      NULL, MS_NOUSER);
}

static void fini_ve_shmem(struct ve_struct *ve)
{
	unregister_ve_fs_type(ve->shmem_fstype, ve->shmem_mnt);
	/* shmem_fstype is freed in real_put_ve -> free_ve_filesystems */
	ve->shmem_mnt = NULL;
}

#if defined(CONFIG_NET) && defined(CONFIG_SYSFS)
extern struct device_attribute ve_net_class_attributes[];
static inline int init_ve_netclass(void)
{
	struct class *nc;
	int err;

	nc = kzalloc(sizeof(*nc), GFP_KERNEL);
	if (!nc)
		return -ENOMEM;

	nc->name = net_class.name;
	nc->dev_release = net_class.dev_release;
	nc->dev_uevent = net_class.dev_uevent;
	nc->dev_attrs = ve_net_class_attributes;

	err = class_register(nc);
	if (!err) {
		get_exec_env()->net_class = nc;
		return 0;
	}
	kfree(nc);	
	return err;
}

static inline void fini_ve_netclass(void)
{
	struct ve_struct *ve = get_exec_env();

	class_unregister(ve->net_class);
	kfree(ve->net_class);
	ve->net_class = NULL;
}
#else
static inline int init_ve_netclass(void) { return 0; }
static inline void fini_ve_netclass(void) { ; }
#endif

static const struct {
	unsigned	minor;
	char		*name;
} mem_class_devices [] = {
	{3, "null"},
	{5, "zero"},
	{7, "full"},
	{8, "random"},
	{9, "urandom"},
	{0, NULL},
};

extern char *mem_devnode(struct device *dev, mode_t *mode);
static int init_ve_mem_class(void)
{
	int i;
	struct class *ve_mem_class;

	ve_mem_class = class_create(THIS_MODULE, "mem");
	if (IS_ERR(ve_mem_class))
		return -ENOMEM;
	ve_mem_class->devnode = mem_devnode;

	for (i = 0; mem_class_devices[i].name; i++)
		device_create(ve_mem_class, NULL,
				MKDEV(MEM_MAJOR, mem_class_devices[i].minor),
				NULL, mem_class_devices[i].name);

	get_exec_env()->mem_class = ve_mem_class;
	return 0;
}


void fini_ve_mem_class(void)
{
	int i;
	struct class *ve_mem_class = get_exec_env()->mem_class;

	for (i = 0; mem_class_devices[i].name; i++)
		device_destroy(ve_mem_class,
				MKDEV(MEM_MAJOR, mem_class_devices[i].minor));
	class_destroy(ve_mem_class);
}

static void fini_ve_sysfs_fs(struct ve_struct *ve)
{
	kobject_put(ve->cgroup_kobj);
	kobject_put(ve->fs_kobj);
}

static int init_ve_sysfs_fs(struct ve_struct *ve)
{
	ve->fs_kobj = kobject_create_and_add("fs", NULL);
	if (!ve->fs_kobj)
		goto err;
	ve->cgroup_kobj = kobject_create_and_add("cgroup", ve->fs_kobj);
	if (!ve->cgroup_kobj)
		goto err;
	return 0;
err:
	fini_ve_sysfs_fs(ve);
	return -ENOMEM;
}

static int init_ve_ksysfs(struct ve_struct *ve)
{
#if defined(CONFIG_HOTPLUG)
	return ksysfs_init_ve(ve, &ve->kernel_kobj);
#else
	return 0;
#endif
}

static void fini_ve_ksysfs(struct ve_struct *ve)
{
#if defined(CONFIG_HOTPLUG)
	ksysfs_fini_ve(ve, &ve->kernel_kobj);
#endif
}

static void fini_ve_sysfs_cpu(struct ve_struct *ve)
{
	struct kobject *kobj, *kobjn;

	if (ve->cpu_kset) {
		list_for_each_entry_safe(kobj, kobjn,
				&ve->cpu_kset->list, entry)
			kobject_put(kobj);
		kset_put(ve->cpu_kset);
	}
}

static int init_ve_sysfs_cpu(struct ve_struct *ve)
{
	int i, nr_cpus;
	struct kobject *kobj;

	ve->cpu_kset = kset_create_and_add("cpu", NULL, ve->_system_dir);
	if (!ve->cpu_kset)
		goto out;

	nr_cpus = num_possible_cpus();
	nr_cpus = max(nr_cpus, 2);
	for (i = 0; i < nr_cpus; i++) {
		kobj = kobject_create();
		if (!kobj)
			goto out;
		kobj->kset = ve->cpu_kset;
		if (kobject_add(kobj, NULL, "cpu%d", i)) {
			kobject_put(kobj);
			goto out;
		}
	}

	return 0;
out:
	fini_ve_sysfs_cpu(ve);
	return -ENOMEM;
}

static void fini_ve_sysfs_system(struct ve_struct *ve)
{
	fini_ve_sysfs_cpu(ve);
	kobject_put(ve->_system_dir);
}

static int init_ve_sysfs_system(struct ve_struct *ve)
{
	int err;

	err = -ENOMEM;
	ve->_system_dir = kobject_create_and_add("system",
						 &ve->devices_kset->kobj);
	if (!ve->_system_dir)
		goto out;

	err = init_ve_sysfs_cpu(ve);
	if (err)
		goto out;

	return 0;
out:
	fini_ve_sysfs_system(ve);
	return err;
}

static int init_ve_devtmpfs(struct ve_struct *ve)
{
#ifdef CONFIG_DEVTMPFS
	char opts[] = "mode=0755";
	return register_ve_fs_type_data(ve, &dev_fs_type,
			&ve->devtmpfs_fstype, &ve->devtmpfs_mnt, opts);
#else
	return 0;
#endif
}

static void fini_ve_devtmpfs(struct ve_struct *ve)
{
#ifdef CONFIG_DEVTMPFS
	unregister_ve_fs_type(ve->devtmpfs_fstype, ve->devtmpfs_mnt);
	ve->devtmpfs_mnt = NULL;
#endif
}

int ve_smnfct_enabled = 1;
static ssize_t ve_smnfct_state_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "live\n");
}

static struct kobj_attribute ve_smnfct_state_attr = {
	.attr	= { .name = "initstate", .mode = 0444 },
	.show	= ve_smnfct_state_show,
};

static struct attribute * ve_smnfct_attrs[] = {
	&ve_smnfct_state_attr.attr,
};

static struct attribute_group ve_smnfct_attr_group = {
	.attrs = ve_smnfct_attrs,
};

#define CENTOS7_OSRELEASE "3.10.0-"
int init_ve_smnfct(struct ve_struct *ve)
{
	int err = 0;

	if (!(ve->features & VE_FEATURE_SMNFCT))
		goto out;

	if (!ve_smnfct_enabled)
		goto out;

	if (ve->smod_kobj)
		goto out;

	if (strncmp(ve->ve_ns->uts_ns->name.release, CENTOS7_OSRELEASE, 7))
		goto out;

	err = -ENOMEM;
	ve->smod_kobj = kobject_create_and_add("module", NULL);
	if (!ve->smod_kobj)
		goto out;

	ve->smct_kobj = kobject_create_and_add("nf_conntrack", ve->smod_kobj);
	if (!ve->smct_kobj)
		goto err_smct;

	err = sysfs_create_group(ve->smct_kobj, &ve_smnfct_attr_group);
	if (err)
		goto err_sysfs;

	return 0;

err_sysfs:
	kobject_put(ve->smct_kobj);
err_smct:
	kobject_put(ve->smod_kobj);
	ve->smod_kobj = NULL;
out:
	return err;
}
EXPORT_SYMBOL(init_ve_smnfct);

static void fini_ve_smnfct(struct ve_struct *ve)
{
	if (ve->smod_kobj) {
		sysfs_remove_group(ve->smct_kobj, &ve_smnfct_attr_group);
		kobject_put(ve->smct_kobj);
		kobject_put(ve->smod_kobj);
		ve->smod_kobj = NULL;
	}
}

static int init_ve_sysfs(struct ve_struct *ve)
{
	int err;

#ifdef CONFIG_SYSFS
	err = 0;
	if (ve->features & VE_FEATURE_SYSFS) {
		err = init_ve_sysfs_root(ve);
		if (err != 0)
			goto out;
		err = register_ve_fs_type(ve,
				   &sysfs_fs_type,
				   &ve->sysfs_fstype,
				   &ve->sysfs_mnt);
		if (err != 0)
			goto out_fs_type;
	}
#endif

	err = classes_init();
	if (err != 0)
		goto err_classes;

	err = devices_init();
	if (err != 0)
		goto err_devices;

	err = init_ve_netclass();
	if (err != 0)
		goto err_net;

	err = init_ve_tty_class();
	if (err != 0)
		goto err_tty;

	err = init_ve_mem_class();
	if (err != 0)
		goto err_mem;

	err = init_ve_sysfs_fs(ve);
	if (err != 0)
		goto err_fs;

	err = init_ve_sysfs_system(ve);
	if (err != 0)
		goto err_sys;

	err = init_ve_ksysfs(ve);
	if (err !=0)
		goto err_ksys;

	return 0;

err_ksys:
	fini_ve_sysfs_system(ve);
err_sys:
	fini_ve_sysfs_fs(ve);
err_fs:
	fini_ve_mem_class();
err_mem:
	fini_ve_tty_class();
err_tty:
	fini_ve_netclass();
err_net:
	devices_fini();
err_devices:
	classes_fini();
err_classes:
#ifdef CONFIG_SYSFS
	unregister_ve_fs_type(ve->sysfs_fstype, ve->sysfs_mnt);
	/* sysfs_fstype is freed in real_put_ve -> free_ve_filesystems */
out_fs_type:
	sysfs_put(ve->_sysfs_root);
	ve->_sysfs_root = NULL;
out:
#endif
	return err;
}

static void fini_ve_sysfs(struct ve_struct *ve)
{
	fini_ve_smnfct(ve);
	fini_ve_ksysfs(ve);
	fini_ve_sysfs_system(ve);
	fini_ve_sysfs_fs(ve);
	fini_ve_mem_class();
	fini_ve_tty_class();
	fini_ve_netclass();
	devices_fini();
	classes_fini();
#ifdef CONFIG_SYSFS
	unregister_ve_fs_type(ve->sysfs_fstype, ve->sysfs_mnt);
	ve->sysfs_mnt = NULL;
	sysfs_put(ve->_sysfs_root);
	ve->_sysfs_root = NULL;
	/* sysfs_fstype is freed in real_put_ve -> free_ve_filesystems */
#endif
}

static void free_ve_filesystems(struct ve_struct *ve)
{
#ifdef CONFIG_SYSFS
	kfree(ve->sysfs_fstype);
	ve->sysfs_fstype = NULL;
#endif
	kfree(ve->shmem_fstype);
	ve->shmem_fstype = NULL;

#if defined(CONFIG_FUSE_FS) || defined(CONFIG_FUSE_FS_MODULE)
	BUG_ON(ve->fuse_fs_type && !list_empty(&ve->_fuse_conn_list));
	kfree(ve->fuse_fs_type);
	ve->fuse_fs_type = NULL;

	kfree(ve->fuse_ctl_fs_type);
	ve->fuse_ctl_fs_type = NULL;
#endif

#if defined(CONFIG_DEVTMPFS)
	kfree(ve->devtmpfs_fstype);
	ve->devtmpfs_fstype = NULL;
#endif

#if defined(CONFIG_BINFMT_MISC) || defined(CONFIG_BINFMT_MISC_MODULE)
	kfree(ve->bm_fs_type);
	ve->bm_fs_type = NULL;
#endif

	free_ve_proc(ve);
}

static int init_printk(struct ve_struct *ve)
{
	struct ve_prep_printk {
		wait_queue_head_t       log_wait;
		unsigned		log_start;
		unsigned		log_end;
		unsigned		logged_chars;
	} *tmp;

	tmp = kzalloc(sizeof(struct ve_prep_printk), GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	init_waitqueue_head(&tmp->log_wait);
	ve->_log_wait = &tmp->log_wait;
	ve->_log_start = &tmp->log_start;
	ve->_log_end = &tmp->log_end;
	ve->_logged_chars = &tmp->logged_chars;
	/* ve->log_buf will be initialized later by ve_log_init() */
	return 0;
}

static void fini_printk(struct ve_struct *ve)
{
	/* 
	 * there is no spinlock protection here because nobody can use
	 * log_buf at the moments when this code is called. 
	 */
	kfree(ve->log_buf);
	kfree(ve->_log_wait);
}

static void fini_venet(struct ve_struct *ve)
{
#ifdef CONFIG_INET
	tcp_v4_kill_ve_sockets(ve);
	synchronize_net();
#endif
}

static int init_ve_sched(struct ve_struct *ve, unsigned int vcpus)
{
	int err;

	err = fairsched_new_node(ve->veid, vcpus);

	return err;
}

static void fini_ve_sched(struct ve_struct *ve, int leave)
{
	fairsched_drop_node(ve->veid, leave);
}

/*
 * Namespaces
 */

static inline int init_ve_namespaces(struct ve_struct *ve,
		struct nsproxy **old)
{
	int err;
	struct task_struct *tsk;
	struct nsproxy *cur;

	tsk = current;
	cur = tsk->nsproxy;

	err = copy_namespaces(CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWPID | CLONE_NEWNET,
			tsk, 1);
	if (err < 0)
		return err;

	ve->ve_ns = get_nsproxy(tsk->nsproxy);
	memcpy(ve->ve_ns->uts_ns->name.release, virt_utsname.release,
			sizeof(virt_utsname.release));

	if (cur->pid_ns->flags & PID_NS_HIDE_CHILD)
		ve->ve_ns->pid_ns->flags |= PID_NS_HIDDEN;

	*old = cur;
	return 0;
}

static inline void fini_ve_namespaces(struct ve_struct *ve,
		struct nsproxy *old)
{
	struct task_struct *tsk = current;
	struct nsproxy *tmp;

	if (old) {
		tmp = tsk->nsproxy;
		tsk->nsproxy = get_nsproxy(old);
		put_nsproxy(tmp);
		tmp = ve->ve_ns;
		ve->ve_ns = get_nsproxy(old);
		put_nsproxy(tmp);
	} else {
		put_cred(ve->init_cred);
		put_nsproxy(ve->ve_ns);
		ve->ve_ns = NULL;
	}
}

static int init_ve_netns(struct ve_struct *ve)
{
	ve->ve_netns = get_net(ve->ve_ns->net_ns);
	return 0;
}

static void fini_ve_netns(struct ve_struct *ve)
{
	struct net *net;
	DECLARE_COMPLETION_ONSTACK(sysfs_completion);

	net = ve->ve_netns;
	if (!net)
		return; /* it isn't initialized yet */
	net->sysfs_completion = &sysfs_completion;
	put_net(net);
	wait_for_completion(&sysfs_completion);
}

static inline void switch_ve_namespaces(struct ve_struct *ve,
		struct task_struct *tsk)
{
	struct nsproxy *old_ns;
	struct nsproxy *new_ns;

	BUG_ON(tsk != current);
	old_ns = tsk->nsproxy;
	new_ns = ve->ve_ns;

	if (old_ns != new_ns) {
		tsk->nsproxy = get_nsproxy(new_ns);
		put_nsproxy(old_ns);
	}
}

static __u64 get_ve_features(env_create_param_t *data, int datalen)
{
	__u64 known_features;

	if (datalen < sizeof(struct env_create_param3))
		/* this version of vzctl is aware of VE_FEATURES_OLD only */
		known_features = VE_FEATURES_OLD;
	else
		known_features = data->known_features;

	/*
	 * known features are set as required
	 * yet unknown features are set as in VE_FEATURES_DEF
	 */
	return (data->feature_mask & known_features) |
		(VE_FEATURES_DEF & ~known_features);
}

static int init_ve_struct(struct ve_struct *ve, envid_t veid,
		u32 class_id, env_create_param_t *data, int datalen)
{
	(void)get_ve(ve);
	ve->veid = veid;
	ve->class_id = class_id;
	ve->features = get_ve_features(data, datalen);
	INIT_LIST_HEAD(&ve->vetask_lh);
	init_rwsem(&ve->op_sem);

	ve->start_timespec = current->start_time;
	ve->real_start_timespec = current->real_start_time;
	/* The value is wrong, but it is never compared to process
	 * start times */
	ve->start_jiffies = get_jiffies_64();

	ve->_randomize_va_space = ve0._randomize_va_space;
	INIT_LIST_HEAD(&ve->vetask_auxlist);
	INIT_LIST_HEAD(&ve->devices);

	ve->odirect_enable = 2;
	ve->fsync_enable = 2;

	INIT_LIST_HEAD(&ve->ve_list);
	init_waitqueue_head(&ve->ve_list_wait);
	mutex_init(&ve->sync_mutex);

	INIT_LIST_HEAD(&ve->devmnt_list);
	mutex_init(&ve->devmnt_mutex);

	idr_init(&ve->_posix_timers_id);
	spin_lock_init(&ve->posix_timers_lock);

	atomic_set(&ve->arp_neigh_entries, 0);
	atomic_set(&ve->nd_neigh_entries, 0);
	atomic_set(&ve->mnt_nr, 0);

	init_waitqueue_head(&ve->mnt_poll);
	ve->mnt_event = 0;

	spin_lock_init(&ve->aio_nr_lock);
	ve->aio_nr = 0;
	ve->aio_max_nr = AIO_MAX_NR_DEFAULT;

	atomic_set(&ve->netns_nr, sysctl_ve_netns_nr);

	return 0;
}

/**********************************************************************
 **********************************************************************
 *
 * /proc/meminfo virtualization
 *
 **********************************************************************
 **********************************************************************/
static int ve_set_meminfo(envid_t veid, unsigned long val)
{
#ifdef CONFIG_BEANCOUNTERS
	struct ve_struct *ve;

	ve = get_ve_by_id(veid);
	if (!ve)
		return -EINVAL;

	if (val == 0)
		val = VE_MEMINFO_SYSTEM;
	else if (val == 1)
		val = VE_MEMINFO_DEFAULT;
	else if (val == 2)
		val = VE_MEMINFO_COMPLETE;

	ve->meminfo_val = val;
	real_put_ve(ve);
	return 0;
#else
	return -ENOTTY;
#endif
}

static int init_ve_meminfo(struct ve_struct *ve)
{
	ve->meminfo_val = VE_MEMINFO_DEFAULT;
	return 0;
}

static inline void fini_ve_meminfo(struct ve_struct *ve)
{
}

static void set_ve_root(struct ve_struct *ve, struct task_struct *tsk)
{
	get_fs_root(tsk->fs, &ve->root_path);
	/* mark_tree_virtual(&ve->root_path); */
	ub_dcache_set_owner(ve->root_path.dentry, get_exec_ub_top());
}

static void put_ve_root(struct ve_struct *ve)
{
	path_put(&ve->root_path);
}

static void set_ve_caps(struct ve_struct *ve, struct task_struct *tsk)
{
	/* required for real_setdevperms from register_ve_<fs> above */
	memcpy(&ve->ve_cap_bset, &tsk->cred->cap_effective, sizeof(kernel_cap_t));
}

static int ve_list_add(struct ve_struct *ve)
{
	mutex_lock(&ve_list_lock);
	if (__find_ve_by_id(ve->veid) != NULL)
		goto err_exists;

	list_add_rcu(&ve->ve_list, &ve_list_head);
	nr_ve++;
	mutex_unlock(&ve_list_lock);
	return 0;

err_exists:
	mutex_unlock(&ve_list_lock);
	return -EEXIST;
}

static void ve_list_del(struct ve_struct *ve)
{
	mutex_lock(&ve_list_lock);
	list_del_rcu(&ve->ve_list);
	nr_ve--;
	mutex_unlock(&ve_list_lock);
	wake_up_all(&ve->ve_list_wait);
}

static void init_ve_cred(struct ve_struct *ve, struct cred *new)
{
	const struct cred *cur;
	kernel_cap_t bset;

	bset = ve->ve_cap_bset;
	cur = current_cred();
	new->cap_effective = cap_intersect(cur->cap_effective, bset);
	new->cap_inheritable = cap_intersect(cur->cap_inheritable, bset);
	new->cap_permitted = cap_intersect(cur->cap_permitted, bset);
	new->cap_bset = cap_intersect(cur->cap_bset, bset);

	ve->init_cred = new;
	ve->user_ns = new->user->user_ns;
}

static void ve_move_task(struct ve_struct *new)
{
	struct task_struct *tsk = current;
	struct ve_struct *old;

	might_sleep();
	BUG_ON(!(thread_group_leader(tsk) && thread_group_empty(tsk)));

	/* this probihibts ptracing of task entered to VE from host system */
	if (tsk->mm)
		tsk->mm->vps_dumpable = VD_VE_ENTER_TASK;
	/* setup capabilities before enter */
	if (commit_creds(get_new_cred(new->init_cred)))
		BUG();

	/* Reset OOM score adjustment */
	tsk->signal->oom_adj = 0;
	test_set_oom_score_adj(OOM_SCORE_ADJ_UNSET);

	/* Reset loginuid */
	audit_set_loginuid(current, (uid_t)-1);

	/* Adjust cpuid faulting */
	set_cpuid_faulting(!ve_is_super(new));

	old = tsk->ve_task_info.owner_env;
	tsk->ve_task_info.owner_env = new;

	/* set ve fs_struct for kernel threads */
	if (current->flags & PF_KTHREAD)
		daemonize_fs_struct();

	tasklist_write_lock_irq();
	list_move_tail(&tsk->ve_task_info.vetask_list, &new->vetask_lh);
	list_move_tail(&tsk->ve_task_info.aux_list, &new->vetask_auxlist);
	old->pcounter--;
	new->pcounter++;
	write_unlock_irq(&tasklist_lock);

	real_put_ve(old);
	get_ve(new);

	cgroup_kernel_attach(new->ve_cgroup, tsk);
}

#ifdef CONFIG_VE_IPTABLES

static __u64 setup_iptables_mask(__u64 init_mask)
{
	/* Remove when userspace will start supplying IPv6-related bits. */
	init_mask &= ~VE_IP_IPTABLES6;
	init_mask &= ~VE_IP_FILTER6;
	init_mask &= ~VE_IP_MANGLE6;
	init_mask &= ~VE_IP_IPTABLE_NAT_MOD;
	init_mask &= ~VE_NF_CONNTRACK_MOD;

	if (mask_ipt_allow(init_mask, VE_IP_IPTABLES))
		init_mask |= VE_IP_IPTABLES6;
	if (mask_ipt_allow(init_mask, VE_IP_FILTER))
		init_mask |= VE_IP_FILTER6;
	if (mask_ipt_allow(init_mask, VE_IP_MANGLE))
		init_mask |= VE_IP_MANGLE6;
	if (mask_ipt_allow(init_mask, VE_IP_NAT))
		init_mask |= VE_IP_IPTABLE_NAT;
	if (mask_ipt_allow(init_mask, VE_IP_CONNTRACK))
		init_mask |= VE_NF_CONNTRACK;

	return init_mask;
}

#endif

static inline int init_ve_cpustats(struct ve_struct *ve)
{
	ve->sched_lat_ve.cur = alloc_percpu(struct kstat_lat_pcpu_snap_struct);
	if (ve->sched_lat_ve.cur == NULL)
		return -ENOMEM;
	return 0;
}

static inline void free_ve_cpustats(struct ve_struct *ve)
{
	free_percpu(ve->sched_lat_ve.cur);
	ve->sched_lat_ve.cur = NULL;
}

static int alone_in_pgrp(struct task_struct *tsk)
{
	struct task_struct *p;
	int alone = 0;

	read_lock(&tasklist_lock);
	do_each_pid_task(task_pid(tsk), PIDTYPE_PGID, p) {
		if (p != tsk)
			goto out;
	} while_each_pid_task(task_pid(tsk), PIDTYPE_PGID, p);
	do_each_pid_task(task_pid(tsk), PIDTYPE_SID, p) {
		if (p != tsk)
			goto out;
	} while_each_pid_task(task_pid(tsk), PIDTYPE_SID, p);
	alone = 1;
out:
	read_unlock(&tasklist_lock);
	return alone;
}

#ifdef CONFIG_CGROUP_DEVICE

static struct vfsmount *ve_cgroup_mnt;
static struct cgroup *ve_cgroup_root;

static int init_ve_cgroups(struct ve_struct *ve)
{
	char name[16];

	snprintf(name, sizeof(name), "%u", ve->veid);
	ve->ve_cgroup = cgroup_kernel_open(ve_cgroup_root,
			CGRP_CREAT|CGRP_WEAK, name);
	if (IS_ERR(ve->ve_cgroup))
		return PTR_ERR(ve->ve_cgroup);
	return ve_prep_devcgroup(ve);
}

static void fini_ve_cgroups(struct ve_struct *ve)
{
	cgroup_kernel_close(ve->ve_cgroup);
	ve->ve_cgroup = NULL;
}

static int __init init_vecalls_cgroups(void)
{
	struct cgroup_sb_opts opts = {
		.name		= "container",
		.subsys_bits	=
			(1ul << devices_subsys_id) |
			(1ul << freezer_subsys_id),
	};

	ve_cgroup_mnt = cgroup_kernel_mount(&opts);
	if (IS_ERR(ve_cgroup_mnt))
		return PTR_ERR(ve_cgroup_mnt);
	ve_cgroup_root = cgroup_get_root(ve_cgroup_mnt);
	get_ve0()->ve_cgroup = ve_cgroup_root;
	return 0;
}

static void fini_vecalls_cgroups(void)
{
	kern_umount(ve_cgroup_mnt);
}
#else
static int init_ve_cgroups(struct ve_struct *ve) { }
static int fini_ve_cgroups(struct ve_struct *ve) { }
static int init_vecalls_cgroups(void) { return 0; }
static void fini_vecalls_cgroups(void) { ; }
#endif /* CONFIG_CGROUP_DEVICE */

void fini_kthreadd(struct ve_struct *ve)
{
	long delay = 1;

	if (ve->khelper_wq)
		destroy_workqueue(ve->khelper_wq);
	kthreadd_stop(ve);

	while (ve->pcounter > 1) {
		schedule_timeout(delay);
		delay = (delay < HZ) ? (delay << 1) : HZ;
	}
}

int init_kthreadd(struct ve_struct *ve)
{
	int err;

	err = kthreadd_create();
	if (err < 0)
		return err;

	ve->khelper_wq = create_singlethread_workqueue_ve("khelper", ve);
	if (ve->khelper_wq == NULL) {
		fini_kthreadd(ve);
		return -ENOMEM;
	}

	return 0;
}

static int do_env_create(envid_t veid, unsigned int flags, u32 class_id,
			 env_create_param_t *data, int datalen)
{
	struct task_struct *tsk;
	struct cred *new_creds;
	struct ve_struct *old;
	struct ve_struct *old_exec;
	struct ve_struct *ve;
 	__u64 init_mask;
	int err;
	struct nsproxy *old_ns;

	tsk = current;
	old = VE_TASK_INFO(tsk)->owner_env;

	if (!thread_group_leader(tsk) || !thread_group_empty(tsk))
		return -EINVAL;

	if (tsk->signal->tty) {
		printk("ERR: CT init has controlling terminal\n");
		return -EINVAL;
	}
	if (task_pgrp(tsk) != task_pid(tsk) ||
			task_session(tsk) != task_pid(tsk)) {
		int may_setsid;

		read_lock(&tasklist_lock);
		may_setsid = !tsk->signal->leader &&
			!pid_task(find_pid_ns(task_pid_nr(tsk), &init_pid_ns), PIDTYPE_PGID);
		read_unlock(&tasklist_lock);

		if (!may_setsid) {
			printk("ERR: CT init is process group leader\n");
			return -EINVAL;
		}
	}
	/* Check that the process is not a leader of non-empty group/session.
	 * If it is, we cannot virtualize its PID and must fail. */
	if (!alone_in_pgrp(tsk)) {
		printk("ERR: CT init is not alone in process group\n");
		return -EINVAL;
	}


	VZTRACE("%s: veid=%d classid=%d pid=%d\n",
		__FUNCTION__, veid, class_id, current->pid);

	err = -ENOMEM;
	ve = kzalloc(sizeof(struct ve_struct), GFP_KERNEL);
	if (ve == NULL)
		goto err_struct;

	init_ve_struct(ve, veid, class_id, data, datalen);
	__module_get(THIS_MODULE);
	down_write(&ve->op_sem);
	if (flags & VE_LOCK)
		ve->is_locked = 1;

	/*
	 * this should be done before adding to list
	 * because if calc_load_ve finds this ve in
	 * list it will be very surprised
	 */
	if ((err = init_ve_cpustats(ve)) < 0)
		goto err_cpu_stats;

	if ((err = init_ve_cgroups(ve)))
		goto err_cgroup;

	if ((err = ve_list_add(ve)) < 0)
		goto err_exist;

	/* this should be done before context switching */
	if ((err = init_printk(ve)) < 0)
		goto err_log_wait;

	old_exec = set_exec_env(ve);

	if ((err = init_ve_sched(ve, data->total_vcpus)) < 0)
		goto err_sched;

	set_ve_root(ve, tsk);

	if ((err = init_ve_devtmpfs(ve)))
		goto err_devtmpfs;

	if ((err = init_ve_sysfs(ve)))
		goto err_sysfs;

	init_mask = data ? data->iptables_mask : VE_IP_DEFAULT;

#ifdef CONFIG_VE_IPTABLES
	/* Set up ipt_mask as it will be used during
	 * net namespace initialization
	 */
	init_mask = setup_iptables_mask(init_mask);
	ve->ipt_mask = init_mask;
#endif

	if ((err = init_ve_namespaces(ve, &old_ns)))
		goto err_ns;

	if ((err = init_ve_proc(ve)))
		goto err_proc;

	if ((err = init_ve_netns(ve)))
		goto err_netns;

	if ((err = init_ve_tty_drivers(ve)) < 0)
		goto err_tty;

	if ((err = init_ve_vtty(ve)))
		goto err_vtty;

	if ((err = init_ve_shmem(ve)))
		goto err_shmem;

	if ((err = init_ve_devpts(ve)))
		goto err_devpts;

	if((err = init_ve_meminfo(ve)))
		goto err_meminf;

	set_ve_caps(ve, tsk);

	if ((err = pid_ns_attach_init(ve->ve_ns->pid_ns, tsk)) < 0)
		goto err_vpid;

	err = -ENOMEM;
	new_creds = prepare_creds();
	if (new_creds == NULL)
		goto err_creds;

	if ((err = create_user_ns(new_creds)) < 0)
		goto err_uns;

	init_ve_cred(ve, new_creds);

	ve_move_task(ve);

	if ((err = init_kthreadd(ve)) < 0)
		goto err_kthreadd;

	if ((err = ve_hook_iterate_init(VE_SS_CHAIN, ve)) < 0)
		goto err_ve_hook;

	put_nsproxy(old_ns);

	ve->is_running = 1;
	up_write(&ve->op_sem);

	printk(KERN_INFO "CT: %d: started\n", veid);
	return veid;

err_ve_hook:
	fini_kthreadd(ve);
err_kthreadd:
	ve_move_task(old);
	/* creds will put user and user ns */
err_uns:
	put_cred(new_creds);
err_creds:
	mntget(ve->proc_mnt);
err_vpid:
	fini_venet(ve);
	fini_ve_meminfo(ve);
err_meminf:
	fini_ve_devpts(ve);
err_devpts:
	fini_ve_shmem(ve);
err_shmem:
	fini_ve_vtty(ve);
err_vtty:
	fini_ve_tty_drivers(ve);
err_tty:
err_netns:
	/*
	 * If process hasn't become VE's init, proc_mnt won't be put during
	 * pidns death, so this mntput by hand is needed. If it has, we
	 * compensate with mntget above.
	 */
	mntput(ve->proc_mnt);
	fini_ve_proc(ve);
err_proc:
	/* free_ve_utsname() is called inside real_put_ve() */
	fini_ve_namespaces(ve, old_ns);
	put_nsproxy(old_ns);
	fini_ve_netns(ve);
	/*
	 * We need to compensate, because fini_ve_namespaces() assumes
	 * ve->ve_ns will continue to be used after, but VE will be freed soon
	 * (in kfree() sense).
	 */
	put_nsproxy(ve->ve_ns);
err_ns:
	fini_ve_sysfs(ve);
err_sysfs:
	fini_ve_devtmpfs(ve);
err_devtmpfs:
	put_ve_root(ve);

	/* It is safe to restore current->envid here because
	 * ve_fairsched_detach does not use current->envid. */
	/* Really fairsched code uses current->envid in sys_fairsched_mknod 
	 * only.  It is correct if sys_fairsched_mknod is called from
	 * userspace.  If sys_fairsched_mknod is called from
	 * ve_fairsched_attach, then node->envid and node->parent_node->envid
	 * are explicitly set to valid value after the call. */
	/* FIXME */
	VE_TASK_INFO(tsk)->owner_env = old;
	VE_TASK_INFO(tsk)->exec_env = old_exec;

	fini_ve_sched(ve, 1);
err_sched:
	(void)set_exec_env(old_exec);

	/* we can jump here having incorrect envid */
	VE_TASK_INFO(tsk)->owner_env = old;
	fini_printk(ve);
err_log_wait:
	/* cpustats will be freed in do_env_free */
	ve_list_del(ve);
	up_write(&ve->op_sem);

	real_put_ve(ve);
err_struct:
	printk(KERN_INFO "CT: %d: failed to start with err=%d\n", veid, err);
	return err;

err_exist:
	fini_ve_cgroups(ve);
err_cgroup:
	free_ve_cpustats(ve);
err_cpu_stats:
	kfree(ve);
	module_put(THIS_MODULE);
	goto err_struct;
}


/**********************************************************************
 **********************************************************************
 *
 * VE start/stop callbacks
 *
 **********************************************************************
 **********************************************************************/

int real_env_create(envid_t veid, unsigned flags, u32 class_id,
			env_create_param_t *data, int datalen)
{
	int status;
	struct ve_struct *ve;

	if (!flags) {
		status = get_exec_env()->veid;
		goto out;
	}

	status = -EPERM;
	if (!capable_setveid())
		goto out;

	status = -EINVAL;
	if ((flags & VE_TEST) && (flags & (VE_ENTER|VE_CREATE)))
		goto out;

	status = -EINVAL;
	ve = get_ve_by_id(veid);
	if (ve) {
		if (flags & VE_TEST) {
			status = 0;
			goto out_put;
		}
		if (flags & VE_EXCLUSIVE) {
			status = -EACCES;
			goto out_put;
		}
		if (flags & VE_CREATE) {
			flags &= ~VE_CREATE;
			flags |= VE_ENTER;
		}
	} else {
		if (flags & (VE_TEST|VE_ENTER)) {
			status = -ESRCH;
			goto out;
		}
	}

	if (flags & VE_CREATE) {
		status = do_env_create(veid, flags, class_id, data, datalen);
		goto out;
	} else if (flags & VE_ENTER)
		status = do_env_enter(ve, flags);

	/* else: returning EINVAL */

out_put:
	real_put_ve(ve);
out:
	return status;
}
EXPORT_SYMBOL(real_env_create);

static int do_env_enter(struct ve_struct *ve, unsigned int flags)
{
	struct task_struct *tsk = current;
	int err;

	VZTRACE("%s: veid=%d\n", __FUNCTION__, ve->veid);

	err = -EBUSY;
	down_read(&ve->op_sem);
	if (!ve->is_running)
		goto out_up;
	if (ve->is_locked && !(flags & VE_SKIPLOCK))
		goto out_up;
	err = -EINVAL;
	if (!thread_group_leader(tsk) || !thread_group_empty(tsk))
		goto out_up;

#ifdef CONFIG_VZ_FAIRSCHED
	err = fairsched_move_task(ve->veid, current);
	if (err)
		goto out_up;
#endif
	switch_ve_namespaces(ve, tsk);
	set_exec_env(ve);
	ve_move_task(ve);

	if (alone_in_pgrp(tsk) && !(flags & VE_SKIPLOCK))
		pid_ns_attach_task(ve->ve_ns->pid_ns, tsk);

	/* Unlike VE_CREATE, we do not setsid() in VE_ENTER.
	 * Process is allowed to be in an external group/session.
	 * If user space callers wants, it will do setsid() after
	 * VE_ENTER.
	 */
	err = VE_TASK_INFO(tsk)->owner_env->veid;
	tsk->did_ve_enter = 1;

out_up:
	up_read(&ve->op_sem);
	return err;
}

extern void fini_ve_devices(struct ve_struct *ve);

static void env_cleanup(struct ve_struct *ve)
{
	struct ve_struct *old_ve;

	VZTRACE("real_do_env_cleanup\n");

	down_read(&ve->op_sem);
	old_ve = set_exec_env(ve);

	fini_venet(ve);

	/* no new packets in flight beyond this point */

	fini_ve_sched(ve, 0);

	fini_ve_devpts(ve);
	fini_ve_shmem(ve);
	fini_ve_vtty(ve);
	unregister_ve_tty_drivers(ve);
	fini_ve_meminfo(ve);

	fini_ve_devices(ve);

	fini_ve_namespaces(ve, NULL);
	fini_ve_netns(ve);
	fini_ve_proc(ve);
	fini_ve_sysfs(ve);
	fini_ve_devtmpfs(ve);

	ve_hook_iterate_fini(VE_CLEANUP_CHAIN, ve);

	put_ve_root(ve);

	(void)set_exec_env(old_ve);
	fini_printk(ve);	/* no printk can happen in ve context anymore */

	ve_list_del(ve);
	up_read(&ve->op_sem);

	real_put_ve(ve);
}

static DECLARE_COMPLETION(vzmond_complete);
static int vzmond_helper(void *arg)
{
	char name[18];
	struct ve_struct *ve;

	ve = (struct ve_struct *)arg;
	snprintf(name, sizeof(name), "vzmond/%d", ve->veid);
	daemonize(name);
	env_cleanup(ve);
	module_put_and_exit(0);
}

static void do_pending_env_cleanups(void)
{
	int err;
	struct ve_struct *ve;

	spin_lock(&ve_cleanup_lock);
	while (1) {
		if (list_empty(&ve_cleanup_list) || need_resched())
			break;

		ve = list_first_entry(&ve_cleanup_list,
				struct ve_struct, cleanup_list);
		list_del(&ve->cleanup_list);
		spin_unlock(&ve_cleanup_lock);

		__module_get(THIS_MODULE);
		err = kernel_thread(vzmond_helper, (void *)ve, 0);
		if (err < 0) {
			env_cleanup(ve);
			module_put(THIS_MODULE);
		}

		spin_lock(&ve_cleanup_lock);
	}
	spin_unlock(&ve_cleanup_lock);
}

static inline int have_pending_cleanups(void)
{
	return !list_empty(&ve_cleanup_list);
}

static int vzmond(void *arg)
{
	set_current_state(TASK_INTERRUPTIBLE);

	while (!kthread_should_stop() || have_pending_cleanups()) {
		schedule();
		try_to_freeze();
		if (signal_pending(current))
			flush_signals(current);

		do_pending_env_cleanups();
		set_current_state(TASK_INTERRUPTIBLE);
		if (have_pending_cleanups())
			__set_current_state(TASK_RUNNING);
	}

	__set_task_state(current, TASK_RUNNING);
	complete_and_exit(&vzmond_complete, 0);
}

static int __init init_vzmond(void)
{
	ve_cleanup_thread = kthread_run(vzmond, NULL, "vzmond");
	if (IS_ERR(ve_cleanup_thread))
		return PTR_ERR(ve_cleanup_thread);
	else
		return 0;
}

static void fini_vzmond(void)
{
	kthread_stop(ve_cleanup_thread);
	WARN_ON(!list_empty(&ve_cleanup_list));
}

static void ve_devmnt_free(struct ve_devmnt *devmnt)
{
	if (!devmnt)
		return;

	kfree(devmnt->allowed_options);
	kfree(devmnt->hidden_options);
	kfree(devmnt);
}

static void free_ve_devmnts(struct ve_struct *ve)
{
	while (!list_empty(&ve->devmnt_list)) {
		struct ve_devmnt *devmnt;

		devmnt = list_first_entry(&ve->devmnt_list, struct ve_devmnt, link);
		list_del(&devmnt->link);
		ve_devmnt_free(devmnt);
	}
}

static void real_do_env_free(struct ve_struct *ve)
{
	VZTRACE("real_do_env_free\n");

	idr_destroy(&ve->_posix_timers_id);
	fini_ve_cgroups(ve);
	free_ve_tty_drivers(ve);
	free_ve_filesystems(ve);
	free_ve_cpustats(ve);
	free_ve_devmnts(ve);
	printk(KERN_INFO "CT: %d: stopped\n", VEID(ve));
	kfree_rcu(ve, rcu);

	module_put(THIS_MODULE);
}

/**********************************************************************
 **********************************************************************
 *
 * VE TTY handling
 *
 **********************************************************************
 **********************************************************************/

static struct tty_driver *alloc_ve_tty_driver(struct tty_driver *base,
					   struct ve_struct *ve)
{
	size_t size;
	struct tty_driver *driver;

	/* FIXME: make it a normal way (or wait till ms version) */

	driver = kmalloc(sizeof(struct tty_driver), GFP_KERNEL_UBC);
	if (!driver)
		goto out;

	memcpy(driver, base, sizeof(struct tty_driver));

	driver->driver_state = NULL;

	size = base->num * 3 * sizeof(void *);
	if (!(driver->flags & TTY_DRIVER_DEVPTS_MEM)) {
		void **p;
		p = kzalloc(size, GFP_KERNEL_UBC);
		if (!p)
			goto out_free;

		driver->ttys = (struct tty_struct **)p;
		driver->termios = (struct ktermios **)(p + driver->num);
		driver->termios_locked = (struct ktermios **)
			(p + driver->num * 2);
	} else {
		driver->ttys = NULL;
		driver->termios = NULL;
		driver->termios_locked = NULL;
	}

	driver->owner_env = ve;
	driver->flags |= TTY_DRIVER_INSTALLED;
	kref_init(&driver->kref);

	return driver;

out_free:
	kfree(driver);
out:
	return NULL;
}

static void free_ve_tty_driver(struct tty_driver *driver)
{
	if (!driver)
		return;

	clear_termios(driver);
	kfree(driver->ttys);
	kfree(driver);
}

static int alloc_ve_tty_drivers(struct ve_struct* ve)
{
#ifdef CONFIG_LEGACY_PTYS
	/* Traditional BSD devices */
	ve->pty_driver = alloc_ve_tty_driver(pty_driver, ve);
	if (!ve->pty_driver)
		goto out_mem;

	ve->pty_slave_driver = alloc_ve_tty_driver(pty_slave_driver, ve);
	if (!ve->pty_slave_driver)
		goto out_mem;

	ve->pty_driver->other       = ve->pty_slave_driver;
	ve->pty_slave_driver->other = ve->pty_driver;
#endif	
	return 0;

out_mem:
	free_ve_tty_drivers(ve);
	return -ENOMEM;
}

static void free_ve_tty_drivers(struct ve_struct* ve)
{
#ifdef CONFIG_LEGACY_PTYS
	free_ve_tty_driver(ve->pty_driver);
	free_ve_tty_driver(ve->pty_slave_driver);
	ve->pty_driver = ve->pty_slave_driver = NULL;
#endif	
}

static inline void __register_tty_driver(struct tty_driver *driver)
{
	list_add(&driver->tty_drivers, &tty_drivers);
}

static inline void __unregister_tty_driver(struct tty_driver *driver)
{
	if (!driver)
		return;
	list_del(&driver->tty_drivers);
}

static int register_ve_tty_drivers(struct ve_struct* ve)
{
	mutex_lock(&tty_mutex);
#ifdef CONFIG_LEGACY_PTYS
	__register_tty_driver(ve->pty_driver);
	__register_tty_driver(ve->pty_slave_driver);
#endif	
	mutex_unlock(&tty_mutex);

	return 0;
}

static void unregister_ve_tty_drivers(struct ve_struct* ve)
{
	VZTRACE("unregister_ve_tty_drivers\n");

	mutex_lock(&tty_mutex);
#ifdef CONFIG_LEGACY_PTYS
	__unregister_tty_driver(ve->pty_driver);
	__unregister_tty_driver(ve->pty_slave_driver);
#endif
	mutex_unlock(&tty_mutex);
}

static int init_ve_tty_drivers(struct ve_struct *ve)
{
	int err;

	if ((err = alloc_ve_tty_drivers(ve)))
		goto err_ttyalloc;
	if ((err = register_ve_tty_drivers(ve)))
		goto err_ttyreg;
	return 0;

err_ttyreg:
	free_ve_tty_drivers(ve);
err_ttyalloc:
	return err;
}

static void fini_ve_tty_drivers(struct ve_struct *ve)
{
	unregister_ve_tty_drivers(ve);
	free_ve_tty_drivers(ve);
}

static void fini_ve_vtty(struct ve_struct *ve)
{
	int minor;

	for (minor = 0 ; minor <= MAX_NR_VTTY ; minor++)
		device_destroy(ve->tty_class, MKDEV(TTY_MAJOR, minor));
}

static int init_ve_vtty(struct ve_struct *ve)
{
	int err, minor;
	struct device *dev;

	for (minor = 0 ; minor <= MAX_NR_VTTY ; minor++) {
		err = set_device_perms_ve(ve, S_IFCHR | VE_USE_MAJOR | VE_USE_MINOR,
				MKDEV(TTY_MAJOR, minor), 06);
		if (err)
			goto out;
		dev = device_create(ve->tty_class, NULL,
				MKDEV(TTY_MAJOR, minor), NULL, "tty%d", minor);
		err = PTR_ERR(dev);
		if (IS_ERR(dev))
			goto out;
	}

	return 0;

out:
	fini_ve_vtty(ve);
	return err;
}

/*
 * Free the termios and termios_locked structures because
 * we don't want to get memory leaks when modular tty
 * drivers are removed from the kernel.
 */
static void clear_termios(struct tty_driver *driver)
{
	int i;
	struct ktermios *tp;

	if (driver->termios == NULL)
		return;
	for (i = 0; i < driver->num; i++) {
		tp = driver->termios[i];
		if (tp) {
			driver->termios[i] = NULL;
			kfree(tp);
		}
		tp = driver->termios_locked[i];
		if (tp) {
			driver->termios_locked[i] = NULL;
			kfree(tp);
		}
	}
}


/**********************************************************************
 **********************************************************************
 *
 * Pieces of VE network
 *
 **********************************************************************
 **********************************************************************/

#ifdef CONFIG_NET
#include <asm/uaccess.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/route.h>
#include <net/ip_fib.h>
#endif

static int ve_dev_add(envid_t veid, char *dev_name)
{
	struct net_device *dev;
	struct ve_struct *dst_ve;
	struct net *dst_net;
	int err = -ESRCH;

	dst_ve = get_ve_by_id(veid);
	if (dst_ve == NULL)
		goto out;

	dst_net = dst_ve->ve_netns;

	rtnl_lock();
	read_lock(&dev_base_lock);
	dev = __dev_get_by_name(&init_net, dev_name);
	read_unlock(&dev_base_lock);
	if (dev == NULL)
		goto out_unlock;

	err = __dev_change_net_namespace(dev, dst_net, dev_name,
					 get_exec_ub_top());
out_unlock:
	rtnl_unlock();
	real_put_ve(dst_ve);

	if (dev == NULL)
		printk(KERN_WARNING "%s: device %s not found\n",
			__func__, dev_name);
out:
	return err;
}

static int ve_dev_del(envid_t veid, char *dev_name)
{
	struct net_device *dev;
	struct ve_struct *src_ve;
	struct net *src_net;
	int err = -ESRCH;

	src_ve = get_ve_by_id(veid);
	if (src_ve == NULL)
		goto out;

	src_net = src_ve->ve_netns;

	rtnl_lock();

	read_lock(&dev_base_lock);
	dev = __dev_get_by_name(src_net, dev_name);
	read_unlock(&dev_base_lock);
	if (dev == NULL)
		goto out_unlock;

	err = __dev_change_net_namespace(dev, &init_net, dev_name,
					 netdev_bc(dev)->owner_ub);
out_unlock:
	rtnl_unlock();
	real_put_ve(src_ve);

	if (dev == NULL)
		printk(KERN_WARNING "%s: device %s not found\n",
			__func__, dev_name);
out:
	return err;
}

int real_ve_dev_map(envid_t veid, int op, char *dev_name)
{
	if (!capable_setveid())
		return -EPERM;
	switch (op) {
	case VE_NETDEV_ADD:
		return ve_dev_add(veid, dev_name);
	case VE_NETDEV_DEL:
		return ve_dev_del(veid, dev_name);
	default:
		return -EINVAL;
	}
}

/**********************************************************************
 **********************************************************************
 *
 * VE information via /proc
 *
 **********************************************************************
 **********************************************************************/
#ifdef CONFIG_PROC_FS
#if BITS_PER_LONG == 32
#define VESTAT_LINE_WIDTH (6 * 11 + 6 * 21)
#define VESTAT_LINE_FMT "%10u %10lu %10lu %10lu %10Lu %20Lu %20Lu %20Lu %20Lu %20Lu %20Lu %10lu\n"
#define VESTAT_HEAD_FMT "%10s %10s %10s %10s %10s %20s %20s %20s %20s %20s %20s %10s\n"
#else
#define VESTAT_LINE_WIDTH (12 * 21)
#define VESTAT_LINE_FMT "%20u %20lu %20lu %20lu %20Lu %20Lu %20Lu %20Lu %20Lu %20Lu %20Lu %20lu\n"
#define VESTAT_HEAD_FMT "%20s %20s %20s %20s %20s %20s %20s %20s %20s %20s %20s %20s\n"
#endif

static int vestat_seq_show(struct seq_file *m, void *v)
{
	struct list_head *entry;
	struct ve_struct *ve;
	struct ve_struct *curve;
	int ret;
	unsigned long user_ve, nice_ve, system_ve;
	unsigned long long uptime;
	u64 uptime_cycles, idle_time, strv_time, used;
	struct kernel_cpustat kstat;

	entry = (struct list_head *)v;
	ve = list_entry(entry, struct ve_struct, ve_list);

	curve = get_exec_env();
	if (entry == ve_list_head.next ||
	    (!ve_is_super(curve) && ve == curve)) {
		/* print header */
		seq_printf(m, "%-*s\n",
			VESTAT_LINE_WIDTH - 1,
			"Version: 2.2");
		seq_printf(m, VESTAT_HEAD_FMT, "VEID",
					"user", "nice", "system",
					"uptime", "idle",
					"strv", "uptime", "used",
					"maxlat", "totlat", "numsched");
	}

	if (ve == get_ve0())
		return 0;

	ret = fairsched_get_cpu_stat(ve->veid, &kstat);
	if (ret)
		return ret;

	strv_time = 0;
	user_ve = kstat.cpustat[USER];
	nice_ve = kstat.cpustat[NICE];
	system_ve = kstat.cpustat[SYSTEM];
	used = kstat.cpustat[USED];
	idle_time = kstat.cpustat[IDLE];

	uptime_cycles = ve_get_uptime(ve);
	uptime = get_jiffies_64() - ve->start_jiffies;

	seq_printf(m, VESTAT_LINE_FMT, ve->veid,
				user_ve, nice_ve, system_ve,
				(unsigned long long)uptime,
				(unsigned long long)idle_time, 
				(unsigned long long)strv_time,
				(unsigned long long)uptime_cycles,
				(unsigned long long)used,
				(unsigned long long)ve->sched_lat_ve.last.maxlat,
				(unsigned long long)ve->sched_lat_ve.last.totlat,
				ve->sched_lat_ve.last.count);
	return 0;
}

void *ve_seq_start(struct seq_file *m, loff_t *pos)
{
	struct ve_struct *curve;

	curve = get_exec_env();
	mutex_lock(&ve_list_lock);
	if (!ve_is_super(curve)) {
		if (*pos != 0)
			return NULL;
		return curve;
	}

	return seq_list_start(&ve_list_head, *pos);
}
EXPORT_SYMBOL(ve_seq_start);

void *ve_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	if (!ve_is_super(get_exec_env()))
		return NULL;
	else
		return seq_list_next(v, &ve_list_head, pos);
}
EXPORT_SYMBOL(ve_seq_next);

void ve_seq_stop(struct seq_file *m, void *v)
{
	mutex_unlock(&ve_list_lock);
}
EXPORT_SYMBOL(ve_seq_stop);

static struct seq_operations vestat_seq_op = {
        .start	= ve_seq_start,
        .next	= ve_seq_next,
        .stop	= ve_seq_stop,
        .show	= vestat_seq_show
};

static int vestat_open(struct inode *inode, struct file *file)
{
        return seq_open(file, &vestat_seq_op);
}

static struct file_operations proc_vestat_operations = {
        .open	 = vestat_open,
        .read	 = seq_read,
        .llseek	 = seq_lseek,
        .release = seq_release
};

static struct seq_operations devperms_seq_op = {
	.start  = ve_seq_start,
	.next   = ve_seq_next,
	.stop   = ve_seq_stop,
	.show   = devperms_seq_show,
};

static int devperms_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &devperms_seq_op);
}

static struct file_operations proc_devperms_ops = {
	.open           = devperms_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release        = seq_release,
};

static int vz_version_show(struct seq_file *file, void* v)
{
	static const char ver[] = VZVERSION "\n";

	return seq_puts(file, ver);
}

static int vz_version_open(struct inode *inode, struct file *file)
{
	return single_open(file, vz_version_show, NULL);
}

static struct file_operations proc_vz_version_oparations = {
	.open    = vz_version_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
};

/* /proc/vz/veinfo */

static ve_seq_print_t veaddr_seq_print_cb;

void vzmon_register_veaddr_print_cb(ve_seq_print_t cb)
{
	rcu_assign_pointer(veaddr_seq_print_cb, cb);
}
EXPORT_SYMBOL(vzmon_register_veaddr_print_cb);

void vzmon_unregister_veaddr_print_cb(ve_seq_print_t cb)
{
	rcu_assign_pointer(veaddr_seq_print_cb, NULL);
	synchronize_rcu();
}
EXPORT_SYMBOL(vzmon_unregister_veaddr_print_cb);

static int veinfo_seq_show(struct seq_file *m, void *v)
{
	struct ve_struct *ve;
	ve_seq_print_t veaddr_seq_print;

	ve = list_entry((struct list_head *)v, struct ve_struct, ve_list);

	seq_printf(m, "%10u %5u %5u", ve->veid, ve->class_id, ve->pcounter);

	rcu_read_lock();
	veaddr_seq_print = rcu_dereference(veaddr_seq_print_cb);
	if (veaddr_seq_print)
		veaddr_seq_print(m, ve);
	rcu_read_unlock();

	seq_putc(m, '\n');
	return 0;
}

static struct seq_operations veinfo_seq_op = {
	.start	= ve_seq_start,
	.next	=  ve_seq_next,
	.stop	=  ve_seq_stop,
	.show	=  veinfo_seq_show,
};

static int veinfo_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &veinfo_seq_op);
}

static struct file_operations proc_veinfo_operations = {
	.open		= veinfo_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static int __init init_vecalls_proc(void)
{
	struct proc_dir_entry *de;

	de = proc_create("vestat", S_IFREG | S_IRUSR, glob_proc_vz_dir,
			&proc_vestat_operations);
	if (!de)
		printk(KERN_WARNING "VZMON: can't make vestat proc entry\n");

	de = proc_create("devperms", S_IFREG | S_IRUSR, proc_vz_dir,
			&proc_devperms_ops);
	if (!de)
		printk(KERN_WARNING "VZMON: can't make devperms proc entry\n");

	de = proc_create("version", S_IFREG | S_IRUGO, proc_vz_dir,
			&proc_vz_version_oparations);
	if (!de)
		printk(KERN_WARNING "VZMON: can't make version proc entry\n");

	de = proc_create("veinfo", S_IFREG | S_IRUSR, glob_proc_vz_dir,
			&proc_veinfo_operations);
	if (!de)
		printk(KERN_WARNING "VZMON: can't make veinfo proc entry\n");

	return 0;
}

static void fini_vecalls_proc(void)
{
	remove_proc_entry("version", proc_vz_dir);
	remove_proc_entry("devperms", proc_vz_dir);
	remove_proc_entry("vestat", glob_proc_vz_dir);
	remove_proc_entry("veinfo", glob_proc_vz_dir);
}
#else
#define init_vecalls_proc()	(0)
#define fini_vecalls_proc()	do { } while (0)
#endif /* CONFIG_PROC_FS */

static int init_ve_osrelease(struct ve_struct *ve, char *release)
{
	if (!release)
		return -ENODATA;

	if (strlen(release) >= sizeof(ve->ve_ns->uts_ns->name.release))
		return -EMSGSIZE;

	down_write(&uts_sem);
	strcpy(ve->ve_ns->uts_ns->name.release, release);
	up_write(&uts_sem);
	init_ve_smnfct(ve);

	return 0;
}

static struct proc_dir_entry *ve_proc_mkdir(struct ve_struct *ve, char *name,
						struct proc_dir_entry *parent,
						struct list_head *list)
{
	struct proc_dir_entry *de;
	struct ve_proc_dir_entry *ve_de;

	ve_de = kmalloc(sizeof(struct ve_proc_dir_entry *), GFP_KERNEL);
	if (!ve_de)
		return ERR_PTR(-ENOMEM);
	
	de = proc_mkdir(name, parent);
	if (!de) {
		kfree(ve_de);
		return ERR_PTR(-EINVAL);
	}

	ve_de->de = de;
	ve_de->ve = ve;
	list_add(&ve_de->list, list);

	return de;
}

static struct proc_dir_entry * ve_proc_mkdir_recursive(struct ve_struct *ve,
				char *path, struct list_head *list)
{
	struct proc_dir_entry *parent, *de;
	char *name, *end;
	INIT_LIST_HEAD(list);

	name = path;
	parent = ve->proc_root;
	while (1) {
		end = strchr(name, '/');
		if (end)
			*end = '\0';
		de = __proc_lookup(parent, name, strlen(name));
		if (de == NULL) {
			parent = ve_proc_mkdir(ve, name, parent, list);
			if (IS_ERR(parent))
				goto out_err;
		} else
			parent = de;
		if (end)
			*end = '/';
		else
			break;
		name = end + 1;
	}
	return parent;
out_err:
	cleanup_ve_proc_entries(ve, list);
	return parent;
}

/*
 * data is a buffer with two strings, the first is name of a new entry and
 * the second is path to the target entry.
 */
static int ve_configure_make_proc_link(struct ve_struct *ve, mode_t mode,
					unsigned int size, char *data)
{
	struct proc_dir_entry *de, *link_de, *parent;
	struct ve_proc_dir_entry *ve_de;
	char *link, *name, *end;
	LIST_HEAD(list);
	int ret = 0;
	
	if (data[size-1] != '\0')
		return -EINVAL;

	name = data;
	link = strchr(data, '\0');
	if (link == data + size-1)
		return -EINVAL;
	link++;

	down(&ve_proc_entries_lock);
	parent = ve->proc_root;
	end = strrchr(name, '/');
	if (end) {
		*end = '\0';
		parent = ve_proc_mkdir_recursive(ve, name, &list);
		*end = '/';
		if (IS_ERR(parent)) {
			ret = PTR_ERR(parent);
			goto out_unlock;
		}
		name = end + 1;
	}

	de = __proc_lookup(parent, name, strlen(name));
	if (de) {
		ret = -EEXIST;
		goto out_unlock;
	}

	ve_de = kmalloc(sizeof(struct ve_proc_dir_entry *), GFP_KERNEL);
	if (!ve_de) {
		ret = -ENOMEM;
		goto out_dir;
	}

	link_de = proc_lookup_entry(link, get_ve0()->proc_root);
	if (!link_de) {
		ret = -ENOENT;
		goto out_free;
	}
	
	de = create_proc_hardlink(name, mode, parent, link_de);
	if (!de) {
		ret = -EINVAL;
		goto out_free;
	}

	ve_de->de = de;
	ve_de->ve = ve;
	list_splice_init(&list, &ve_proc_entries);
	list_add(&ve_de->list, &ve_proc_entries);
out_free:
	if (ret)
		kfree(ve_de);
out_dir:
	if (ret)
		cleanup_ve_proc_entries(ve, &list);
out_unlock:
	up(&ve_proc_entries_lock);	
	return ret;
}

/*
 * 'data' for VE_CONFIGURE_MOUNT_OPTIONS is a zero-terminated string
 * consisting of substrings separated by MNTOPT_DELIM.
 */
#define MNTOPT_DELIM ';'

/*
 * Each substring has the form of "<type> <comma-separated-list-of-options>"
 * where types are:
 */
enum {
	MNTOPT_HIDDEN = 1,
	MNTOPT_ALLOWED = 2,
};

/*
 * 'ptr' points to the first character of buffer to parse
 * 'endp' points to the last character of buffer to parse
 */
static int ve_parse_mount_options(char *ptr, char *endp,
				  struct ve_devmnt *devmnt)
{
	while (*ptr) {
		char *delim = strchr(ptr, MNTOPT_DELIM) ? : endp;
		char *space = strchr(ptr, ' ');
		int type;
		char *options, *p;
		int options_size = delim - space;
		char **opts_pp = NULL; /* where to store 'options' */

		if (delim == ptr || !space || options_size <= 1)
			return -EINVAL;

		type = simple_strtoul(ptr, &p, 10);
		if (p != space)
			return -EINVAL;

	        options = kmalloc(options_size, GFP_KERNEL);
		if (!options)
			return -ENOMEM;

		strncpy(options, space + 1, options_size - 1);
		options[options_size - 1] = 0;

		switch (type) {
		case MNTOPT_ALLOWED:
			opts_pp = &devmnt->allowed_options;
			break;
		case MNTOPT_HIDDEN:
			opts_pp = &devmnt->hidden_options;
			break;
		};

		/* wrong type or already set */
		if (!opts_pp || *opts_pp) {
			kfree(options);
			return -EINVAL;
		}

		*opts_pp = options;

		if (!*delim)
			break;

		ptr = delim + 1;
	}

	return 0;
}

static int ve_configure_mount_options(struct ve_struct *ve, unsigned int val,
				      unsigned int size, char *data)
{
	struct ve_devmnt *devmnt, *old;
	int err;

	if (size <= 1)
		return -EINVAL; /* TODO: remove devmnt from list by dev */

	data[size - 1] = 0;

	devmnt = kzalloc(sizeof(*devmnt), GFP_KERNEL);
	if (!devmnt)
		return -ENOMEM;

	devmnt->dev = new_decode_dev(val);

	err = ve_parse_mount_options(data, data + size - 1, devmnt);
	if (err) {
		ve_devmnt_free(devmnt);
		return err;
	}

	mutex_lock(&ve->devmnt_mutex);
	list_for_each_entry(old, &ve->devmnt_list, link) {
		/* Delete old devmnt */
		if (old->dev == devmnt->dev) {
			list_del(&old->link);
			ve_devmnt_free(old);
			break;
		}
	}
	list_add(&devmnt->link, &ve->devmnt_list);
	mutex_unlock(&ve->devmnt_mutex);

	return 0;
}

static int ve_configure(envid_t veid, unsigned int key,
			unsigned int val, unsigned int size, char *data)
{
	struct ve_struct *ve;
	int err = -ENOKEY;

	switch(key) {
	case VE_CONFIGURE_OPEN_TTY:
		return vtty_open_master(veid, val);
	}

	ve = get_ve_by_id(veid);
	if (!ve)
		return -EINVAL;

	switch(key) {
	case VE_CONFIGURE_OS_RELEASE:
		err = init_ve_osrelease(ve, data); 
		break;
	case VE_CONFIGURE_CREATE_PROC_LINK:
		err = ve_configure_make_proc_link(ve, val, size, data);
		break;
	case VE_CONFIGURE_MOUNT_OPTIONS:
		err = ve_configure_mount_options(ve, val, size, data);
		break;
 	}

	real_put_ve(ve);
 	return err;
}

static int ve_configure_ioctl(struct vzctl_ve_configure *arg)
{
	int err;
	struct vzctl_ve_configure s;
	char *data = NULL;

	err = -EFAULT;
	if (copy_from_user(&s, (void __user *)arg, sizeof(s)))
		goto out;
	if (s.size) {
		if (s.size > PAGE_SIZE)
			return -EMSGSIZE;

		data = kzalloc(s.size + 1, GFP_KERNEL);
		if (unlikely(!data))
			return -ENOMEM;

		if (copy_from_user(data, (void __user *) &arg->data, s.size))
			goto out;
	}
	err = ve_configure(s.veid, s.key, s.val, s.size, data);
out:
	kfree(data);
	return err;
}

/**********************************************************************
 **********************************************************************
 *
 * User ctl
 *
 **********************************************************************
 **********************************************************************/

int vzcalls_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int err;

	err = -ENOTTY;
	switch(cmd) {
	    case VZCTL_MARK_ENV_TO_DOWN: {
		        /* Compatibility issue */
		        err = 0;
		}
		break;
	    case VZCTL_SETDEVPERMS: {
			/* Device type was mistakenly declared as dev_t
			 * in the old user-kernel interface.
			 * That's wrong, dev_t is a kernel internal type.
			 * I use `unsigned' not having anything better in mind.
			 * 2001/08/11  SAW  */
			struct vzctl_setdevperms s;
			err = -EFAULT;
			if (copy_from_user(&s, (void __user *)arg, sizeof(s)))
				break;
			err = real_setdevperms(s.veid, s.type,
					new_decode_dev(s.dev), s.mask);
		}
		break;
#ifdef CONFIG_INET
	    case VZCTL_VE_NETDEV: {
			struct vzctl_ve_netdev d;
			char *s;
			err = -EFAULT;
			if (copy_from_user(&d, (void __user *)arg, sizeof(d)))
				break;
			err = -ENOMEM;
			s = kmalloc(IFNAMSIZ+1, GFP_KERNEL);
			if (s == NULL)
				break;
			err = -EFAULT;
			if (strncpy_from_user(s, d.dev_name, IFNAMSIZ) > 0) {
				s[IFNAMSIZ] = 0;
				err = real_ve_dev_map(d.veid, d.op, s);
			}
			kfree(s);
		}
		break;
#endif
	    case VZCTL_ENV_CREATE: {
			struct vzctl_env_create s;
			err = -EFAULT;
			if (copy_from_user(&s, (void __user *)arg, sizeof(s)))
				break;
			err = real_env_create(s.veid, s.flags, s.class_id,
				NULL, 0);
		}
		break;
	    case VZCTL_ENV_CREATE_DATA: {
			struct vzctl_env_create_data s;
			env_create_param_t *data;
			err = -EFAULT;
			if (copy_from_user(&s, (void __user *)arg, sizeof(s)))
				break;
			err=-EINVAL;
			if (s.datalen < VZCTL_ENV_CREATE_DATA_MINLEN ||
			    s.datalen > VZCTL_ENV_CREATE_DATA_MAXLEN ||
			    s.data == 0)
				break;
			err = -ENOMEM;
			data = kzalloc(sizeof(*data), GFP_KERNEL);
			if (!data)
				break;

			err = -EFAULT;
			if (copy_from_user(data, (void __user *)s.data,
						s.datalen))
				goto free_data;
			err = real_env_create(s.veid, s.flags, s.class_id,
				data, s.datalen);
free_data:
			kfree(data);
		}
		break;
	    case VZCTL_GET_CPU_STAT: {
			struct vzctl_cpustatctl s;
			err = -EFAULT;
			if (copy_from_user(&s, (void __user *)arg, sizeof(s)))
				break;
			err = ve_get_cpu_stat(s.veid, s.cpustat);
		}
		break;
	    case VZCTL_VE_MEMINFO: {
			struct vzctl_ve_meminfo s;
			err = -EFAULT;
			if (copy_from_user(&s, (void __user *)arg, sizeof(s)))
				break;
			err = ve_set_meminfo(s.veid, s.val);
		}
		break;
	    case VZCTL_VE_CONFIGURE:
		err = ve_configure_ioctl((struct vzctl_ve_configure *)arg);
		break;
	}
	return err;
}

#ifdef CONFIG_COMPAT
int compat_vzcalls_ioctl(struct file *file, unsigned int cmd,
		unsigned long arg)
{
	int err;

	switch(cmd) {
	case VZCTL_GET_CPU_STAT: {
		/* FIXME */
	}
	case VZCTL_COMPAT_ENV_CREATE_DATA: {
		struct compat_vzctl_env_create_data cs;
		struct vzctl_env_create_data __user *s;

		s = compat_alloc_user_space(sizeof(*s));
		err = -EFAULT;
		if (copy_from_user(&cs, (void *)arg, sizeof(cs)))
			break;

		if (put_user(cs.veid, &s->veid) ||
		    put_user(cs.flags, &s->flags) ||
		    put_user(cs.class_id, &s->class_id) ||
		    put_user(compat_ptr(cs.data), &s->data) ||
		    put_user(cs.datalen, &s->datalen))
			break;
		err = vzcalls_ioctl(file, VZCTL_ENV_CREATE_DATA,
						(unsigned long)s);
		break;
	}
#ifdef CONFIG_NET
	case VZCTL_COMPAT_VE_NETDEV: {
		struct compat_vzctl_ve_netdev cs;
		struct vzctl_ve_netdev __user *s;

		s = compat_alloc_user_space(sizeof(*s));
		err = -EFAULT;
		if (copy_from_user(&cs, (void *)arg, sizeof(cs)))
			break;

		if (put_user(cs.veid, &s->veid) ||
		    put_user(cs.op, &s->op) ||
		    put_user(compat_ptr(cs.dev_name), &s->dev_name))
			break;
		err = vzcalls_ioctl(file, VZCTL_VE_NETDEV, (unsigned long)s);
		break;
	}
#endif
	case VZCTL_COMPAT_VE_MEMINFO: {
		struct compat_vzctl_ve_meminfo cs;
		err = -EFAULT;
		if (copy_from_user(&cs, (void *)arg, sizeof(cs)))
			break;
		err = ve_set_meminfo(cs.veid, cs.val);
		break;
	}
	default:
		err = vzcalls_ioctl(file, cmd, arg);
		break;
	}
	return err;
}
#endif

static struct vzioctlinfo vzcalls = {
	.type		= VZCTLTYPE,
	.ioctl		= vzcalls_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= compat_vzcalls_ioctl,
#endif
	.owner		= THIS_MODULE,
};


/**********************************************************************
 **********************************************************************
 *
 * Init/exit stuff
 *
 **********************************************************************
 **********************************************************************/

static inline __init int init_vecalls_ioctls(void)
{
	vzioctl_register(&vzcalls);
	return 0;
}

static inline void fini_vecalls_ioctls(void)
{
	vzioctl_unregister(&vzcalls);
}

#ifdef CONFIG_SYSCTL
static struct ctl_table_header *table_header;
static const int zero, one = 1;
static ctl_table kernel_table[] = {
	{
		.procname	= "ve_allow_kthreads",
		.data		= &ve_allow_kthreads,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "ve_smnfct_enabled",
		.data		= &ve_smnfct_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one,
	},
	{ 0 }
};

static ctl_table root_table[] =  {
	{CTL_KERN, "kernel",  NULL, 0, 0555, kernel_table},
	{ 0 }
};

static int init_vecalls_sysctl(void)
{
	table_header = register_sysctl_table(root_table);
	if (!table_header)
		return -ENOMEM ;
	return 0;
}

static void fini_vecalls_sysctl(void)
{
	unregister_sysctl_table(table_header);
} 
#else
static int init_vecalls_sysctl(void) { return 0; }
static void fini_vecalls_sysctl(void) { ; }
#endif

static int __init vecalls_init(void)
{
	int err;

	err = init_vecalls_cgroups();
	if (err)
		goto out_cgroups;

	err = init_vecalls_sysctl();
	if (err)
		goto out_vzmond;

	err = init_vzmond();
	if (err < 0)
		goto out_sysctl;

	err = init_vecalls_proc();
	if (err < 0)
		goto out_proc;

	err = init_vecalls_ioctls();
	if (err < 0)
		goto out_ioctls;

	/* We can easy dereference this hook if VE is running
	 * because in this case vzmon refcount > 0
	 */
	do_ve_enter_hook = do_env_enter;
	/*
	 * This one can also be dereferenced since not freed
	 * VE holds reference on module
	 */
	do_env_free_hook = real_do_env_free;

	return 0;

out_ioctls:
	fini_vecalls_proc();
out_proc:
	fini_vzmond();
out_sysctl:
	fini_vecalls_sysctl();
out_vzmond:
	fini_vecalls_cgroups();
out_cgroups:
	return err;
}

static void __exit vecalls_exit(void)
{
	do_env_free_hook = NULL;
	do_ve_enter_hook = NULL;
	fini_vecalls_ioctls();
	fini_vecalls_proc();
	fini_vzmond();
	fini_vecalls_sysctl();
	fini_vecalls_cgroups();
}

MODULE_AUTHOR("Virtuozzo");
MODULE_DESCRIPTION("Virtuozzo Control");
MODULE_LICENSE("GPL v2");

module_init(vecalls_init)
module_exit(vecalls_exit)
