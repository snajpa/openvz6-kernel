/*
 *  linux/kernel/ve/ve.c
 *
 *  Copyright (C) 2000-2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

/*
 * 've.c' helper file performing VE sub-system initialization
 */

#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/capability.h>
#include <linux/ve.h>
#include <linux/smp_lock.h>
#include <linux/init.h>
#include <linux/freezer.h>

#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/sys.h>
#include <linux/kdev_t.h>
#include <linux/termios.h>
#include <linux/tty_driver.h>
#include <linux/netdevice.h>
#include <linux/utsname.h>
#include <linux/proc_fs.h>
#include <linux/kernel_stat.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/ve_proto.h>
#include <linux/devpts_fs.h>
#include <linux/user_namespace.h>
#include <linux/init_task.h>
#include <linux/mutex.h>

#include <linux/vzcalluser.h>

unsigned long vz_rstamp = 0x37e0f59d;
EXPORT_SYMBOL(vz_rstamp);

#ifdef CONFIG_MODULES
struct module no_module = { .state = MODULE_STATE_GOING };
EXPORT_SYMBOL(no_module);
#endif

#if defined(CONFIG_VE_CALLS_MODULE) || defined(CONFIG_VE_CALLS)
void (*do_env_free_hook)(struct ve_struct *ve);
EXPORT_SYMBOL(do_env_free_hook);

void do_env_free(struct ve_struct *env)
{
	BUG_ON(env->pcounter > 0);
	BUG_ON(env->is_running);

	preempt_disable();
	do_env_free_hook(env);
	preempt_enable();
}
EXPORT_SYMBOL(do_env_free);
#endif

int (*do_ve_enter_hook)(struct ve_struct *ve, unsigned int flags);
EXPORT_SYMBOL(do_ve_enter_hook);

struct ve_struct ve0 = {
	.counter		= ATOMIC_INIT(1),
	.pcounter		= 1,
	.ve_list		= LIST_HEAD_INIT(ve0.ve_list),
	.vetask_lh		= LIST_HEAD_INIT(ve0.vetask_lh),
	.vetask_auxlist		= LIST_HEAD_INIT(ve0.vetask_auxlist),
	.start_jiffies		= INITIAL_JIFFIES,
	.ve_ns			= &init_nsproxy,
	.ve_netns		= &init_net,
	.user_ns		= &init_user_ns,
	.is_running		= 1,
	.op_sem			= __RWSEM_INITIALIZER(ve0.op_sem),
#ifdef CONFIG_VE_IPTABLES
	.ipt_mask		= VE_IP_ALL,	/* everything is allowed */
#endif
	.features		= -1,
	.meminfo_val		= VE_MEMINFO_SYSTEM,
	._randomize_va_space	=
#ifdef CONFIG_COMPAT_BRK
					1,
#else
					2,
#endif
	.proc_fstype		= &proc_fs_type,
	.devices		= LIST_HEAD_INIT(ve0.devices),
	.init_cred		= &init_cred,
	.fsync_enable		= FSYNC_FILTERED,
	.sync_mutex		= __MUTEX_INITIALIZER(ve0.sync_mutex),
	.arp_neigh_entries	= ATOMIC_INIT(0),
	.nd_neigh_entries	= ATOMIC_INIT(0),
	.mnt_nr			= ATOMIC_INIT(0),
	.mnt_poll		= __WAIT_QUEUE_HEAD_INITIALIZER(ve0.mnt_poll),
	.mnt_event		= 0,
	.aio_nr			= 0,
	.aio_max_nr		= AIO_MAX_NR_DEFAULT,
	.netns_nr		= ATOMIC_INIT(INT_MAX),
};

EXPORT_SYMBOL(ve0);

LIST_HEAD(ve_list_head);
DEFINE_MUTEX(ve_list_lock);

struct ve_struct *__find_ve_by_id(envid_t veid)
{
	struct ve_struct *ve;

	for_each_ve(ve) {
		if (ve->veid == veid)
			return ve;
	}
	return NULL;
}
EXPORT_SYMBOL(__find_ve_by_id);

struct ve_struct *get_ve_by_id(envid_t veid)
{
	struct ve_struct *ve;

	rcu_read_lock();
	ve = __find_ve_by_id(veid);
	if (!ve || !atomic_inc_not_zero(&ve->counter))
		ve = NULL;
	rcu_read_unlock();
	return ve;
}
EXPORT_SYMBOL(get_ve_by_id);

LIST_HEAD(ve_cleanup_list);
DEFINE_SPINLOCK(ve_cleanup_lock);
struct task_struct *ve_cleanup_thread;

EXPORT_SYMBOL(ve_list_lock);
EXPORT_SYMBOL(ve_list_head);
EXPORT_SYMBOL(ve_cleanup_lock);
EXPORT_SYMBOL(ve_cleanup_list);
EXPORT_SYMBOL(ve_cleanup_thread);

static DEFINE_PER_CPU(struct kstat_lat_pcpu_snap_struct, ve0_lat_stats);

void init_ve0(void)
{
	struct ve_struct *ve;

	ve = get_ve0();
	ve->sched_lat_ve.cur = &per_cpu_var(ve0_lat_stats);
	list_add_rcu(&ve->ve_list, &ve_list_head);
	INIT_LIST_HEAD(&ve->_kthread_create_list);
	spin_lock_init(&ve->aio_nr_lock);
}

void ve_cleanup_schedule(struct ve_struct *ve)
{
	BUG_ON(ve_cleanup_thread == NULL);

	spin_lock(&ve_cleanup_lock);
	list_add_tail(&ve->cleanup_list, &ve_cleanup_list);
	spin_unlock(&ve_cleanup_lock);

	wake_up_process(ve_cleanup_thread);
}

int ve_freeze(struct ve_struct *env)
{
	int err;

	down_write(&env->op_sem);
	err = -ESRCH;
	if (!env->is_running)
		goto out;
	err = -EBUSY;
	if (env->is_locked)
		goto out;
	env->is_locked = 1;
	up_write(&env->op_sem);

	err = freezer_change_state(env->ve_cgroup, CGROUP_FROZEN);
	if (err)
		ve_thaw(env);

	return err;

out:
	up_write(&env->op_sem);
	return err;
}
EXPORT_SYMBOL(ve_freeze);

void ve_thaw(struct ve_struct *env)
{
	freezer_change_state(env->ve_cgroup, CGROUP_THAWED);

	down_write(&env->op_sem);
	WARN_ON(!env->is_locked);
	env->is_locked = 0;
	up_write(&env->op_sem);
}
EXPORT_SYMBOL(ve_thaw);
