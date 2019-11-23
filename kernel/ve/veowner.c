/*
 *  kernel/ve/veowner.c
 *
 *  Copyright (C) 2000-2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#include <linux/sched.h>
#include <linux/ve.h>
#include <linux/ve_proto.h>
#include <linux/ipc.h>
#include <linux/fs_struct.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/delay.h>
#include <linux/vmalloc.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/inetdevice.h>
#include <linux/pid_namespace.h>
#include <linux/xattr.h>
#include <asm/system.h>
#include <asm/io.h>

#include <net/tcp.h>

/*
 * ------------------------------------------------------------------------
 * proc entries
 * ------------------------------------------------------------------------
 */

#ifdef CONFIG_PROC_FS
struct proc_dir_entry *proc_vz_dir;
EXPORT_SYMBOL(proc_vz_dir);

struct proc_dir_entry *glob_proc_vz_dir;
EXPORT_SYMBOL(glob_proc_vz_dir);

static void prepare_proc(void)
{
	proc_vz_dir = proc_mkdir("vz", NULL);
	if (!proc_vz_dir)
		panic("Can't create /proc/vz dir\n");

	glob_proc_vz_dir = proc_mkdir("vz", &glob_proc_root);
	if (!proc_vz_dir)
		panic("Can't create /proc/vz dir\n");
	proc_create("container", S_IFDIR|S_IRUSR|S_IXUSR, proc_vz_dir, NULL);
}
#endif

/*
 * ------------------------------------------------------------------------
 * OpenVZ sysctl
 * ------------------------------------------------------------------------
 */
int ve_xattr_policy = VE_XATTR_POLICY_ACCEPT;
static int ve_area_access_check;

static struct ctl_table vz_fs_table[] = {
	{
		.procname	= "ve-area-access-check",
		.data		= &ve_area_access_check,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "ve-xattr-policy",
		.data		= &ve_xattr_policy,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "fsync-enable",
		.extra1		= (void *)offsetof(struct ve_struct, fsync_enable),
		.maxlen		= sizeof(int),
		.mode		= 0644 | S_ISVTX,
		.proc_handler	= &proc_dointvec,
	},
	{ 0 }
};

static struct ctl_path fs_path[] = {
	{ .ctl_name = CTL_FS, .procname = "fs", },
	{ }
};

static void prepare_sysctl(void)
{
	register_sysctl_paths(fs_path, vz_fs_table);
}

/*
 * ------------------------------------------------------------------------
 * XXX init_ve_system
 * ------------------------------------------------------------------------
 */

void init_ve_system(void)
{
	struct task_struct *init_entry;
	struct ve_struct *ve;
	struct path root;

	ve = get_ve0();

	init_entry = init_pid_ns.child_reaper;
	/* if ve_move_task to VE0 (e.g. in cpt code)	*
	 * occurs, ve_cap_bset on VE0 is required	*/
	ve->ve_cap_bset = CAP_INIT_EFF_SET;

	get_fs_root(init_entry->fs, &root);
	ve->root_path = root;

#ifdef CONFIG_PROC_FS
	prepare_proc();
#endif
	prepare_sysctl();
}
