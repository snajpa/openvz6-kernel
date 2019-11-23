/* -*- c -*- --------------------------------------------------------------- *
 *
 * linux/fs/autofs/init.c
 *
 *  Copyright 1997-1998 Transmeta Corporation -- All Rights Reserved
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 *
 * ------------------------------------------------------------------------- */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/ve_proto.h>
#include "autofs_i.h"

static int autofs_get_sb(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data, struct vfsmount *mnt)
{
	return get_sb_nodev(fs_type, flags, data, autofs4_fill_super, mnt);
}

static struct file_system_type autofs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "autofs",
	.get_sb		= autofs_get_sb,
	.kill_sb	= autofs4_kill_sb,
	.fs_flags	= FS_VIRTUALIZED,
};

static void ve_autofs_stop(void *data)
{
	struct ve_struct *ve = data;

	umount_ve_fs_type(&autofs_fs_type, ve->veid);
}

static struct ve_hook autofs4_hook = {
	.fini	  = ve_autofs_stop,
	.owner	  = THIS_MODULE,
	.priority = HOOK_PRIO_FS,
};

static int __init init_autofs4_fs(void)
{
	int err;

	err = register_filesystem(&autofs_fs_type);
	if (err)
		return err;

	autofs_dev_ioctl_init();
	ve_hook_register(VE_INIT_EXIT_CHAIN, &autofs4_hook);

	return err;
}

static void __exit exit_autofs4_fs(void)
{
	ve_hook_unregister(&autofs4_hook);
	autofs_dev_ioctl_exit();
	unregister_filesystem(&autofs_fs_type);
}

module_init(init_autofs4_fs) 
module_exit(exit_autofs4_fs)
MODULE_LICENSE("GPL");
