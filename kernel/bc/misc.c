/*
 *  kernel/bc/misc.c
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#include <linux/tty.h>
#include <linux/tty_driver.h>
#include <linux/signal.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/sched.h>
#include <linux/module.h>

#include <bc/beancounter.h>
#include <bc/kmem.h>
#include <bc/proc.h>

/*
 * Task staff
 */

#define TASK_KMEM_SIZE	(sizeof(struct task_struct) + THREAD_SIZE)

int ub_task_charge(struct user_beancounter *ub)
{
	if (ub_kmem_charge(ub, TASK_KMEM_SIZE, GFP_KERNEL))
		goto no_mem;

	if (charge_beancounter_fast(ub, UB_NUMPROC, 1, UB_HARD))
		goto no_num;

	return 0;

no_num:
	ub_kmem_uncharge(ub, TASK_KMEM_SIZE);
no_mem:
	return -ENOMEM;
}

void ub_task_uncharge(struct user_beancounter *ub)
{
	uncharge_beancounter_fast(ub, UB_NUMPROC, 1);
	ub_kmem_uncharge(ub, TASK_KMEM_SIZE);
}

void ub_task_get(struct user_beancounter *ub, struct task_struct *task)
{
	struct task_beancounter *new_bc = &task->task_bc;

	new_bc->task_ub = get_beancounter_longterm(ub);
	new_bc->exec_ub = get_beancounter_longterm(ub);
}

void ub_task_put(struct task_struct *task)
{
	struct task_beancounter *task_bc;

	task_bc = &task->task_bc;

	put_beancounter_longterm(task_bc->exec_ub);
	put_beancounter_longterm(task_bc->task_ub);

	task_bc->exec_ub = (struct user_beancounter *)0xdeadbcbc;
	task_bc->task_ub = (struct user_beancounter *)0xdead100c;
}

int ub_file_charge(struct file *f)
{
	struct user_beancounter *ub = get_exec_ub_top();
	int err;

	err = charge_beancounter_fast(ub, UB_NUMFILE, 1, UB_HARD);
	if (unlikely(err))
		goto no_file;

	err = ub_kmem_charge(ub,
			CHARGE_SIZE(kmem_cache_objuse(filp_cachep)),
			GFP_KERNEL);
	if (unlikely(err))
		goto no_kmem;

	f->f_ub = get_beancounter(ub);

	return 0;

no_kmem:
	uncharge_beancounter_fast(ub, UB_NUMFILE, 1);
no_file:
	return err;
}

void ub_file_uncharge(struct file *f)
{
	struct user_beancounter *ub = f->f_ub;

	ub_kmem_uncharge(ub,
			CHARGE_SIZE(kmem_cache_objuse(filp_cachep)));
	uncharge_beancounter_fast(ub, UB_NUMFILE, 1);
	put_beancounter(ub);
}

int ub_flock_charge(struct file_lock *fl, int hard)
{
	struct user_beancounter *ub;
	int err;

	/* No need to get_beancounter here since it's already got in slab */
	ub = slab_ub(fl);
	if (ub == NULL)
		return 0;

	err = charge_beancounter(ub, UB_NUMFLOCK, 1, hard ? UB_HARD : UB_SOFT);
	if (!err)
		fl->fl_charged = 1;
	return err;
}

void ub_flock_uncharge(struct file_lock *fl)
{
	struct user_beancounter *ub;

	/* Ub will be put in slab */
	ub = slab_ub(fl);
	if (ub == NULL || !fl->fl_charged)
		return;

	uncharge_beancounter(ub, UB_NUMFLOCK, 1);
	fl->fl_charged = 0;
}

/*
 * PTYs
 */

int ub_pty_charge(struct tty_struct *tty)
{
	struct user_beancounter *ub;
	int retval;

	ub = slab_ub(tty);
	retval = 0;
	if (ub && tty->driver->subtype == PTY_TYPE_MASTER &&
			!test_bit(TTY_CHARGED, &tty->flags)) {
		retval = charge_beancounter(ub, UB_NUMPTY, 1, UB_HARD);
		if (!retval)
			set_bit(TTY_CHARGED, &tty->flags);
	}
	return retval;
}

void ub_pty_uncharge(struct tty_struct *tty)
{
	struct user_beancounter *ub;

	ub = slab_ub(tty);
	if (ub && tty->driver->subtype == PTY_TYPE_MASTER &&
			test_bit(TTY_CHARGED, &tty->flags)) {
		uncharge_beancounter(ub, UB_NUMPTY, 1);
		clear_bit(TTY_CHARGED, &tty->flags);
	}
}
