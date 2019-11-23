/*
 *
 *  kernel/cpt/cpt_dump.c
 *
 *  Copyright (C) 2000-2005  SWsoft
 *  All rights reserved.
 *
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/pagemap.h>
#include <linux/ptrace.h>
#include <linux/utrace.h>
#include <linux/smp_lock.h>
#include <linux/ve.h>
#include <linux/ve_proto.h>
#include <bc/task.h>
#include <linux/cpt_image.h>
#include <linux/nsproxy.h>
#include <linux/mnt_namespace.h>
#include <linux/netdevice.h>
#include <linux/dcache.h>
#include <linux/if_tun.h>
#include <linux/utsname.h>
#include <linux/pid_namespace.h>
#include <linux/ipc_namespace.h>
#include <linux/netdevice.h>
#include <linux/mount.h>
#include <linux/ve_nfs.h>
#include <linux/freezer.h>

#include <linux/cpt_obj.h>
#include <linux/cpt_context.h>
#include "cpt_dump.h"
#include "cpt_files.h"
#include "cpt_mm.h"
#include "cpt_process.h"
#include "cpt_net.h"
#include "cpt_socket.h"
#include "cpt_ubc.h"
#include "cpt_kernel.h"
#include "cpt_fsmagic.h"


static int vps_child_level(struct task_struct *root, struct task_struct *c)
{
	int level = 0;
	int veid = VE_TASK_INFO(c)->owner_env->veid;

	while (VE_TASK_INFO(c)->owner_env->veid == veid) {
		if (c->pid != c->tgid)
			c = c->group_leader;
		if (c == root)
			return level;

		c = c->real_parent;
		level++;
	}
	return -1;
}

static inline int freezable(struct task_struct * p)
{
	if (p->exit_state)
		return 0;

	/* skip kernel threads */
	if (p->flags & PF_KTHREAD)
		return 0;

	switch (p->state) {
	case TASK_STOPPED:
		return 0;
	default:
		return 1;
	}
}

static void ve_print_frozen(cpt_context_t *ctx)
{
	struct task_struct *p, *g;
	int tainted = 0;
	struct ve_struct *curr, *ve;

	ve = get_ve_by_id(ctx->ve_id);
	if (!ve) {
		eprintk_ctx("%s: Failed to get VE by id %d\n", __func__, ctx->ve_id);
		return;
	}

	curr = set_exec_env(ve);

	read_lock(&tasklist_lock);
	do_each_thread_ve(g, p) {
		if (freezing(p) || frozen(p)) {
			if (!tainted++)
				add_taint(TAINT_CRAP);
			eprintk_ctx("ve#%d: %s process: " CPT_FID
				    ", exit_state: %d, state: %ld\n",
				    get_exec_env()->veid,
				    (freezing(p)) ? "freezing" : "frozen",
				    CPT_TID(p), p->exit_state, p->state);
		}
	} while_each_thread_ve(g, p);
	read_unlock(&tasklist_lock);

	(void)set_exec_env(curr);

	put_ve(ve);
}

static void wake_ve(cpt_context_t *ctx)
{
	struct task_struct *p, *g;

	read_lock(&tasklist_lock);
	do_each_thread_ve(g, p) {
		thaw_process(p);
	} while_each_thread_ve(g, p);
	read_unlock(&tasklist_lock);
	ve_print_frozen(ctx);
}

static int check_process_external(struct task_struct *p)
{
	if (pid_alive(p)) {
		if (p->pids[PIDTYPE_PID].pid->level == 0)
			return PIDTYPE_PID;
		if (p->pids[PIDTYPE_PGID].pid->level == 0)
			return PIDTYPE_PGID;
		if (p->pids[PIDTYPE_SID].pid->level == 0)
			return PIDTYPE_SID;
	}

	return PIDTYPE_MAX;
}

enum
{
	OBSTACLE_NOGO = -1,
	OBSTACLE_TIMEOUT = -2,
	OBSTACLE_TRYAGAIN = -3,
	OBSTACLE_SIGNAL = -4,
};

#define DEFAULT_SUSPEND_TIMEOUT_MIN		10UL
#define DEFAULT_SUSPEND_TIMEOUT_MAX		(60UL * 60)       /* 1 hour */

unsigned long suspend_timeout_min = DEFAULT_SUSPEND_TIMEOUT_MIN;
unsigned long suspend_timeout_max = DEFAULT_SUSPEND_TIMEOUT_MAX;

unsigned int suspend_timeout = DEFAULT_SUSPEND_TIMEOUT_MIN;

unsigned int kill_external = 0;

static int check_trace(struct task_struct *tsk, struct task_struct *root,
			cpt_context_t *ctx)
{
	return task_utrace_attached(tsk);
}

static int vps_kill_and_reap_external(struct cpt_context *ctx)
{
	struct task_struct *p, *g;
	struct task_struct *root;
	int external_tasks = 0;

	read_lock(&tasklist_lock);

	root = find_task_by_pid_ns(1, current->nsproxy->pid_ns);
	if (!root) {
		eprintk_ctx("cannot find ve init\n");
		read_unlock(&tasklist_lock);
		return -ESRCH;
	}

	do_each_thread_ve(g, p) {
		if ((vps_child_level(root, p) < 0) && !cpt_skip_task(p)) {
			if (!fatal_signal_pending(p)) {
				p->flags |= PF_EXIT_RESTART;
				send_sig(SIGKILL, p, true);
				wake_up_process(p);
			}
			external_tasks++;
		}
	} while_each_thread_ve(g, p);

	read_unlock(&tasklist_lock);

	if (external_tasks > 0) {
		/* Wait for external tasks to die. See do_notify_parent(). */
		schedule_timeout_interruptible(HZ/20);
	}
	return external_tasks;
}

static int vps_handle_external(struct cpt_context *ctx)
{
	int status;

	if (!kill_external)
		return 0;

	do {
		status = vps_kill_and_reap_external(ctx);
	} while (status > 0);

	return status;
}

static int vps_stop_iteration(struct cpt_context *ctx)
{
	struct task_struct *p, *g;
	struct task_struct *root;
	int todo = 0;

	read_lock(&tasklist_lock);

	root = find_task_by_pid_ns(1, current->nsproxy->pid_ns);
	if (!root) {
		eprintk_ctx("cannot find ve init\n");
		todo = -ESRCH;
		goto out;
	}

	do_each_thread_ve(g, p) {
		if (vps_child_level(root, p) >= 0) {
			if (!freezable(p) || frozen(p))
				continue;

			switch (check_process_external(p)) {
			case PIDTYPE_PID:
				eprintk_ctx("external process %d/%d(%s) inside CT (e.g. vzctl enter or vzctl exec).\n",
						cpt_task_pid_nr(p, PIDTYPE_PID), p->pid, p->comm);
				todo = OBSTACLE_NOGO;
				goto out;
			case PIDTYPE_PGID:
				eprintk_ctx("external process group %d/%d(%s) inside CT "
						"(e.g. vzctl enter or vzctl exec).\n",
						cpt_task_pid_nr(p, PIDTYPE_PGID), p->pid, p->comm);
				todo = OBSTACLE_NOGO;
				goto out;
			case PIDTYPE_SID:
				eprintk_ctx("external process session %d/%d(%s) inside CT "
						"(e.g. vzctl enter or vzctl exec).\n",
						cpt_task_pid_nr(p, PIDTYPE_SID), p->pid, p->comm);
				todo = OBSTACLE_NOGO;
				goto out;
			}

			if (p->vfork_done) {
				/* Task between vfork()...exec()
				 * cannot be frozen, because parent
				 * wait in uninterruptible state.
				 * So, we do nothing, waiting for
				 * exec(), unless:
				 */
				if (p->state == TASK_STOPPED ||
				    p->state == TASK_TRACED) {
					eprintk_ctx("task " CPT_FID " is stopped while vfork(). "
							"Checkpointing is impossible.\n",
							CPT_TID(p));
					todo = OBSTACLE_NOGO;
					/* It is fatal, _user_ stopped
					 * vfork()ing task, so that we
					 * cannot suspend now.
					 */
				} else {
					todo = OBSTACLE_TRYAGAIN;
				}
				goto out;
			}
			if (p->signal->group_exit_task &&
			    p->signal->notify_count) {
				/* exec() waits for threads' death */
				wprintk_ctx("task " CPT_FID " waits for threads' death\n", CPT_TID(p));
				todo = OBSTACLE_TRYAGAIN;
				goto out;
			}
			if (check_trace(p, root, ctx)) {
				eprintk_ctx("task " CPT_FID " is traced. Checkpointing is impossible.\n", CPT_TID(p));
				todo = OBSTACLE_NOGO;
				goto out;
			}
			if (p->flags & PF_NOFREEZE) {
				eprintk_ctx("task " CPT_FID " is unfreezable. Checkpointing is impossible.\n", CPT_TID(p));
				todo = OBSTACLE_NOGO;
				goto out;
			}

			if (freeze_task(p, false) && (todo >= 0))
				todo++;
			else if (!frozen(p))
				eprintk_ctx("This can't be: task's " CPT_FID " is not frozen, and freeze attempt has failed.\n", CPT_TID(p));
		} else {
			if (!cpt_skip_task(p)) {
				eprintk_ctx("foreign process %d/%d(%s) inside CT (e.g. vzctl enter or vzctl exec).\n",
						cpt_task_pid_nr(p, PIDTYPE_PID), task_pid_nr(p), p->comm);
				todo = OBSTACLE_NOGO;
				goto out;
			}
		}
	} while_each_thread_ve(g, p);
out:
	read_unlock(&tasklist_lock);
	return todo;
}

static int check_stop_status(struct cpt_context *ctx, int todo,
			     unsigned long start_time,
			     unsigned long stop_time)
{
	int status = todo;

	if (todo > 0) {
		/* No visible obstacles, but VE did not freeze
		 * for timeout. Interrupt suspend, if it is major
		 * timeout or signal; if it is minor timeout
		 * we will wake VE and restart suspend.
		 */
		if (time_after(jiffies, start_time + suspend_timeout*HZ)) {
			struct task_struct *p, *g;
			int i = 0;

			eprintk_ctx("timed out (%d seconds).\n", suspend_timeout);
			eprintk_ctx("Unfrozen tasks (no more than 10): see dmesg output.\n");
			read_lock(&tasklist_lock);
			do_each_thread_ve(g, p) {
				task_lock(p);
				if (freezable(p) && !frozen(p) && (i++ < 10))
					sched_show_task(p);
				task_unlock(p);

			} while_each_thread_ve(g, p);
			read_unlock(&tasklist_lock);

			todo = OBSTACLE_TIMEOUT;
		} else if (signal_pending(current))
			todo = OBSTACLE_SIGNAL;
		else if (time_after(jiffies, stop_time))
			todo = OBSTACLE_TRYAGAIN;
	}

	switch (todo) {
	case OBSTACLE_NOGO:
		eprintk_ctx("suspend is impossible now.\n");
		status = -EAGAIN;
		break;
	case OBSTACLE_SIGNAL:
		{
			int i = _NSIG;
			sigset_t *set = &current->pending.signal;

			eprintk_ctx("interrupted by signal: ");
			do {
				int x = 0;

				i -= 4;
				if (sigismember(set, i+1)) x |= 1;
				if (sigismember(set, i+2)) x |= 2;
				if (sigismember(set, i+3)) x |= 4;
				if (sigismember(set, i+4)) x |= 8;
				eprintk_ctx("%x", x);
			} while (i >= 4);
			eprintk_ctx(".\n");
		}
	case OBSTACLE_TIMEOUT:
		status = -EINTR;
		break;
	case OBSTACLE_TRYAGAIN:
		if (time_after(jiffies, start_time + DEFAULT_SUSPEND_TIMEOUT_MIN*HZ) ||
		    signal_pending(current)) {
			wprintk_ctx("suspend timed out\n");
			status = -EAGAIN;
			break;
		}
		/*
		 * All we need here is to return a posive code, which
		 * indicates, that we have to continue the suspend loop.
		 */
		status = 1;
		break;
	}
	return status;
}

static int vps_stop_tasks(struct cpt_context *ctx)
{
	unsigned long start_time = jiffies;
	unsigned long timeout = HZ/5;
	int status;
	int round = 0;

	do_gettimespec(&ctx->start_time); 
	do_posix_clock_monotonic_gettime(&ctx->cpt_monotonic_time);
	ctx->virt_jiffies64 = get_jiffies_64() + get_exec_env()->jiffies_fixup;

	atomic_inc(&get_exec_env()->suspend);

	status = vps_handle_external(ctx);
	if (status)
		goto out;

	do {
		unsigned long stop_time = jiffies + timeout;
		int result;

		result = vps_stop_iteration(ctx);

		status = check_stop_status(ctx, result, start_time, stop_time);
		if (status > 0) {
			if (result == OBSTACLE_TRYAGAIN) {
				wprintk_ctx("minor suspend timeout (%lu) expired, "
					    "trying again\n", timeout);

				/* Try again. VE is awake, give it some time to run. */
				current->state = TASK_INTERRUPTIBLE;
				schedule_timeout(HZ);

				/* After a short wait restart suspend
				 * with longer timeout */
				timeout = min(timeout<<1, DEFAULT_SUSPEND_TIMEOUT_MIN*HZ);
			} else {
				if (round++ > 0) {
					/* VE is partially frozen, give processes
					 * a chance to enter to refrigerator(). */
					current->state = TASK_INTERRUPTIBLE;
					schedule_timeout(HZ/20);
				} else {
					yield();
				}
			}
		}
	} while (status > 0);

out:
	atomic_dec(&get_exec_env()->suspend);

	return status;
}

static int cpt_unlock_ve(struct cpt_context *ctx)
{
	struct ve_struct *env;

	env = get_ve_by_id(ctx->ve_id);
	if (!env)
		return -ESRCH;
	down_write(&env->op_sem);
	env->is_locked = 0;
	up_write(&env->op_sem);
	put_ve(env);
	return 0;
}

int cpt_resume(struct cpt_context *ctx)
{
	cpt_object_t *obj;

	cpt_unlock_sockets(ctx);

	if (list_empty(&ctx->object_array[CPT_OBJ_TASK]))
		goto skip_tasks;

	for_each_object(obj, CPT_OBJ_TASK) {
		struct task_struct *tsk = obj->o_obj;

		if (thaw_process(tsk) == 0 && freezable(tsk))
			eprintk_ctx("strange, %s not frozen\n", tsk->comm );
		put_task_struct(tsk);
	}

	ve_print_frozen(ctx);

skip_tasks:
	cpt_resume_network(ctx);

	cpt_unlock_ve(ctx);

	cpt_finish_ubc(ctx);
	cpt_finish_vfsmount_ref(ctx);
	cpt_object_destroy(ctx);
	return 0;
}

void cpt_drop_nfs_unhashed(struct cpt_context *ctx)
{
	cpt_object_t *obj;

	for_each_object(obj, CPT_OBJ_FILE) {
		struct file *file = obj->o_obj;
		struct dentry *d = file->f_dentry;

		if (d->d_flags & DCACHE_NFSFS_RENAMED) {
			spin_lock(&d->d_lock);
			d->d_flags &= ~DCACHE_NFSFS_RENAMED;
			spin_unlock(&d->d_lock);
		}
	}
}

int cpt_kill(struct cpt_context *ctx)
{
	int err = 0;
	struct ve_struct *env;
	cpt_object_t *obj;
	struct task_struct *root_task = NULL;

	if (!ctx->ve_id)
		return -EINVAL;

	env = get_ve_by_id(ctx->ve_id);
	if (!env)
		return -ESRCH;

	if (current->ve_task_info.owner_env == env) {
		wprintk_ctx("attempt to kill ve from inside, escaping...\n");
		err = -EPERM;
		goto out;
	}

	cpt_kill_sockets(ctx);

	cpt_drop_nfs_unhashed(ctx);

	for_each_object(obj, CPT_OBJ_TASK) {
		struct task_struct *tsk = obj->o_obj;

		if (tsk->exit_state) {
			put_task_struct(tsk);
			continue;
		}

		if (cpt_task_pid_nr(tsk, PIDTYPE_PID) == 1) {
			root_task = tsk;
			continue;
		}

		tsk->robust_list = NULL;
#ifdef CONFIG_COMPAT
		tsk->compat_robust_list = NULL;
#endif
		tsk->clear_child_tid = NULL;

		if (tsk->ptrace) {
			tasklist_write_lock_irq();
			tsk->ptrace = 0;
			if (!list_empty(&tsk->ptrace_entry)) {
				tsk->parent = tsk->real_parent;
				list_del_init(&tsk->ptrace_entry);
			}
			write_unlock_irq(&tasklist_lock);
		}

		send_sig(SIGKILL, tsk, 1);
		thaw_process(tsk);

		put_task_struct(tsk);
	}

	yield();

	if (root_task != NULL) {
		send_sig(SIGKILL, root_task, 1);
		thaw_process(root_task);

		put_task_struct(root_task);
	}

	cpt_finish_ubc(ctx);
	cpt_finish_vfsmount_ref(ctx);
	cpt_object_destroy(ctx);

	/* Wait for ve_list_del() */
	wait_event_interruptible(env->ve_list_wait, env->ve_list.prev == LIST_POISON2);

out:
	put_ve(env);
	return err;
}

#ifdef CONFIG_BEANCOUNTERS
static void collect_task_ubc(struct task_struct *t, struct cpt_context *ctx)
{
	struct task_beancounter *tbc;

	tbc = &(t->task_bc);
	cpt_add_ubc(top_beancounter(tbc->exec_ub), ctx);
	cpt_add_ubc(top_beancounter(tbc->task_ub), ctx);
}
#else
static void inline collect_task_ubc(struct task_struct *t,
		struct cpt_context *ctx)
{ return; }
#endif

static cpt_object_t * remember_task(struct task_struct * child,
		cpt_object_t * head, cpt_context_t * ctx)
{
	cpt_object_t *cobj;
	int err;

	if (freezable(child) && !frozen(child)) {
		eprintk_ctx("process " CPT_FID " is not frozen, state: %ld, flags: 0x%x\n",
				CPT_TID(child), child->state, child->flags);
		err = -EINVAL;
		goto err;
	}

	if (child->exit_state && (child->exit_state != EXIT_ZOMBIE))
		/*
		 * Don't collect dead tasks - just skip it and return the same
		 * object.
		 */
		return head;

	if (lookup_cpt_object(CPT_OBJ_TASK, child, ctx)) BUG();
	if ((cobj = alloc_cpt_object(GFP_KERNEL, ctx)) == NULL) {
		eprintk_ctx("task obj allocation failure\n");
		err = -ENOMEM;
		goto err;
	}
	cobj->o_count = 1;
	cpt_obj_setobj(cobj, child, ctx);
	insert_cpt_object(CPT_OBJ_TASK, cobj, head, ctx);
	collect_task_ubc(child, ctx);
	return cobj;

err:
	put_task_struct(child);
	return ERR_PTR(err);
}

static int vps_collect_tasks(struct cpt_context *ctx)
{
	int err = -ESRCH;
	cpt_object_t *obj;
	struct task_struct *root;
	read_lock(&tasklist_lock);
	root = find_task_by_pid_ns(1, current->nsproxy->pid_ns);
	if (root)
		get_task_struct(root);
	read_unlock(&tasklist_lock);

	if (!root) {
		err = -ESRCH;
		eprintk_ctx("vps_collect_tasks: cannot find root\n");
		goto out;
	}

	if (root->exit_state) {
		err = -ESRCH;
		eprintk_ctx("vps_collect_tasks: init is dead, nothing to dump\n");
		goto out;
	}

	if ((obj = alloc_cpt_object(GFP_KERNEL, ctx)) == NULL) {
		put_task_struct(root);
		return -ENOMEM;
	}
	obj->o_count = 1;
	cpt_obj_setobj(obj, root, ctx);
	intern_cpt_object(CPT_OBJ_TASK, obj, ctx);
	collect_task_ubc(root, ctx);

	/* Collect process subtree recursively */
	for_each_object(obj, CPT_OBJ_TASK) {
		cpt_object_t *head = obj;
		struct task_struct *tsk = obj->o_obj;
		struct task_struct *child;

		if (freezable(tsk) && !frozen(tsk)) {
			eprintk_ctx("process " CPT_FID " is not frozen\n", CPT_TID(tsk));
			err = -EINVAL;
			goto out;
		}

		if (tsk->state == TASK_RUNNING)
			printk("State TASK_RUNNING on collect stage %ld " CPT_FID "\n", tsk->state, CPT_TID(tsk));

		wait_task_inactive(tsk, 0);

		err = check_task_state(tsk, ctx);
		if (err)
			goto out;

		if (tsk->pid == tsk->tgid) {
			child = tsk;
			for (;;) {
				read_lock(&tasklist_lock);
				child = next_thread(child);
				if (child != tsk)
					get_task_struct(child);
				read_unlock(&tasklist_lock);

				if (child == tsk)
					break;

				if (child->parent != tsk->parent) {
					put_task_struct(child);
					eprintk_ctx("illegal thread structure, kernel bug\n");
					err = -EINVAL;
					goto out;
				}

				head = remember_task(child, head, ctx);
				if (IS_ERR(head)) {
					err = PTR_ERR(head);
					goto out;
				}
			}
		}

		/* About locking. VE is frozen. But lists of children
		 * may change at least for init, when entered task reparents
		 * to init and when reparented task exits. If we take care
		 * of this case, we still can unlock while scanning
		 * tasklists.
		 */
		read_lock(&tasklist_lock);
		list_for_each_entry(child, &tsk->children, sibling) {
			if (child->pid != child->tgid)
				continue;
			/* skip kernel threads */
			if (child->flags & PF_KTHREAD)
				continue;

			get_task_struct(child);
			read_unlock(&tasklist_lock);

			head = remember_task(child, head, ctx);
			if (IS_ERR(head)) {
				err = PTR_ERR(head);
				goto out;
			}

			read_lock(&tasklist_lock);
		}

		read_unlock(&tasklist_lock);
	}

	return 0;

out:
	while (!list_empty(&ctx->object_array[CPT_OBJ_TASK])) {
		struct list_head *head = ctx->object_array[CPT_OBJ_TASK].next;
		cpt_object_t *obj = list_entry(head, cpt_object_t, o_list);
		struct task_struct *tsk;

		list_del(head);
		tsk = obj->o_obj;
		put_task_struct(tsk);
		free_cpt_object(obj, ctx);
	}
	return err;
}

static int cpt_collect(struct cpt_context *ctx)
{
	int err;

	if ((err = cpt_collect_mm(ctx)) != 0)
		return err;

	if ((err = cpt_collect_sysv(ctx)) != 0)
		return err;

	if ((err = cpt_collect_namespace(ctx)) != 0)
		return err;

	if ((err = cpt_collect_files(ctx)) != 0)
		return err;

	if ((err = cpt_collect_fs(ctx)) != 0)
		return err;

	if ((err = cpt_collect_signals(ctx)) != 0)
		return err;

	if ((err = cpt_collect_posix_timers(ctx)) != 0)
		return err;

	return 0;
}

static int cpt_dump_veinfo(cpt_context_t *ctx)
{
	struct cpt_veinfo_image *i = cpt_get_buf(ctx);
	struct ve_struct *ve;
	struct timespec delta;
	struct ipc_namespace *ns;

	cpt_open_section(ctx, CPT_SECT_VEINFO);
	cpt_open_object(NULL, ctx);

	memset(i, 0, sizeof(*i));

	i->cpt_next = CPT_NULL;
	i->cpt_object = CPT_OBJ_VEINFO;
	i->cpt_hdrlen = sizeof(*i);
	i->cpt_content = CPT_CONTENT_VOID;

	ve = get_exec_env();
	ns = ve->ve_ns->ipc_ns;

	i->shm_ctl_all = ns->shm_ctlall;
	if (ns->shm_ctlall > 0xFFFFFFFFU)
		i->shm_ctl_all = 0xFFFFFFFFU;
	i->shm_ctl_max = ns->shm_ctlmax;
	if (ns->shm_ctlmax > 0xFFFFFFFFU)
		i->shm_ctl_max = 0xFFFFFFFFU;
	i->shm_ctl_mni = ns->shm_ctlmni;

	i->msg_ctl_max = ns->msg_ctlmax;
	i->msg_ctl_mni = ns->msg_ctlmni;
	i->msg_ctl_mnb = ns->msg_ctlmnb;

	BUILD_BUG_ON(sizeof(ns->sem_ctls) != sizeof(i->sem_ctl_arr));
	i->sem_ctl_arr[0] = ns->sem_ctls[0];
	i->sem_ctl_arr[1] = ns->sem_ctls[1];
	i->sem_ctl_arr[2] = ns->sem_ctls[2];
	i->sem_ctl_arr[3] = ns->sem_ctls[3];

	do_posix_clock_monotonic_gettime(&delta);
	_set_normalized_timespec(&delta,
			delta.tv_sec - ve->start_timespec.tv_sec,
			delta.tv_nsec - ve->start_timespec.tv_nsec);
	i->start_timespec_delta = cpt_timespec_export(&delta);
	i->start_jiffies_delta = get_jiffies_64() - ve->start_jiffies;

	do_posix_clock_monotonic_gettime(&delta);
	monotonic_to_bootbased(&delta);
	_set_normalized_timespec(&delta,
			delta.tv_sec - ve->real_start_timespec.tv_sec,
			delta.tv_nsec - ve->real_start_timespec.tv_nsec);
	i->real_start_timespec_delta = cpt_timespec_export(&delta);

	i->last_pid = ve->ve_ns->pid_ns->last_pid;
	i->rnd_va_space	= ve->_randomize_va_space + 1;
	i->vpid_max = ve->ve_ns->pid_ns->pid_max;
	i->aio_max_nr = ve->aio_max_nr;
	memcpy(&i->cpt_ve_bcap, &ve->ve_cap_bset, sizeof(i->cpt_ve_bcap));

	ctx->write(i, sizeof(*i), ctx);
	cpt_release_buf(ctx);
	cpt_close_object(ctx);
	cpt_close_section(ctx);
	return 0;
}

static int cpt_dump_utsname(cpt_context_t *ctx)
{
	int len;
	struct cpt_object_hdr o;
	struct ve_struct *ve;
	struct uts_namespace *ns;

	cpt_open_section(ctx, CPT_SECT_UTSNAME);

	ve = get_exec_env();
	ns = ve->ve_ns->uts_ns;

 	cpt_open_object(NULL, ctx);
	len = strlen(ns->name.nodename);
 	o.cpt_next = CPT_NULL;
	o.cpt_object = CPT_OBJ_NAME;
	o.cpt_hdrlen = sizeof(o);
	o.cpt_content = CPT_CONTENT_NAME;

	ctx->write(&o, sizeof(o), ctx);
	ctx->write(ns->name.nodename, len+1, ctx);
	ctx->align(ctx);
 	cpt_close_object(ctx);
 
 	cpt_open_object(NULL, ctx);
	len = strlen(ns->name.domainname);
 	o.cpt_next = CPT_NULL;
	o.cpt_object = CPT_OBJ_NAME;
	o.cpt_hdrlen = sizeof(o);
	o.cpt_content = CPT_CONTENT_NAME;

	ctx->write(&o, sizeof(o), ctx);
	ctx->write(ns->name.domainname, len+1, ctx);
	ctx->align(ctx);
	cpt_close_object(ctx);

 	cpt_open_object(NULL, ctx);
	len = strlen(ns->name.release);
 	o.cpt_next = CPT_NULL;
	o.cpt_object = CPT_OBJ_NAME;
	o.cpt_hdrlen = sizeof(o);
	o.cpt_content = CPT_CONTENT_NAME;

	ctx->write(&o, sizeof(o), ctx);
	ctx->write(ns->name.release, len+1, ctx);
	ctx->align(ctx);
 	cpt_close_object(ctx);

	cpt_close_section(ctx);
	return 0;
}

#ifndef CONFIG_IA64
static int cpt_dump_vsyscall(cpt_context_t *ctx)
{
	struct cpt_page_block *pgb = cpt_get_buf(ctx);

	cpt_open_section(ctx, CPT_SECT_VSYSCALL);
	cpt_open_object(NULL, ctx);

	pgb->cpt_next = CPT_NULL;
	pgb->cpt_object = CPT_OBJ_VSYSCALL;
	pgb->cpt_hdrlen = sizeof(*pgb);
	pgb->cpt_content = CPT_CONTENT_DATA;
	pgb->cpt_start = cpt_ptr_export(vsyscall_addr);
	pgb->cpt_end = pgb->cpt_start + PAGE_SIZE;

	ctx->write(pgb, sizeof(*pgb), ctx);
	cpt_release_buf(ctx);

	ctx->write(vsyscall_addr, PAGE_SIZE, ctx);

	cpt_close_object(ctx);
	cpt_close_section(ctx);
	return 0;
}
#endif

int cpt_dump(struct cpt_context *ctx)
{
	struct user_beancounter *bc = get_exec_ub_top();
	struct ve_struct *oldenv, *env;
	cpt_object_t *obj;
	struct nsproxy *old_ns;
	int err, err2 = 0;

	if (!ctx->ve_id)
		return -EINVAL;

	env = get_ve_by_id(ctx->ve_id);
	if (!env)
		return -ESRCH;

	down_read(&env->op_sem);
	err = -ESRCH;
	if (!env->is_running)
		goto out_noenv;
	if (!env->is_locked)
		goto out_noenv;
	err = -EINVAL;
	if (env->ve_ns->pid_ns->flags & PID_NS_HIDDEN) {
		printk(KERN_WARNING "CT: checkpointing not supported yet"
				" for hidden pid namespaces.\n");
		goto out_noenv;
	}

	err = -ENOTSUPP;
	for_each_object(obj, CPT_OBJ_TASK) {
		struct task_struct *tsk = obj->o_obj;
		struct nsproxy *nsp = tsk->nsproxy;
		char *str = NULL;

		if (!nsp)
			continue;

		if (nsp->uts_ns != env->ve_ns->uts_ns)
			str = "uts";
		else if (nsp->ipc_ns != env->ve_ns->ipc_ns)
			str = "ipc";
		else if (nsp->pid_ns != env->ve_ns->pid_ns)
			str = "pid";
		else if (nsp->net_ns != env->ve_ns->net_ns)
			str = "net";

		if (str) {
			printk(KERN_WARNING "CT %d, process %d/%d(%s): "
			       "checkpointing is not supported yet for "
			       "nested %s namespaces.\n",
			       env->veid, cpt_task_pid_nr(tsk, PIDTYPE_PID),
			       tsk->pid, tsk->comm, str);
			goto out_noenv;
		}
	}

	oldenv = set_exec_env(env);
	old_ns = current->nsproxy;
	current->nsproxy = env->ve_ns;

	/* Phase 2: real checkpointing */
	err = cpt_open_dumpfile(ctx);
	if (err)
		goto out;
	
	cpt_major_hdr_out(ctx);

	if (!err)
		err = cpt_dump_veinfo(ctx);
	if (!err)
		err = cpt_dump_ubc(ctx);

	/*
	 * Backup old limits and set them temporary unlimited to avoid
	 * internal reclaimer, oomkiller and other unpleasantnesses
	 * Correct value already dumpled into image at this point
	 */
	set_ubc_unlimited(ctx, bc);

	if (!err)
		err = cpt_dump_namespace(ctx);
	if (!err)
		err = cpt_dump_cgroups(ctx);
	if (!err)
		err = cpt_dump_files(ctx);
	if (!err)
		err = cpt_dump_files_struct(ctx);
	if (!err)
		err = cpt_dump_fs_struct(ctx);
	/* netdevices should be dumped after dumping open files
	   as we need to restore netdevice binding to /dev/net/tun file */
	if (!err)
		err = cpt_dump_ifinfo(ctx);
	if (!err)
		err = cpt_dump_sighand(ctx);
	if (!err)
		err = cpt_dump_posix_timers(ctx);
	if (!err)
		err = cpt_dump_vm(ctx);
	if (!err)
		err = cpt_dump_sysvsem(ctx);
	if (!err)
		err = cpt_dump_sysvmsg(ctx);
	if (!err)
		err = cpt_dump_tasks(ctx);
	if (!err)
		err = cpt_dump_orphaned_sockets(ctx);
#if defined(CONFIG_VE_IPTABLES) && \
    (defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE))
	if (!err)
		err = cpt_dump_ip_conntrack(ctx);
#endif
	if (!err)
		err = cpt_dump_utsname(ctx);

#ifndef CONFIG_IA64
	if (!err)
		err = cpt_dump_vsyscall(ctx);
#endif

	if (!err)
		err = cpt_dump_tail(ctx);

	err2 = cpt_close_dumpfile(ctx);

	cpt_close_pram(ctx, err ? : err2);

	/*
	 * Restore limits back
	 */
	restore_ubc_limits(ctx, bc);

out:
	current->nsproxy = old_ns;
	set_exec_env(oldenv);
out_noenv:
	up_read(&env->op_sem);
	put_ve(env);
	return err ? : err2;
}

int cpt_vps_suspend(struct cpt_context *ctx)
{
	struct ve_struct *oldenv, *env;
	struct nsproxy *old_ns;
	int err = 0;

	ctx->kernel_config_flags = test_kernel_config();
	cpt_object_init(ctx);

	if (!ctx->ve_id) {
		env = get_exec_env();
		if (env == get_ve0())
			return -EINVAL;
		wprintk("undefined ve_id\n");
		ctx->ve_id = env->veid;
		get_ve(env);
	} else {
		env = get_ve_by_id(ctx->ve_id);
		if (!env)
			return -ESRCH;
	}

#ifdef CONFIG_VE_IPTABLES
	ctx->iptables_mask = env->ipt_mask;
#endif
	ctx->features = env->features;

	down_write(&env->op_sem);
	err = -ESRCH;
	if (!env->is_running)
		goto out_noenv;

	err = -EBUSY;
	if (env->is_locked)
		goto out_noenv;
	env->is_locked = 1;
	downgrade_write(&env->op_sem);

	oldenv = set_exec_env(env);
	old_ns = current->nsproxy;
	current->nsproxy = env->ve_ns;

	/* Start syncing NFS */
	ve_nfs_sync(env, 0);

	/* Find and stop all the tasks */
	if ((err = vps_stop_tasks(ctx)) != 0)
		goto out_wake;

	/* Wait for syncing NFS mounts */
	if ((err = ve_nfs_sync(env, 1)) != 0) {
		eprintk_ctx("failed to sync nfs\n");
		goto out_wake;
	}

	if ((err = cpt_suspend_network(ctx)) != 0)
		goto out_wake;

	/* At the moment all the state is frozen. We do not need to lock
	 * the state, which can be changed only if the tasks are running.
	 */

	/* Collect task tree */
	if ((err = vps_collect_tasks(ctx)) != 0)
		goto out_wake;

	/* Collect all the resources */
	err = cpt_collect(ctx);

out:
	current->nsproxy = old_ns;
	set_exec_env(oldenv);
	up_read(&env->op_sem);
	put_ve(env);
        return err;

out_noenv:
	up_write(&env->op_sem);
	put_ve(env);
	return err;

out_wake:
	wake_ve(ctx);
	goto out;
}

static void check_unsupported_netdevices(struct cpt_context *ctx, __u32 *caps)
{
	struct net *net = get_exec_env()->ve_netns;
	struct net_device *dev;

	read_lock(&dev_base_lock);
	for_each_netdev(net, dev) {
		if (dev->netdev_ops->ndo_cpt)
			continue;

		eprintk_ctx("unsupported netdevice %s\n", dev->name);
		*caps |= (1<<CPT_UNSUPPORTED_NETDEV);
		break;
	}
	read_unlock(&dev_base_lock);
}

static void check_one_process(struct cpt_context *ctx, __u32 *caps,
		unsigned int flags, struct ve_struct *env,
		struct task_struct *root, struct task_struct *p)
{
	struct mnt_namespace *ns;

	if (p->flags & PF_KTHREAD)
		return;

	if (tsk_used_math(p)) {
		*caps |= flags & ((1<<CPT_CPU_X86_FXSR) |
				(1<<CPT_CPU_X86_SSE) |
				(1<<CPT_CPU_X86_SSE2) |
				(1<<CPT_CPU_X86_SSE4_1) |
				(1<<CPT_CPU_X86_SSE4_2) |
				(1<<CPT_CPU_X86_MMX) |
				(1<<CPT_CPU_X86_3DNOW) |
				(1<<CPT_CPU_X86_3DNOW2) |
				(1<<CPT_CPU_X86_SSE4A) |
				(1<<CPT_CPU_X86_XSAVE) |
				(1<<CPT_CPU_X86_AVX) |
				(1<<CPT_CPU_X86_AESNI) |
				(1<<CPT_CPU_X86_RDRAND));
	}
	/* This is not 100% true. VE could migrate with vdso using int80.
	 * In this case we do not need SEP/SYSCALL32 caps. It is not so easy
	 * to test, so that we do not. */
#ifdef CONFIG_X86_64
	if (!(task_thread_info(p)->flags & _TIF_IA32))
		*caps |= flags & (1<<CPT_CPU_X86_EMT64);
	else if (p->mm && p->mm->context.vdso) {
		if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL)
			*caps |= flags & (1<<CPT_CPU_X86_SEP);
		else
			*caps |= flags & (1<<CPT_CPU_X86_SYSCALL32);
	}
#elif defined(CONFIG_X86_32)
	if (p->mm && p->mm->context.vdso)
		*caps |= flags & (1<<CPT_CPU_X86_SEP);
#endif
#ifdef CONFIG_IA64
	if (!IS_IA32_PROCESS(task_pt_regs(p)))
		*caps |= (1<<CPT_CPU_X86_IA64);
#endif
	if (vps_child_level(root, p) >= 0) {
		switch (check_process_external(p)) {
		case PIDTYPE_PID:
			eprintk_ctx("external process %d/%d(%s) inside CT (e.g. vzctl enter or vzctl exec).\n",
					cpt_task_pid_nr(p, PIDTYPE_PID), p->pid, p->comm);
			*caps |= (1<<CPT_EXTERNAL_PROCESS);
			break;
		case PIDTYPE_PGID:
			eprintk_ctx("external process group %d/%d(%s) inside CT "
					"(e.g. vzctl enter or vzctl exec).\n",
					task_pgrp_vnr(p), p->pid, p->comm);
			*caps |= (1<<CPT_EXTERNAL_PROCESS);
			break;
		case PIDTYPE_SID:
			eprintk_ctx("external process session %d/%d(%s) inside CT "
					"(e.g. vzctl enter or vzctl exec).\n",
					task_session_vnr(p), p->pid, p->comm);
			*caps |= (1<<CPT_EXTERNAL_PROCESS);
		}
	} else {
		if (!cpt_skip_task(p)) {
			eprintk_ctx("foreign process %d/%d(%s) inside CT (e.g. vzctl enter or vzctl exec).\n",
					cpt_task_pid_nr(p, PIDTYPE_PID), p->pid, p->comm);
			*caps |= (1<<CPT_EXTERNAL_PROCESS);
		}
	}
	task_lock(p);
	ns = NULL;
	if (p->nsproxy) {
		ns = p->nsproxy->mnt_ns;
		if (ns)
			get_mnt_ns(ns);
	}
	task_unlock(p);
	if (ns) {
		if (ns != current->nsproxy->mnt_ns) {
			*caps |= (1<<CPT_NAMESPACES);
		}
		put_mnt_ns(ns);
	}
	if (p->policy != SCHED_NORMAL && p->policy != SCHED_BATCH && p->policy != SCHED_IDLE) {
		eprintk_ctx("scheduler policy is not supported %d/%d(%s)\n",
				cpt_task_pid_nr(p, PIDTYPE_PID), p->pid, p->comm);
		*caps |= (1<<CPT_SCHEDULER_POLICY);
	}
	if (check_trace(p, root, ctx)) {
		eprintk_ctx("task %d/%d(%s) is ptraced from host system\n",
				p->pid, cpt_task_pid_nr(p, PIDTYPE_PID), p->comm);
		*caps |= (1<<CPT_PTRACED_FROM_VE0);
	}
	if (cpt_check_unsupported(p, ctx)) {
		*caps |= (1<<CPT_UNSUPPORTED_MISC);
	}
}

static void check_unsupported_mounts(struct cpt_context *ctx, __u32 *caps,
		struct ve_struct *env, struct mnt_namespace *n, char *path_buf)
{
	struct list_head *p;
	char *path;

	down_read(&namespace_sem);
	list_for_each(p, &n->list) {
		struct vfsmount *mnt = list_entry(p, struct vfsmount, mnt_list);
		struct path p, tmp = env->root_path;

		p.dentry = mnt->mnt_root;
		p.mnt = mnt;
		spin_lock(&dcache_lock);
		path = __d_path(&p, &tmp,
				path_buf, PAGE_SIZE);
		spin_unlock(&dcache_lock);
		if (IS_ERR(path))
			continue;

		if (check_one_vfsmount(mnt)) {
			eprintk_ctx("Unsupported filesystem %s\n", mnt->mnt_sb->s_type->name);
			*caps |= (1<<CPT_UNSUPPORTED_FSTYPE);
		}
	}
	up_read(&namespace_sem);
}

int cpt_vps_caps(struct cpt_context *ctx, __u32 *caps)
{
	struct task_struct *p;
	struct task_struct *root;
	struct ve_struct *env;
	struct ve_struct *old_env;
	struct nsproxy *old_ns;
	struct mnt_namespace *n;
	int err;
	unsigned int flags = test_cpu_caps_and_features();

	if (!ctx->ve_id)
		return -EINVAL;

	env = get_ve_by_id(ctx->ve_id);
	if (env == NULL)
		return -ESRCH;

	down_read(&env->op_sem);
	err = -ESRCH;
	if (!env->is_running) {
		eprintk_ctx("CT is not running\n");
		goto out_noenv;
	}

	err = -EBUSY;
	if (env->is_locked) {
		eprintk_ctx("CT is locked\n");
		goto out_noenv;
	}

	*caps = flags & ((1<<CPT_CPU_X86_CMOV) | (1 << CPT_NO_IPV6));
#ifdef CONFIG_X86_64
	*caps |= flags & (1<<CPT_CPU_X86_SYSCALL);
#endif
	if (flags & (1 << CPT_SLM_DMPRST)) {
		eprintk_ctx("SLM is enabled, but slm_dmprst module is not loaded\n");
		*caps |= (1 << CPT_SLM_DMPRST);
	}

	old_env = set_exec_env(env);
	old_ns = current->nsproxy;
	current->nsproxy = env->ve_ns;

	check_unsupported_netdevices(ctx, caps);

	read_lock(&tasklist_lock);
	root = find_task_by_pid_ns(1, current->nsproxy->pid_ns);
	if (!root) {
		read_unlock(&tasklist_lock);
		eprintk_ctx("cannot find ve init\n");
		err = -ESRCH;
		goto out;
	}
	get_task_struct(root);
	for (p = __first_task_ve(env); p != NULL ; p = __next_task_ve(env, p))
		check_one_process(ctx, caps, flags, env, root, p);
	read_unlock(&tasklist_lock);

	task_lock(root);
	n = NULL;
	if (root->nsproxy) {
		n = root->nsproxy->mnt_ns;
		if (n)
			get_mnt_ns(n);
	}
	task_unlock(root);
	if (n) {
		char *path_buf;

		path_buf = (char *) __get_free_page(GFP_KERNEL);
		if (!path_buf) {
			put_mnt_ns(n);
			err = -ENOMEM;
			goto out_root;
		}

		check_unsupported_mounts(ctx, caps, env, n, path_buf);

		free_page((unsigned long) path_buf);
		put_mnt_ns(n);
	}

	err = 0;

out_root:
	put_task_struct(root);
out:
	current->nsproxy = old_ns;
	set_exec_env(old_env);
out_noenv:
	up_read(&env->op_sem);
	put_ve(env);

	return err;
}
