#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/cpuset.h>
#include <linux/module.h>
#include <linux/oom.h>

#include <bc/beancounter.h>
#include <bc/oom_kill.h>
#include <bc/vmpages.h>

#define UB_OOM_TIMEOUT	(5 * HZ)

void ub_oom_start(struct oom_control *oom_ctrl)
{
	current->task_bc.oom_generation = oom_ctrl->generation;
}

static inline struct user_beancounter *oom_ctrl_ub(struct oom_control *ctrl)
{
	if (ctrl == &global_oom_ctrl)
		return NULL;

	return container_of(ctrl, struct user_beancounter, oom_ctrl);
}

static inline int oom_ctrl_id(struct oom_control *ctrl)
{
	struct user_beancounter *ub = oom_ctrl_ub(ctrl);

	return ub ? top_beancounter(ub)->ub_uid : -1;
}

static inline int oom_ctrl_ratelimit(struct oom_control *ctrl)
{
	struct user_beancounter *ub = oom_ctrl_ub(ctrl);

	/* do not flood kernel log if oom occurred in a mem cgroup */
	if (ub && ub->parent)
		return 0;

	return ub ? __ratelimit(&ub->ub_ratelimit) : printk_ratelimit();
}

static void __ub_release_oom_control(struct oom_control *oom_ctrl, char *why)
{
	if (oom_ctrl_ratelimit(oom_ctrl)) {
		struct user_beancounter *ub = oom_ctrl_ub(oom_ctrl);

		printk(KERN_WARNING"oom-killer in ub %d generation %d ends: %s\n",
		       oom_ctrl_id(oom_ctrl), oom_ctrl->generation, why);

		if (ub)
			__show_ub_mem(ub);
		else
			show_mem(SHOW_MEM_FILTER_NODES);
	}

	oom_ctrl->kill_counter = 0;
	oom_ctrl->generation++;

	/* if there is time to sleep in ub_oom_lock -> sleep will continue */
	wake_up_all(&oom_ctrl->wq);
}

static void ub_release_oom_control(struct oom_control *oom_ctrl)
{
	spin_lock(&oom_ctrl->lock);
	__ub_release_oom_control(oom_ctrl, "task died");
	spin_unlock(&oom_ctrl->lock);
}

/*
 * Must be called under task_lock() held
 */
void ub_oom_mark_mm(struct mm_struct *mm, struct oom_control *oom_ctrl)
{
	mm_ub_top(mm)->ub_parms[UB_OOMGUARPAGES].failcnt++;

	if (oom_ctrl == &global_oom_ctrl ||
	    ub_is_descendant(mm_ub(mm), oom_ctrl_ub(oom_ctrl)))
		mm->oom_ctrl = oom_ctrl;
	else {
		/*
		 * Task can be killed when using either global oom ctl
		 * or by mm->mm_ub one. In other case we must release ctl now.
		 * When this task will die it'll have to decide with ctl
		 * to use lokking at this flag and we have to sure it
		 * will use the proper one.
		 */
		__ub_release_oom_control(oom_ctrl, "mark bug");
		WARN_ON(1);
	}
}

static inline int ub_oom_completed(struct oom_control *oom_ctrl)
{
	if (test_thread_flag(TIF_MEMDIE))
		/* we were oom killed - just die */
		return 1;
	if (current->task_bc.oom_generation != oom_ctrl->generation)
		/* some task was succesfully killed */
		return 1;
	return 0;
}

static void ub_clear_oom(void)
{
	struct user_beancounter *ub;

	rcu_read_lock();
	for_each_top_beancounter(ub)
		clear_bit(UB_OOM_NOPROC, &ub->ub_flags);
	rcu_read_unlock();
}

static struct oom_control *parent_oom_ctrl(struct oom_control *oom_ctrl)
{
	struct user_beancounter *ub;

	ub = oom_ctrl_ub(oom_ctrl);
	if (!ub)
		return NULL;
	if (!ub->parent)
		return &global_oom_ctrl;
	return &ub->parent->oom_ctrl;
}

static int wait_parent_oom(struct oom_control *oom_ctrl)
{
	while ((oom_ctrl = parent_oom_ctrl(oom_ctrl)) != NULL) {
		if (oom_ctrl->kill_counter) {
			wait_event_killable(oom_ctrl->wq,
					    oom_ctrl->kill_counter == 0);
			return -EAGAIN;
		}
	}
	return 0;
}

int ub_oom_lock(struct oom_control *oom_ctrl, gfp_t gfp_mask)
{
	int timeout;
	DEFINE_WAIT(oom_w);

	if (wait_parent_oom(oom_ctrl)) {
		/*
		 * Check if global OOM killeris on the way. If so -
		 * let the senior handle the situation.
		 */
		return -EAGAIN;
	}

	spin_lock(&oom_ctrl->lock);
	if (!oom_ctrl->kill_counter && !ub_oom_completed(oom_ctrl))
		goto out_do_oom;

	timeout = UB_OOM_TIMEOUT;
	while (1) {
		if (ub_oom_completed(oom_ctrl)) {
			spin_unlock(&oom_ctrl->lock);
			/*
			 * We raced with some other OOM killer and need
			 * to update generation to be sure, that we can
			 * call OOM killer on next loop iteration.
			 */
			ub_oom_start(oom_ctrl);
			return -EAGAIN;
		}

		if (timeout == 0) {
			/*
			 * Time is up, let's kill somebody else but
			 * release the oom ctl since the stuck task
			 * wasn't able to do it.
			 */
			__ub_release_oom_control(oom_ctrl, "timeout");
			break;
		}

		__set_current_state(TASK_UNINTERRUPTIBLE);
		add_wait_queue(&oom_ctrl->wq, &oom_w);
		spin_unlock(&oom_ctrl->lock);

		timeout = schedule_timeout(timeout);

		spin_lock(&oom_ctrl->lock);
		remove_wait_queue(&oom_ctrl->wq, &oom_w);

	}

out_do_oom:
	ub_clear_oom();

	if (oom_ctrl_ratelimit(oom_ctrl)) {
		struct user_beancounter *ub = oom_ctrl_ub(oom_ctrl);

		printk(KERN_WARNING"%d (%s) invoked oom-killer in ub %d "
			"generation %d gfp 0x%x\n",
			current->pid, current->comm, oom_ctrl_id(oom_ctrl),
			oom_ctrl->generation, gfp_mask);

		if (ub) {
			show_ub_mem(ub);
		} else {
			dump_stack();
			show_mem(SHOW_MEM_FILTER_NODES);
			show_slab_info();
		}
	}

	return 0;
}

long ub_current_overdraft(struct user_beancounter *ub)
{
	return ((ub->ub_parms[UB_KMEMSIZE].held
		  + ub->ub_parms[UB_TCPSNDBUF].held
		  + ub->ub_parms[UB_TCPRCVBUF].held
		  + ub->ub_parms[UB_OTHERSOCKBUF].held
		  + ub->ub_parms[UB_DGRAMRCVBUF].held)
		 >> PAGE_SHIFT) - ub_oomguarpages_left(ub);
}

int ub_oom_task_skip(struct user_beancounter *ub, struct task_struct *tsk)
{
	struct user_beancounter *mm_ub;

	if (ub == NULL)
		return 0;

	task_lock(tsk);
	if (tsk->mm == NULL)
		mm_ub = NULL;
	else
		mm_ub = mm_ub(tsk->mm);

	task_unlock(tsk);

	return !ub_is_descendant(mm_ub, ub);
}

struct user_beancounter *ub_oom_select_worst(void)
{
	struct user_beancounter *ub, *walkp;
	long ub_maxover;

	ub_maxover = 0;
	ub = NULL;

	rcu_read_lock();
	for_each_top_beancounter(walkp) {
		long ub_overdraft;

		if (test_bit(UB_OOM_NOPROC, &walkp->ub_flags))
			continue;

		ub_overdraft = ub_current_overdraft(walkp);
		if (ub_overdraft > ub_maxover && get_beancounter_rcu(walkp)) {
			put_beancounter(ub);
			ub = walkp;
			ub_maxover = ub_overdraft;
		}
	}

	if (ub) {
		set_bit(UB_OOM_NOPROC, &ub->ub_flags);
		printk(KERN_INFO "OOM selected worst BC %d (overdraft %lu):\n",
				ub->ub_uid, ub_maxover);
		__show_ub_mem(ub);
	}
	rcu_read_unlock();

	return ub;
}

void ub_oom_unlock(struct oom_control *oom_ctrl)
{
	spin_unlock(&oom_ctrl->lock);
}

void ub_oom_mm_dead(struct mm_struct *mm)
{
	ub_release_oom_control(mm->oom_ctrl);
}

unsigned long ub_oom_total_pages(struct user_beancounter *ub)
{
	ub = top_beancounter(ub);
	return min(totalram_pages, ub->ub_parms[UB_PHYSPAGES].limit) +
	       min_t(unsigned long, total_swap_pages,
			       ub->ub_parms[UB_SWAPPAGES].limit);
}

int out_of_memory_in_ub(struct user_beancounter *ub, gfp_t gfp_mask)
{
	struct task_struct *p;
	int res = 0;
	unsigned long ub_mem_pages;
	int points;
	char message[48];

	if (ub_oom_lock(&ub->oom_ctrl, gfp_mask))
		goto out;

	snprintf(message, sizeof(message),
		 "Out of memory in %sUB %u",
		 ub->parent ? "mem cgroup inside " : "",
		 top_beancounter(ub)->ub_uid);

	ub_mem_pages = ub_oom_total_pages(ub);
	read_lock(&tasklist_lock);

	do {
		p = select_bad_process(&points, ub_mem_pages, ub, NULL, NULL);
		if (PTR_ERR(p) == -1UL || !p) {
			__ub_release_oom_control(&ub->oom_ctrl, "no victims");
			break;
		}
	} while (oom_kill_process(p, gfp_mask, 0, points, ub_mem_pages,
				  ub, NULL, NULL, message));

	read_unlock(&tasklist_lock);
	ub_oom_unlock(&ub->oom_ctrl);

	if (!p)
		res = -ENOMEM;
out:
	/*
	 * Give "p" a good chance of killing itself before we
	 * retry to allocate memory unless "p" is current
	 */
	if (!test_thread_flag(TIF_MEMDIE))
		schedule_timeout_uninterruptible(1);

	return res;
}

struct oom_control global_oom_ctrl;

void init_oom_control(struct oom_control *oom_ctrl)
{
	spin_lock_init(&oom_ctrl->lock);
	init_waitqueue_head(&oom_ctrl->wq);
}
