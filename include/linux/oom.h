#ifndef __INCLUDE_LINUX_OOM_H
#define __INCLUDE_LINUX_OOM_H

/*
 * /proc/<pid>/oom_adj set to -17 protects from the oom-killer
 */
#define OOM_DISABLE (-17)
/* inclusive */
#define OOM_ADJUST_MIN (-16)
#define OOM_ADJUST_MAX 15

/*
 * /proc/<pid>/oom_score_adj set to OOM_SCORE_ADJ_MIN disables oom killing for
 * pid.
 */
#define OOM_SCORE_ADJ_MIN	(-1000)
#define OOM_SCORE_ADJ_MAX	1000
#define OOM_SCORE_ADJ_UNSET	1001

#ifdef __KERNEL__

#include <linux/sched.h>
#include <linux/types.h>
#include <linux/nodemask.h>
#include <linux/spinlock_types.h>
#include <linux/wait.h>

struct zonelist;
struct notifier_block;
struct mem_cgroup;
struct task_struct;

/*
 * Types of limitations to the nodes from which allocations may occur
 */
enum oom_constraint {
	CONSTRAINT_NONE,
	CONSTRAINT_CPUSET,
	CONSTRAINT_MEMORY_POLICY,
	CONSTRAINT_MEMCG,
};

extern int test_set_oom_score_adj(int new_val);

struct task_struct *select_bad_process(int *ppoints,
		unsigned long totalpages, struct user_beancounter *ub,
		struct mem_cgroup *mem, const nodemask_t *nodemask);
int oom_kill_process(struct task_struct *p, gfp_t gfp_mask, int order,
			    int points, unsigned long totalpages,
			    struct user_beancounter *ub, struct mem_cgroup *mem,
			    nodemask_t *nodemask, const char *message);
/* linux/mm/oom_group.c */
extern int get_task_oom_score_adj(struct task_struct *t);

extern int oom_badness(struct task_struct *p, unsigned long totalpages, long *overdraft);
extern int try_set_zonelist_oom(struct zonelist *zonelist, gfp_t gfp_flags);
extern void clear_zonelist_oom(struct zonelist *zonelist, gfp_t gfp_flags);

extern void out_of_memory(struct zonelist *zonelist, gfp_t gfp_mask,
		int order, nodemask_t *mask);
extern int register_oom_notifier(struct notifier_block *nb);
extern int unregister_oom_notifier(struct notifier_block *nb);

extern bool oom_killer_disabled;

static inline void oom_killer_disable(void)
{
	oom_killer_disabled = true;
}

static inline void oom_killer_enable(void)
{
	oom_killer_disabled = false;
}

/* The badness from the OOM killer */
extern unsigned long badness(struct task_struct *p, struct mem_cgroup *mem,
		      const nodemask_t *nodemask, unsigned long uptime);

extern struct task_struct *find_lock_task_mm(struct task_struct *p);

struct oom_control {
	int			generation;
	int			kill_counter;
	unsigned long		last_kill;
	int			oom_rage;
	spinlock_t		lock;
	wait_queue_head_t 	wq;
};

extern struct oom_control global_oom_ctrl;

extern void init_oom_control(struct oom_control *oom_ctrl);

#endif /* __KERNEL__*/
#endif /* _INCLUDE_LINUX_OOM_H */
