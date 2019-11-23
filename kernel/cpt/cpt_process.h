#include <linux/sched.h>

int cpt_collect_signals(cpt_context_t *);
int cpt_dump_signal(struct cpt_context *);
int cpt_dump_sighand(struct cpt_context *);
int cpt_collect_posix_timers(struct cpt_context *);
int cpt_dump_posix_timers(struct cpt_context *);
int cpt_dump_tasks(struct cpt_context *);

int rst_posix_timers(struct cpt_task_image *ti, struct cpt_context *ctx);
int rst_signal_complete(struct cpt_task_image *ti, int *exiting, struct cpt_context *ctx);
int restore_signal_struct(struct cpt_task_image *ti, int *exiting, cpt_context_t *ctx);
__u32 rst_signal_flag(struct cpt_task_image *ti, struct cpt_context *ctx);

int rst_restore_process(struct cpt_context *ctx);
int rst_process_linkage(struct cpt_context *ctx);

int check_task_state(struct task_struct *tsk, struct cpt_context *ctx);
int cpt_skip_task(struct task_struct *tsk);

struct pid *rst_alloc_pid(pid_t vnr);

static inline pid_t cpt_pid_nr(struct pid *pid)
{
	return pid_nr_ns(pid, current->nsproxy->pid_ns);
}

static inline pid_t cpt_task_pid_nr(struct task_struct *p, enum pid_type type)
{
	return __task_pid_nr_ns(p, type, current->nsproxy->pid_ns);
}
