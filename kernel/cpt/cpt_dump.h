int cpt_dump(struct cpt_context *cpt);
int rst_undump(struct cpt_context *cpt);
int cpt_suspend(struct cpt_context *cpt);
int cpt_resume(struct cpt_context *cpt);
int cpt_kill(struct cpt_context *cpt);
int rst_clean(struct cpt_context *cpt);
int rst_resume(struct cpt_context *cpt);
int rst_kill(struct cpt_context *cpt);

int cpt_freeze_one(pid_t pid, int freeze);
int cpt_vps_suspend(struct cpt_context *ctx);
int vps_rst_undump(struct cpt_context *ctx);

int cpt_vps_caps(struct cpt_context *ctx, __u32 *caps);

int cpt_check_unsupported(struct task_struct *tsk, struct cpt_context *ctx);

extern unsigned long suspend_timeout_min;
extern unsigned long suspend_timeout_max;
extern unsigned int suspend_timeout;

extern unsigned int kill_external;
