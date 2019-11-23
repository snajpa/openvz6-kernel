/*
 *  linux/fs/proc/array.c
 *
 *  Copyright (C) 1992  by Linus Torvalds
 *  based on ideas by Darren Senn
 *
 * Fixes:
 * Michael. K. Johnson: stat,statm extensions.
 *                      <johnsonm@stolaf.edu>
 *
 * Pauline Middelink :  Made cmdline,envline only break at '\0's, to
 *                      make sure SET_PROCTITLE works. Also removed
 *                      bad '!' which forced address recalculation for
 *                      EVERY character on the current page.
 *                      <middelin@polyware.iaf.nl>
 *
 * Danny ter Haar    :	added cpuinfo
 *			<dth@cistron.nl>
 *
 * Alessandro Rubini :  profile extension.
 *                      <rubini@ipvvis.unipv.it>
 *
 * Jeff Tranter      :  added BogoMips field to cpuinfo
 *                      <Jeff_Tranter@Mitel.COM>
 *
 * Bruno Haible      :  remove 4K limit for the maps file
 *			<haible@ma2s2.mathematik.uni-karlsruhe.de>
 *
 * Yves Arrouye      :  remove removal of trailing spaces in get_array.
 *			<Yves.Arrouye@marin.fdn.fr>
 *
 * Jerome Forissier  :  added per-CPU time information to /proc/stat
 *                      and /proc/<pid>/cpu extension
 *                      <forissier@isia.cma.fr>
 *			- Incorporation and non-SMP safe operation
 *			of forissier patch in 2.1.78 by
 *			Hans Marcus <crowbar@concepts.nl>
 *
 * aeb@cwi.nl        :  /proc/partitions
 *
 *
 * Alan Cox	     :  security fixes.
 *			<alan@lxorguk.ukuu.org.uk>
 *
 * Al Viro           :  safe handling of mm_struct
 *
 * Gerhard Wichert   :  added BIGMEM support
 * Siemens AG           <Gerhard.Wichert@pdb.siemens.de>
 *
 * Al Viro & Jeff Garzik :  moved most of the thing into base.c and
 *			 :  proc_misc.c. The rest may eventually go into
 *			 :  base.c too.
 */

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/time.h>
#include <linux/kernel.h>
#include <linux/kernel_stat.h>
#include <linux/tty.h>
#include <linux/string.h>
#include <linux/mman.h>
#include <linux/proc_fs.h>
#include <linux/ioport.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/signal.h>
#include <linux/highmem.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/times.h>
#include <linux/cpuset.h>
#include <linux/rcupdate.h>
#include <linux/delayacct.h>
#include <linux/seq_file.h>
#include <linux/pid_namespace.h>
#include <linux/nospec.h>
#include <linux/prctl.h>
#include <linux/ptrace.h>
#include <linux/tracehook.h>
#include <linux/utrace.h>

#include <bc/beancounter.h>

#include <asm/pgtable.h>
#include <asm/processor.h>
#include "internal.h"

static inline void task_name(struct seq_file *m, struct task_struct *p)
{
	int i;
	char *buf, *end;
	char *name;
	char tcomm[sizeof(p->comm)];

	get_task_comm(tcomm, p);

	seq_printf(m, "Name:\t");
	end = m->buf + m->size;
	buf = m->buf + m->count;
	name = tcomm;
	i = sizeof(tcomm);
	while (i && (buf < end)) {
		unsigned char c = *name;
		name++;
		i--;
		*buf = c;
		if (!c)
			break;
		if (c == '\\') {
			buf++;
			if (buf < end)
				*buf++ = c;
			continue;
		}
		if (c == '\n') {
			*buf++ = '\\';
			if (buf < end)
				*buf++ = 'n';
			continue;
		}
		buf++;
	}
	m->count = buf - m->buf;
	seq_printf(m, "\n");
}

/*
 * The task state array is a strange "bitmap" of
 * reasons to sleep. Thus "running" is zero, and
 * you can test for combinations of others with
 * simple bit tests.
 */
static const char *task_state_array[] = {
	"R (running)",		/*  0 */
	"S (sleeping)",		/*  1 */
	"D (disk sleep)",	/*  2 */
	"T (stopped)",		/*  4 */
	"T (tracing stop)",	/*  8 */
	"Z (zombie)",		/* 16 */
	"X (dead)"		/* 32 */
};

static inline const char *get_task_state(struct task_struct *tsk)
{
	unsigned int state = (tsk->state & TASK_REPORT) | tsk->exit_state;
	const char **p = &task_state_array[0];

	while (state) {
		p++;
		state >>= 1;
	}
	return *p;
}

static int task_virtual_pid(struct task_struct *t)
{
	struct pid *pid;

	pid = task_pid(t);
	/*
	 * this will give wrong result for tasks,
	 * that failed to enter VE, but that's OK
	 */
	return pid ? pid->numbers[pid->level].nr : 0;
}

static inline void task_state(struct seq_file *m, struct pid_namespace *ns,
				struct pid *pid, struct task_struct *p)
{
	struct group_info *group_info;
	int g;
	struct fdtable *fdt = NULL;
	const struct cred *cred;
	pid_t ppid, tpid, vpid;

	rcu_read_lock();
	ppid = pid_alive(p) ? ve_task_ppid_nr_ns(p, ns) : 0;

	tpid = 0;
	if (pid_alive(p)) {
		struct task_struct *tracer = tracehook_tracer_task(p);
		if (tracer)
			tpid = task_pid_nr_ns(tracer, ns);
	}
	vpid = task_virtual_pid(p);
	cred = get_task_cred(p);
	seq_printf(m,
		"State:\t%s\n"
		"Tgid:\t%d\n"
		"Pid:\t%d\n"
		"PPid:\t%d\n"
		"TracerPid:\t%d\n"
		"Uid:\t%d\t%d\t%d\t%d\n"
		"Gid:\t%d\t%d\t%d\t%d\n",
		get_task_state(p),
		task_tgid_nr_ns(p, ns),
		pid_nr_ns(pid, ns),
		ppid, tpid,
		cred->uid, cred->euid, cred->suid, cred->fsuid,
		cred->gid, cred->egid, cred->sgid, cred->fsgid);

	task_utrace_proc_status(m, p);

	task_lock(p);
	if (p->files)
		fdt = files_fdtable(p->files);
	seq_printf(m,
		"FDSize:\t%d\n"
		"Groups:\t",
		fdt ? fdt->max_fds : 0);
	rcu_read_unlock();

	group_info = cred->group_info;
	task_unlock(p);

	for (g = 0; g < group_info->ngroups; g++)
		seq_printf(m, "%d ", GROUP_AT(group_info, g));
	put_cred(cred);

	seq_printf(m, "\n");

	seq_printf(m, "envID:\t%d\nVPid:\t%d\n",
			p->ve_task_info.owner_env->veid, vpid);
	seq_printf(m, "StopState:\t%u\n", p->stopped_state);
}

static void render_sigset_t(struct seq_file *m, const char *header,
				sigset_t *set)
{
	int i;

	seq_printf(m, "%s", header);

	i = _NSIG;
	do {
		int x = 0;

		i -= 4;
		if (sigismember(set, i+1)) x |= 1;
		if (sigismember(set, i+2)) x |= 2;
		if (sigismember(set, i+3)) x |= 4;
		if (sigismember(set, i+4)) x |= 8;
		seq_printf(m, "%x", x);
	} while (i >= 4);

	seq_printf(m, "\n");
}

static void collect_sigign_sigcatch(struct task_struct *p, sigset_t *ign,
				    sigset_t *catch)
{
	struct k_sigaction *k;
	int i;

	k = p->sighand->action;
	for (i = 1; i <= _NSIG; ++i, ++k) {
		if (k->sa.sa_handler == SIG_IGN)
			sigaddset(ign, i);
		else if (k->sa.sa_handler != SIG_DFL)
			sigaddset(catch, i);
	}
}

void task_sig(struct seq_file *m, struct task_struct *p)
{
	unsigned long flags;
	sigset_t pending, shpending, blocked, ignored, caught, saved;
	int num_threads = 0;
	unsigned long qsize = 0;
	unsigned long qlim = 0;

	sigemptyset(&pending);
	sigemptyset(&shpending);
	sigemptyset(&blocked);
	sigemptyset(&ignored);
	sigemptyset(&caught);
	sigemptyset(&saved);

	if (lock_task_sighand(p, &flags)) {
		pending = p->pending.signal;
		shpending = p->signal->shared_pending.signal;
		blocked = p->blocked;
		saved = p->saved_sigmask;
		collect_sigign_sigcatch(p, &ignored, &caught);
		num_threads = atomic_read(&p->signal->count);
		qsize = atomic_read(&__task_cred(p)->user->sigpending);
		qlim = p->signal->rlim[RLIMIT_SIGPENDING].rlim_cur;
		unlock_task_sighand(p, &flags);
	}

	seq_printf(m, "Threads:\t%d\n", num_threads);
	seq_printf(m, "SigQ:\t%lu/%lu\n", qsize, qlim);

	/* render them all */
	render_sigset_t(m, "SigPnd:\t", &pending);
	render_sigset_t(m, "ShdPnd:\t", &shpending);
	render_sigset_t(m, "SigBlk:\t", &blocked);
	render_sigset_t(m, "SigIgn:\t", &ignored);
	render_sigset_t(m, "SigCgt:\t", &caught);
	render_sigset_t(m, "SigSvd:\t", &saved);
}

static void render_cap_t(struct seq_file *m, const char *header,
			kernel_cap_t *a)
{
	unsigned __capi;

	seq_printf(m, "%s", header);
	CAP_FOR_EACH_U32(__capi) {
		seq_printf(m, "%08x",
			   a->cap[(_KERNEL_CAPABILITY_U32S-1) - __capi]);
	}
	seq_printf(m, "\n");
}

static inline void task_cap(struct seq_file *m, struct task_struct *p)
{
	const struct cred *cred;
	kernel_cap_t cap_inheritable, cap_permitted, cap_effective, cap_bset;
	struct ve_struct *ve = get_exec_env();

	rcu_read_lock();
	cred = __task_cred(p);
	cap_inheritable	= cred->cap_inheritable;
	cap_permitted	= cred->cap_permitted;
	cap_effective	= cred->cap_effective;
	cap_bset	= cred->cap_bset;
	rcu_read_unlock();

	if (!ve_is_super(ve)) {
		if (!cap_raised(ve->ve_cap_bset, CAP_NET_ADMIN))
			cap_swap_all(CAP_VE_NET_ADMIN, CAP_NET_ADMIN,
				      &cap_effective,
				      &cap_inheritable,
				      &cap_permitted,
				      &cred->cap_effective,
				      &cred->cap_inheritable,
				      &cred->cap_permitted);

		if (!cap_raised(ve->ve_cap_bset, CAP_SYS_ADMIN))
			cap_swap_all(CAP_VE_SYS_ADMIN, CAP_SYS_ADMIN,
				      &cap_effective,
				      &cap_inheritable,
				      &cap_permitted,
				      &cred->cap_effective,
				      &cred->cap_inheritable,
				      &cred->cap_permitted);
	}

	render_cap_t(m, "CapInh:\t", &cap_inheritable);
	render_cap_t(m, "CapPrm:\t", &cap_permitted);
	render_cap_t(m, "CapEff:\t", &cap_effective);
	render_cap_t(m, "CapBnd:\t", &cap_bset);
}

static inline void task_seccomp(struct seq_file *m, struct task_struct *p)
{
	seq_printf(m, "Speculation_Store_Bypass:\t");
	switch (arch_prctl_spec_ctrl_get(p, PR_SPEC_STORE_BYPASS)) {
	case -EINVAL:
		seq_printf(m, "unknown");
		break;
	case PR_SPEC_NOT_AFFECTED:
		seq_printf(m, "not vulnerable");
		break;
	case PR_SPEC_PRCTL | PR_SPEC_FORCE_DISABLE:
		seq_printf(m, "thread force mitigated");
		break;
	case PR_SPEC_PRCTL | PR_SPEC_DISABLE:
		seq_printf(m, "thread mitigated");
		break;
	case PR_SPEC_PRCTL | PR_SPEC_ENABLE:
		seq_printf(m, "thread vulnerable");
		break;
	case PR_SPEC_DISABLE:
		seq_printf(m, "globally mitigated");
		break;
	default:
		seq_printf(m, "vulnerable");
		break;
	}
	seq_putc(m, '\n');
}

#ifdef CONFIG_BEANCOUNTERS
static inline void ub_dump_task_info(struct task_struct *tsk,
		char *stsk, int ltsk, char *smm, int lmm)
{
	snprintf(stsk, ltsk, "%u", get_task_ub_top(tsk)->ub_uid);
	task_lock(tsk);
	if (tsk->mm)
		snprintf(smm, lmm, "%u", mm_ub_top(tsk->mm)->ub_uid);
	else
		strncpy(smm, "N/A", lmm);
	task_unlock(tsk);
}
#endif

static inline void task_context_switch_counts(struct seq_file *m,
						struct task_struct *p)
{
	seq_printf(m,	"voluntary_ctxt_switches:\t%lu\n"
			"nonvoluntary_ctxt_switches:\t%lu\n",
			p->nvcsw,
			p->nivcsw);
}

int proc_pid_status(struct seq_file *m, struct pid_namespace *ns,
			struct pid *pid, struct task_struct *task)
{
	struct mm_struct *mm = get_task_mm(task);
#ifdef CONFIG_BEANCOUNTERS
	char tsk_ub_info[64], mm_ub_info[64];
#endif

	task_name(m, task);
	task_state(m, ns, pid, task);

	if (mm) {
		task_mem(m, mm);
		mmput(mm);
	}
	task_sig(m, task);
	task_cap(m, task);
	task_seccomp(m, task);
	cpuset_task_status_allowed(m, task);
	task_context_switch_counts(m, task);
#ifdef CONFIG_BEANCOUNTERS
	ub_dump_task_info(task,
			tsk_ub_info, sizeof(tsk_ub_info),
			mm_ub_info, sizeof(mm_ub_info));

	seq_printf(m, "TaskUB:\t%s\n", tsk_ub_info);
	seq_printf(m, "MMUB:\t%s\n", mm_ub_info);
#endif
	return 0;
}

static int do_task_stat(struct seq_file *m, struct pid_namespace *ns,
			struct pid *pid, struct task_struct *task, int whole)
{
	unsigned long vsize, eip, esp, wchan = ~0UL;
	long priority, nice;
	int tty_pgrp = -1, tty_nr = 0;
	sigset_t sigign, sigcatch;
	char state;
	pid_t ppid = 0, pgid = -1, sid = -1;
	int num_threads = 0;
	int permitted;
	struct mm_struct *mm;
	unsigned long long start_time;
	unsigned long cmin_flt = 0, cmaj_flt = 0;
	unsigned long  min_flt = 0,  maj_flt = 0;
	cputime_t cutime, cstime, utime, stime;
	cputime_t cgtime, gtime;
	unsigned long rsslim = 0;
	char tcomm[sizeof(task->comm)];
	unsigned long flags;
#ifdef CONFIG_BEANCOUNTERS
	char ub_task_info[64];
	char ub_mm_info[64];
#endif
	int is_super = ve_is_super(get_exec_env());

	state = *get_task_state(task);
	vsize = eip = esp = 0;
	permitted = ptrace_may_access(task, PTRACE_MODE_READ);
	mm = get_task_mm(task);
	if (mm) {
		vsize = task_vsize(mm);
		if (permitted) {
			eip = KSTK_EIP(task);
			esp = KSTK_ESP(task);
		}
	}

	get_task_comm(tcomm, task);

	sigemptyset(&sigign);
	sigemptyset(&sigcatch);
	cutime = cstime = utime = stime = cputime_zero;
	cgtime = gtime = cputime_zero;

	if (lock_task_sighand(task, &flags)) {
		struct signal_struct *sig = task->signal;

		if (sig->tty) {
			struct pid *pgrp = tty_get_pgrp(sig->tty);
			tty_pgrp = pid_nr_ns(pgrp, ns);
			put_pid(pgrp);
			tty_nr = new_encode_dev(tty_devnum(sig->tty));
		}

		num_threads = atomic_read(&sig->count);
		collect_sigign_sigcatch(task, &sigign, &sigcatch);

		cmin_flt = sig->cmin_flt;
		cmaj_flt = sig->cmaj_flt;
		cutime = sig->cutime;
		cstime = sig->cstime;
		cgtime = sig->cgtime;
		rsslim = sig->rlim[RLIMIT_RSS].rlim_cur;

		/* add up live thread stats at the group level */
		if (whole) {
			struct task_struct *t = task;
			do {
				min_flt += t->min_flt;
				maj_flt += t->maj_flt;
				gtime = cputime_add(gtime, t->gtime);
				t = next_thread(t);
			} while (t != task);

			min_flt += sig->min_flt;
			maj_flt += sig->maj_flt;
			thread_group_times(task, &utime, &stime);
			gtime = cputime_add(gtime, sig->gtime);
		}

		sid = task_session_nr_ns(task, ns);
		ppid = ve_task_ppid_nr_ns(task, ns);
		pgid = task_pgrp_nr_ns(task, ns);

		unlock_task_sighand(task, &flags);
	}

	if (permitted && (!whole || num_threads < 2))
		wchan = get_wchan(task);
	if (!whole) {
		min_flt = task->min_flt;
		maj_flt = task->maj_flt;
		task_times(task, &utime, &stime);
		gtime = task->gtime;
	}

	/* scale priority and nice values from timeslices to -20..20 */
	/* to make it look like a "normal" Unix priority/nice value  */
	priority = task_prio(task);
	nice = task_nice(task);

	/* Temporary variable needed for gcc-2.96 */
	/* convert timespec -> nsec*/
	start_time =
		(unsigned long long)task->real_start_time.tv_sec * NSEC_PER_SEC
				+ task->real_start_time.tv_nsec;
#ifdef CONFIG_VE
	if (!is_super) {
		struct timespec *ve_start_ts =
				&get_exec_env()->real_start_timespec;
		start_time -=
			(unsigned long long)ve_start_ts->tv_sec * NSEC_PER_SEC
				+ ve_start_ts->tv_nsec;
	}
	/* tasks inside a CT can have negative start time e.g. if the CT was
	 * migrated from another hw node, in which case we will report 0 in
	 * order not to confuse userspace */
	if ((s64)start_time < 0)
		start_time = 0;
#endif
	/* convert nsec -> ticks */
	start_time = nsec_to_clock_t(start_time);

#ifdef CONFIG_BEANCOUNTERS
	ub_dump_task_info(task, ub_task_info, sizeof(ub_task_info),
				ub_mm_info, sizeof(ub_mm_info));
#endif

	seq_printf(m, "%d (%s) %c %d %d %d %d %d %u %lu \
%lu %lu %lu %lu %lu %ld %ld %ld %ld %d 0 %llu %lu %ld %lu %lu %lu %lu %lu \
%lu %lu %lu %lu %lu %lu %lu %lu %d %d %u %u %llu %lu %ld"
#ifdef CONFIG_VE
	" 0 0 0 0 0 %d %u"
#endif
#ifdef CONFIG_BEANCOUNTERS
	" %s %s"
#endif
	"\n",
		pid_nr_ns(pid, ns),
		tcomm,
		state,
		ppid,
		pgid,
		sid,
		tty_nr,
		tty_pgrp,
		task->flags,
		min_flt,
		cmin_flt,
		maj_flt,
		cmaj_flt,
		cputime_to_clock_t(utime),
		cputime_to_clock_t(stime),
		cputime_to_clock_t(cutime),
		cputime_to_clock_t(cstime),
		priority,
		nice,
		num_threads,
		start_time,
		vsize,
		mm ? get_mm_rss(mm) : 0,
		rsslim,
		mm ? (permitted ? mm->start_code : 1) : 0,
		mm ? (permitted ? mm->end_code : 1) : 0,
		(permitted && mm) ? mm->start_stack : 0,
		esp,
		eip,
		/* The signal information here is obsolete.
		 * It must be decimal for Linux 2.0 compatibility.
		 * Use /proc/#/status for real-time signals.
		 */
		task->pending.signal.sig[0] & 0x7fffffffUL,
		task->blocked.sig[0] & 0x7fffffffUL,
		sigign      .sig[0] & 0x7fffffffUL,
		sigcatch    .sig[0] & 0x7fffffffUL,
		wchan,
		0UL,
		0UL,
		task->exit_signal,
		is_super ? task_cpu(task) : task_vcpu_id(task),
		task->rt_priority,
		task->policy,
		(unsigned long long)delayacct_blkio_ticks(task),
		cputime_to_clock_t(gtime),
		cputime_to_clock_t(cgtime)
#ifdef CONFIG_VE
		, task_pid_nr_ns(task, task_active_pid_ns(task)),
		VEID(VE_TASK_INFO(task)->owner_env)
#endif
#ifdef CONFIG_BEANCOUNTERS
		, ub_task_info,
		ub_mm_info
#endif
		);
	if (mm)
		mmput(mm);
	return 0;
}

int proc_tid_stat(struct seq_file *m, struct pid_namespace *ns,
			struct pid *pid, struct task_struct *task)
{
	return do_task_stat(m, ns, pid, task, 0);
}

int proc_tgid_stat(struct seq_file *m, struct pid_namespace *ns,
			struct pid *pid, struct task_struct *task)
{
	return do_task_stat(m, ns, pid, task, 1);
}

int proc_pid_statm(struct seq_file *m, struct pid_namespace *ns,
			struct pid *pid, struct task_struct *task)
{
	unsigned long size = 0, resident = 0, shared = 0, text = 0, data = 0;
	struct mm_struct *mm = get_task_mm(task);

	if (mm) {
		size = task_statm(mm, &shared, &text, &data, &resident);
		mmput(mm);
	}
	seq_printf(m, "%lu %lu %lu %lu 0 %lu 0\n",
			size, resident, shared, text, data);

	return 0;
}
