/*
 *
 *  kernel/cpt/cpt_process.c
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
#include <linux/poll.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/compat.h>
#include <linux/cpt_image.h>
#include <linux/nsproxy.h>
#include <linux/futex.h>
#include <linux/posix-timers.h>

#ifdef CONFIG_X86
#include <asm/i387.h>
#endif

#include <linux/cpt_obj.h>
#include <linux/cpt_context.h>
#include "cpt_ubc.h"
#include "cpt_process.h"
#include "cpt_kernel.h"

#ifdef CONFIG_X86_32
#undef task_pt_regs
#define task_pt_regs(t) ((struct pt_regs *)((t)->thread.sp0) - 1)
#endif

int check_task_state(struct task_struct *tsk, struct cpt_context *ctx)
{
#ifdef CONFIG_X86_64
	struct vm_area_struct *vma;
	if (!(task_thread_info(tsk)->flags&_TIF_IA32)) {
		if (task_pt_regs(tsk)->ip >= VSYSCALL_START &&
				task_pt_regs(tsk)->ip < VSYSCALL_END) {
			eprintk_ctx(CPT_FID "cannot be checkpointied while vsyscall, try later\n", CPT_TID(tsk));
			return -EAGAIN;
		}
		vma = find_vma(current->mm, task_pt_regs(tsk)->ip);
		if (vma && vma->vm_mm && vma->vm_start == (long)vma->vm_mm->context.vdso) {
			eprintk_ctx(CPT_FID "cannot be checkpointied while vdso, try later\n", CPT_TID(tsk));
			return -EAGAIN;
		}
	}
#endif
	return 0;
}

#ifdef CONFIG_X86

static u32 encode_segment(u32 segreg)
{
	segreg &= 0xFFFF;

	if (segreg == 0)
		return CPT_SEG_ZERO;
	if ((segreg & 3) != 3) {
		wprintk("Invalid RPL of a segment reg %x\n", segreg);
		return CPT_SEG_ZERO;
	}

	/* LDT descriptor, it is just an index to LDT array */
	if (segreg & 4)
		return CPT_SEG_LDT + (segreg >> 3);

	/* TLS descriptor. */
	if ((segreg >> 3) >= GDT_ENTRY_TLS_MIN &&
	    (segreg >> 3) <= GDT_ENTRY_TLS_MAX)
		return CPT_SEG_TLS1 + ((segreg>>3) - GDT_ENTRY_TLS_MIN);

	/* One of standard desriptors */
#ifdef CONFIG_X86_64
	if (segreg == __USER32_DS)
		return CPT_SEG_USER32_DS;
	if (segreg == __USER32_CS)
		return CPT_SEG_USER32_CS;
	if (segreg == __USER_DS)
		return CPT_SEG_USER64_DS;
	if (segreg == __USER_CS)
		return CPT_SEG_USER64_CS;
#else
	if (segreg == __USER_DS)
		return CPT_SEG_USER32_DS;
	if (segreg == __USER_CS)
		return CPT_SEG_USER32_CS;
#endif
	wprintk("Invalid segment reg %x\n", segreg);
	return CPT_SEG_ZERO;
}

#ifdef CONFIG_X86_64
static void xlate_ptregs_64_to_32(struct cpt_x86_regs *d, struct pt_regs *s,
		struct task_struct *tsk)
{
	d->cpt_ebp = s->bp;
	d->cpt_ebx = s->bx;
	d->cpt_eax = s->ax;
	d->cpt_ecx = s->cx;
	d->cpt_edx = s->dx;
	d->cpt_esi = s->si;
	d->cpt_edi = s->di;
	d->cpt_orig_eax = s->orig_ax;
	d->cpt_eip = s->ip;
	d->cpt_xcs = encode_segment(s->cs);
	d->cpt_eflags = s->flags;
	d->cpt_esp = s->sp;
	d->cpt_xss = encode_segment(s->ss);
	d->cpt_xds = encode_segment(tsk->thread.ds);
	d->cpt_xes = encode_segment(tsk->thread.es);
}

static int dump_registers(struct task_struct *tsk, struct cpt_context *ctx)
{
	cpt_open_object(NULL, ctx);

	if (task_thread_info(tsk)->flags & _TIF_IA32) {
		struct cpt_x86_regs ri;
		ri.cpt_next = sizeof(ri);
		ri.cpt_object = CPT_OBJ_X86_REGS;
		ri.cpt_hdrlen = sizeof(ri);
		ri.cpt_content = CPT_CONTENT_VOID;

		ri.cpt_debugreg[0] = tsk->thread.debugreg0;
		ri.cpt_debugreg[1] = tsk->thread.debugreg1;
		ri.cpt_debugreg[2] = tsk->thread.debugreg2;
		ri.cpt_debugreg[3] = tsk->thread.debugreg3;
		ri.cpt_debugreg[4] = 0;
		ri.cpt_debugreg[5] = 0;
		ri.cpt_debugreg[6] = tsk->thread.debugreg6;
		ri.cpt_debugreg[7] = tsk->thread.debugreg7;
		ri.cpt_fs = encode_segment(tsk->thread.fsindex);
		ri.cpt_gs = CPT_SEG_ZERO;
		ri.cpt_ugs = encode_segment(tsk->thread.gsindex);

		xlate_ptregs_64_to_32(&ri, task_pt_regs(tsk), tsk);

		ctx->write(&ri, sizeof(ri), ctx);
	} else {
		struct cpt_x86_64_regs ri;
		ri.cpt_next = sizeof(ri);
		ri.cpt_object = CPT_OBJ_X86_64_REGS;
		ri.cpt_hdrlen = sizeof(ri);
		ri.cpt_content = CPT_CONTENT_VOID;

		ri.cpt_fsbase = tsk->thread.fs;
		ri.cpt_gsbase = tsk->thread.gs;
		ri.cpt_fsindex = encode_segment(tsk->thread.fsindex);
		ri.cpt_gsindex = encode_segment(tsk->thread.gsindex);
		ri.cpt_ds = encode_segment(tsk->thread.ds);
		ri.cpt_es = encode_segment(tsk->thread.es);
		ri.cpt_debugreg[0] = tsk->thread.debugreg0;
		ri.cpt_debugreg[1] = tsk->thread.debugreg1;
		ri.cpt_debugreg[2] = tsk->thread.debugreg2;
		ri.cpt_debugreg[3] = tsk->thread.debugreg3;
		ri.cpt_debugreg[4] = 0;
		ri.cpt_debugreg[5] = 0;
		ri.cpt_debugreg[6] = tsk->thread.debugreg6;
		ri.cpt_debugreg[7] = tsk->thread.debugreg7;

		memcpy(&ri.cpt_r15, task_pt_regs(tsk), sizeof(struct pt_regs));

		ri.cpt_cs = encode_segment(task_pt_regs(tsk)->cs);
		ri.cpt_ss = encode_segment(task_pt_regs(tsk)->ss);

		ctx->write(&ri, sizeof(ri), ctx);

	}
	cpt_close_object(ctx);

	return 0;
}

#else

static int dump_registers(struct task_struct *tsk, struct cpt_context *ctx)
{
	struct cpt_x86_regs ri;
	struct pt_regs *pt_regs;

	cpt_open_object(NULL, ctx);

	ri.cpt_next = sizeof(ri);
	ri.cpt_object = CPT_OBJ_X86_REGS;
	ri.cpt_hdrlen = sizeof(ri);
	ri.cpt_content = CPT_CONTENT_VOID;

	ri.cpt_debugreg[0] = tsk->thread.debugreg0;
	ri.cpt_debugreg[1] = tsk->thread.debugreg1;
	ri.cpt_debugreg[2] = tsk->thread.debugreg2;
	ri.cpt_debugreg[3] = tsk->thread.debugreg3;
	ri.cpt_debugreg[6] = tsk->thread.debugreg6;
	ri.cpt_debugreg[7] = tsk->thread.debugreg7;

	pt_regs = task_pt_regs(tsk);

	ri.cpt_fs = encode_segment(pt_regs->fs);
	ri.cpt_gs = encode_segment(tsk->thread.gs);
	ri.cpt_ugs = encode_segment(task_user_gs(tsk));

	ri.cpt_ebx = pt_regs->bx;
	ri.cpt_ecx = pt_regs->cx;
	ri.cpt_edx = pt_regs->dx;
	ri.cpt_esi = pt_regs->si;
	ri.cpt_edi = pt_regs->di;
	ri.cpt_ebp = pt_regs->bp;
	ri.cpt_eax = pt_regs->ax;
	ri.cpt_xds = pt_regs->ds;
	ri.cpt_xes = pt_regs->es;
	ri.cpt_orig_eax = pt_regs->orig_ax;
	ri.cpt_eip = pt_regs->ip;
	ri.cpt_xcs = pt_regs->cs;
	ri.cpt_eflags = pt_regs->flags;
	ri.cpt_esp = pt_regs->sp;
	ri.cpt_xss = pt_regs->ss;

	ri.cpt_xcs = encode_segment(pt_regs->cs);
	ri.cpt_xss = encode_segment(pt_regs->ss);
	ri.cpt_xds = encode_segment(pt_regs->ds);
	ri.cpt_xes = encode_segment(pt_regs->es);

	ctx->write(&ri, sizeof(ri), ctx);
	cpt_close_object(ctx);

	return 0;
}
#endif
#endif

#ifdef CONFIG_IA64

/*
   PMD?
 */

#define _C(x) do { if ((err = (x)) < 0) { printk("atm:" CPT_FID #x " %d\n", \
						 CPT_TID(tsk), err); return -EINVAL; } } while (0) 

static int ass_to_mouth(struct cpt_ia64_regs *r, struct task_struct *tsk,
			struct cpt_context *ctx)
{
	int err;
	struct unw_frame_info info;
	struct ia64_fpreg fpval;
	int i;

	unw_init_from_blocked_task(&info, tsk);
	_C(unw_unwind_to_user(&info));

	/* NAT_BITS */
	do {
		unsigned long scratch_unat;

		scratch_unat = info.sw->caller_unat;
		if (info.pri_unat_loc)
			scratch_unat = *info.pri_unat_loc;

		r->nat[0] = ia64_get_scratch_nat_bits(task_pt_regs(tsk), scratch_unat);
		/* Just to be on safe side. */
		r->nat[0] &= 0xFFFFFFFFUL;
	} while (0);

	/* R4-R7 */
	for (i = 4; i <= 7; i++) {
		char nat = 0;
		_C(unw_access_gr(&info, i, &r->gr[i], &nat, 0));
		r->nat[0] |= (nat != 0) << i;
	}

	/* B1-B5 */
	for (i = 1; i <= 5; i++) {
		_C(unw_access_br(&info, i, &r->br[i], 0));
	}

	/* AR_EC, AR_LC */
	_C(unw_access_ar(&info, UNW_AR_EC, &r->ar_ec, 0));
	_C(unw_access_ar(&info, UNW_AR_LC, &r->ar_lc, 0));

	/* F2..F5, F16..F31 */
	for (i = 2; i <= 5; i++) {
		_C(unw_get_fr(&info, i, &fpval));
		memcpy(&r->fr[i*2], &fpval, 16);
	}
	for (i = 16; i <= 31; i++) {
		_C(unw_get_fr(&info, i, &fpval));
		memcpy(&r->fr[i*2], &fpval, 16);
	}
	return 0;
}

#undef _C

static int dump_registers(struct task_struct *tsk, struct cpt_context *ctx)
{
	int err;
	unsigned long pg;
	struct cpt_ia64_regs *r;
	struct ia64_psr *psr;
	struct switch_stack *sw;
	struct pt_regs *pt;
	void *krbs = (void *)tsk + IA64_RBS_OFFSET;
	unsigned long reg;

	if (tsk->exit_state)
		return 0;

	pt = task_pt_regs(tsk);

	sw = (struct switch_stack *) (tsk->thread.ksp + 16);

	if ((pg = __get_free_page(GFP_KERNEL)) == 0)
		return -ENOMEM;

	r = (void*)pg;
	/* To catch if we forgot some register */
	memset(r, 0xA5, sizeof(*r));

	r->gr[0] = 0;
	r->fr[0] = r->fr[1] = 0;
	r->fr[2] = 0x8000000000000000UL;
	r->fr[3] = 0xffff;

	r->nat[0] = r->nat[1] = 0;

	err = ass_to_mouth(r, tsk, ctx);
	if (err) {
		printk("ass_to_mouth error %d\n", err);
		goto out;
	}

	/* gr 1,2-3,8-11,12-13,14,15,16-31 are on pt_regs */
	memcpy(&r->gr[1], &pt->r1, 8*(2-1));
	memcpy(&r->gr[2], &pt->r2, 8*(4-2));
	memcpy(&r->gr[8], &pt->r8, 8*(12-8));
	memcpy(&r->gr[12], &pt->r12, 8*(14-12));
	memcpy(&r->gr[14], &pt->r14, 8*(15-14));
	memcpy(&r->gr[15], &pt->r15, 8*(16-15));
	memcpy(&r->gr[16], &pt->r16, 8*(32-16));

	r->br[0] = pt->b0;
	r->br[6] = pt->b6;
	r->br[7] = pt->b7;

	r->ar_bspstore = pt->ar_bspstore;
	r->ar_unat = pt->ar_unat;
	r->ar_pfs = pt->ar_pfs;
	r->ar_ccv = pt->ar_ccv;
	r->ar_fpsr = pt->ar_fpsr;
	r->ar_csd = pt->ar_csd;
	r->ar_ssd = pt->ar_ssd;
	r->ar_rsc = pt->ar_rsc;

	r->cr_iip = pt->cr_iip;
	r->cr_ipsr = pt->cr_ipsr;

	r->pr = pt->pr;

	r->cfm = pt->cr_ifs;
	r->ar_rnat = pt->ar_rnat;

	/* fpregs 6..9,10..11 are in pt_regs */
	memcpy(&r->fr[2*6], &pt->f6, 16*(10-6));
	memcpy(&r->fr[2*10], &pt->f10, 16*(12-10));
	/* fpreg 12..15 are on switch stack */
	memcpy(&r->fr[2*12], &sw->f12, 16*(16-12));
	/* fpregs 32...127 */
	psr = ia64_psr(task_pt_regs(tsk));
	preempt_disable();
	if (ia64_is_local_fpu_owner(tsk) && psr->mfh) {
		psr->mfh = 0;
		tsk->thread.flags |= IA64_THREAD_FPH_VALID;
		ia64_save_fpu(&tsk->thread.fph[0]);
	}
	preempt_enable();
	memcpy(&r->fr[32*2], tsk->thread.fph, 16*(128-32));

	if (tsk->thread.flags & IA64_THREAD_DBG_VALID) {
		memcpy(r->ibr, tsk->thread.ibr, sizeof(r->ibr));
		memcpy(r->dbr, tsk->thread.dbr, sizeof(r->ibr));
	} else {
		memset(r->ibr, 0, sizeof(r->ibr));
		memset(r->dbr, 0, sizeof(r->dbr));
	}

	r->loadrs = pt->loadrs;
	r->num_regs = ia64_rse_num_regs(krbs, krbs + 8*(pt->loadrs >> 19));
	if ((long)pt->cr_ifs > 0)
		r->num_regs += (pt->cr_ifs & 0x7f);

	if (r->num_regs > 96) {
		eprintk_ctx(CPT_FID " too much RSE regs %lu\n",
			    CPT_TID(tsk), r->num_regs);
		return -EINVAL;
	}

	for (reg = 0; reg < r->num_regs; reg++) {
		unsigned long *ptr = ia64_rse_skip_regs(krbs, reg);
		unsigned long *rnatp = ia64_rse_rnat_addr(ptr);

		r->gr[32+reg] = *ptr;

		if ((unsigned long)rnatp >= sw->ar_bspstore)
			rnatp = &sw->ar_rnat;
		if (*rnatp & (1UL<<ia64_rse_slot_num(ptr))) {
			if (reg < 32)
				r->nat[0] |= (1UL<<(reg+32));
			else
				r->nat[1] |= (1UL<<(reg-32));
		}
	}
	if (r->nat[0] | r->nat[1])
		wprintk_ctx(CPT_FID " nat bits %lx%016lx\n", CPT_TID(tsk),
			    r->nat[1], r->nat[0]);

	cpt_open_object(NULL, ctx);
	r->cpt_next = sizeof(*r);
	r->cpt_object = CPT_OBJ_IA64_REGS;
	r->cpt_hdrlen = sizeof(*r);
	r->cpt_content = CPT_CONTENT_VOID;
	ctx->write(r, sizeof(*r), ctx);
	cpt_close_object(ctx);
	err = 0;

out:
	free_page(pg);
	return err;
}
#endif

static int dump_kstack(struct task_struct *tsk, struct cpt_context *ctx)
{
	struct cpt_obj_bits hdr;
	unsigned long size;
	void *start;

	cpt_open_object(NULL, ctx);

#ifdef CONFIG_X86_64
	size = tsk->thread.sp0 - tsk->thread.sp;
	start = (void*)tsk->thread.sp;
#elif defined(CONFIG_X86_32)
	size = tsk->thread.sp0 - tsk->thread.sp;
	start = (void*)tsk->thread.sp;
#elif defined(CONFIG_IA64)
	size = (unsigned long)(task_pt_regs(tsk)+1) - tsk->thread.ksp;
	start = (void*)tsk->thread.ksp;
#else
#error Arch is not supported
#endif

	hdr.cpt_next = sizeof(hdr) + CPT_ALIGN(size);
	hdr.cpt_object = CPT_OBJ_BITS;
	hdr.cpt_hdrlen = sizeof(hdr);
	hdr.cpt_content = CPT_CONTENT_STACK;
	hdr.cpt_size = size;

	ctx->write(&hdr, sizeof(hdr), ctx);
	ctx->write(start, size, ctx);
	ctx->align(ctx);
	cpt_close_object(ctx);
	return 0;
}

#ifdef CONFIG_X86
/* Determine size and type of FPU struct to store */
static void init_fpu_hdr(struct cpt_obj_bits *hdr)
{
	unsigned long size;
	int type;

	if (likely(cpu_has_xsave)) {
		type = CPT_CONTENT_X86_XSAVE;
		size = xstate_size;
	} else
#ifndef CONFIG_X86_64
	if (!cpu_has_fxsr) {
		size = sizeof(struct i387_fsave_struct);
		type = CPT_CONTENT_X86_FPUSTATE_OLD;
	} else
#endif
	{
		type = CPT_CONTENT_X86_FPUSTATE;
		size = sizeof(struct i387_fxsave_struct);
	}

	hdr->cpt_next = sizeof(struct cpt_obj_bits) + CPT_ALIGN(size);
	hdr->cpt_object = CPT_OBJ_BITS;
	hdr->cpt_hdrlen = sizeof(struct cpt_obj_bits);
	hdr->cpt_content = type;
	hdr->cpt_size = size;
}

/* Formats of i387_fxsave_struct are the same for x86_64
 * and i386. Plain luck. */

static int dump_fpustate(struct task_struct *tsk, struct cpt_context *ctx)
{
	struct cpt_obj_bits hdr;

	if (!tsk->thread.xstate)
		return 0;

	cpt_open_object(NULL, ctx);

	init_fpu_hdr(&hdr);

	ctx->write(&hdr, sizeof(hdr), ctx);
	ctx->write(tsk->thread.xstate, hdr.cpt_size, ctx);
	ctx->align(ctx);
	cpt_close_object(ctx);
	return 0;
}
#endif

#ifdef CONFIG_IA64

static int dump_fpustate(struct task_struct *tsk, struct cpt_context *ctx)
{
	return 0;
}
#endif

static int encode_siginfo(struct cpt_siginfo_image *si, siginfo_t *info)
{
	si->cpt_signo = info->si_signo;
	si->cpt_errno = info->si_errno;
	si->cpt_code = info->si_code;

	/* Allow old kernels (i.e. which does not save _sifields) to restore */
	switch(si->cpt_code & __SI_MASK) {
	case __SI_POLL:
		si->cpt_pid = info->si_band;
		si->cpt_uid = info->si_fd;
		break;
	case __SI_FAULT:
		si->cpt_sigval = cpt_ptr_export(info->si_addr);
#ifdef __ARCH_SI_TRAPNO
		si->cpt_pid = info->si_trapno;
#endif
		break;
	case __SI_CHLD:
		si->cpt_pid = info->si_pid;
		si->cpt_uid = info->si_uid;
		si->cpt_sigval = info->si_status;
		si->cpt_stime = info->si_stime;
		si->cpt_utime = info->si_utime;
		break;
	case __SI_KILL:
	case __SI_RT:
	case __SI_MESGQ:
	default:
		si->cpt_pid = info->si_pid;
		si->cpt_uid = info->si_uid;
		si->cpt_sigval = cpt_ptr_export(info->si_ptr);
		break;
	}

	/* Modern kernel will restore whole _sifields */
	memcpy(si->cpt_sifields, &info->_sifields, sizeof(info->_sifields));
	BUILD_BUG_ON(sizeof(info->_sifields) != sizeof(si->cpt_sifields));

	return 0;
}

static int dump_sigqueue(struct sigpending *list, struct cpt_context *ctx)
{
	struct sigqueue *q;
	loff_t saved_obj;

	if (list_empty(&list->list))
		return 0;

	cpt_push_object(&saved_obj, ctx);
	list_for_each_entry(q, &list->list, list) {
		struct cpt_siginfo_image si;

		/* posix timers are collected separately */
		if (q->info.si_code == SI_TIMER)
			continue;

		si.cpt_next = sizeof(si);
		si.cpt_object = CPT_OBJ_SIGINFO;
		si.cpt_hdrlen = sizeof(si);
		si.cpt_content = CPT_CONTENT_VOID;

		si.cpt_qflags = q->flags;
		si.cpt_user = q->user->uid;

		if (encode_siginfo(&si, &q->info))
			return -EINVAL;

		ctx->write(&si, sizeof(si), ctx);
	}
	cpt_pop_object(&saved_obj, ctx);
	return 0;
}



static int dump_one_signal_struct(cpt_object_t *obj, struct cpt_context *ctx)
{
	struct signal_struct *sig = obj->o_obj;
	struct cpt_signal_image *v = cpt_get_buf(ctx);
	struct task_struct *tsk;
	int i;

	cpt_open_object(obj, ctx);

	v->cpt_next = CPT_NULL;
	v->cpt_object = CPT_OBJ_SIGNAL_STRUCT;
	v->cpt_hdrlen = sizeof(*v);
	v->cpt_content = CPT_CONTENT_ARRAY;

	v->cpt_pgrp_type = CPT_PGRP_NORMAL;
	v->cpt_pgrp = 0;

#if 0 /* the code below seems to be unneeded */
	if (sig->__pgrp <= 0) {
		eprintk_ctx("bad pgid\n");
		cpt_release_buf(ctx);
		return -EINVAL;
	}

	read_lock(&tasklist_lock);
	tsk = find_task_by_pid_ns(sig->__pgrp, &init_pid_ns);
	if (tsk == NULL)
		v->cpt_pgrp_type = CPT_PGRP_ORPHAN;
	read_unlock(&tasklist_lock);
	v->cpt_pgrp = pid_to_vpid(sig->__pgrp);
#endif

	v->cpt_old_pgrp = 0;
/*	if (!sig->tty_old_pgrp) {
		eprintk_ctx("bad tty_old_pgrp\n");
		cpt_release_buf(ctx);
		return -EINVAL;
	}*/
	if (sig->tty_old_pgrp) {
		v->cpt_old_pgrp_type = CPT_PGRP_NORMAL;
		read_lock(&tasklist_lock);
		tsk = pid_task(sig->tty_old_pgrp, PIDTYPE_PID);
		if (tsk == NULL) {
			v->cpt_old_pgrp_type = CPT_PGRP_ORPHAN;
			tsk = pid_task(sig->tty_old_pgrp, PIDTYPE_PGID);
		}
		read_unlock(&tasklist_lock);
		if (tsk == NULL) {
			eprintk_ctx("tty_old_pgrp does not exist anymore\n");
			cpt_release_buf(ctx);
			return -EINVAL;
		}
		v->cpt_old_pgrp = cpt_pid_nr(sig->tty_old_pgrp);
		if ((int)v->cpt_old_pgrp < 0) {
			dprintk_ctx("stray tty_old_pgrp %d\n", pid_nr(sig->tty_old_pgrp));
			v->cpt_old_pgrp = -1;
			v->cpt_old_pgrp_type = CPT_PGRP_STRAY;
		}
	}

	v->cpt_session_type = CPT_PGRP_NORMAL;
	v->cpt_session = 0;

#if 0 /* the code below seems to be unneeded */
	if (sig->__session <= 0) {
		eprintk_ctx("bad session\n");
		cpt_release_buf(ctx);
		return -EINVAL;
	}
	read_lock(&tasklist_lock);
	tsk = find_task_by_pid_ns(sig->__session, &init_pid_ns);
	if (tsk == NULL)
		v->cpt_session_type = CPT_PGRP_ORPHAN;
	read_unlock(&tasklist_lock);
	v->cpt_session = pid_to_vpid(sig->__session);
#endif

	v->cpt_leader = sig->leader;
	v->cpt_ctty = CPT_NULL;
	if (sig->tty) {
		cpt_object_t *cobj = lookup_cpt_object(CPT_OBJ_TTY, sig->tty, ctx);
		if (cobj)
			v->cpt_ctty = cobj->o_pos;
		else {
			eprintk_ctx("controlling tty is not found\n");
			cpt_release_buf(ctx);
			return -EINVAL;
		}
	}
	memcpy(&v->cpt_sigpending, &sig->shared_pending.signal, 8);

	v->cpt_curr_target = 0;
	if (sig->curr_target)
		v->cpt_curr_target = cpt_task_pid_nr(sig->curr_target, PIDTYPE_PID);
	v->cpt_group_exit = ((sig->flags & SIGNAL_GROUP_EXIT) != 0);
	v->cpt_group_exit_code = sig->group_exit_code;
	v->cpt_group_exit_task = 0;
	if (sig->group_exit_task)
		v->cpt_group_exit_task = cpt_task_pid_nr(sig->group_exit_task, PIDTYPE_PID);
	v->cpt_notify_count = sig->notify_count;
	v->cpt_group_stop_count = sig->group_stop_count;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,8)
	v->cpt_utime = sig->utime;
	v->cpt_stime = sig->stime;
	v->cpt_cutime = sig->cutime;
	v->cpt_cstime = sig->cstime;
	v->cpt_nvcsw = sig->nvcsw;
	v->cpt_nivcsw = sig->nivcsw;
	v->cpt_cnvcsw = sig->cnvcsw;
	v->cpt_cnivcsw = sig->cnivcsw;
	v->cpt_min_flt = sig->min_flt;
	v->cpt_maj_flt = sig->maj_flt;
	v->cpt_cmin_flt = sig->cmin_flt;
	v->cpt_cmaj_flt = sig->cmaj_flt;

	v->cpt_flags = 0;
	if (sig->flags & SIGNAL_STOP_STOPPED)
		v->cpt_flags |= CPT_SIGNAL_STOP_STOPPED;
	if (sig->flags & SIGNAL_STOP_CONTINUED)
		v->cpt_flags |= CPT_SIGNAL_STOP_CONTINUED;
	if (sig->flags & SIGNAL_CLD_STOPPED)
		v->cpt_flags |= CPT_SIGNAL_CLD_STOPPED;
	if (sig->flags & SIGNAL_CLD_CONTINUED)
		v->cpt_flags |= CPT_SIGNAL_CLD_CONTINUED;

	if (RLIM_NLIMITS > CPT_RLIM_NLIMITS)
		__asm__("undefined\n");

	for (i=0; i<CPT_RLIM_NLIMITS; i++) {
		if (i < RLIM_NLIMITS) {
			v->cpt_rlim_cur[i] = sig->rlim[i].rlim_cur;
			v->cpt_rlim_max[i] = sig->rlim[i].rlim_max;
		} else {
			v->cpt_rlim_cur[i] = CPT_NULL;
			v->cpt_rlim_max[i] = CPT_NULL;
		}
	}
#endif

	ctx->write(v, sizeof(*v), ctx);
	cpt_release_buf(ctx);

	dump_sigqueue(&sig->shared_pending, ctx);

	cpt_close_object(ctx);
	return 0;
}

int cpt_check_unsupported(struct task_struct *tsk, cpt_context_t *ctx)
{
#ifdef CONFIG_KEYS
	if (tsk->cred->request_key_auth || tsk->cred->thread_keyring) {
		eprintk_ctx("keys are used by " CPT_FID "\n", CPT_TID(tsk));
		return -EBUSY;
	}
#endif
#ifdef CONFIG_NUMA
	if (tsk->mempolicy) {
		eprintk_ctx("NUMA mempolicy is used by " CPT_FID "\n", CPT_TID(tsk));
		return -EBUSY;
	}
#endif
#ifdef CONFIG_TUX
	if (tsk->tux_info) {
		eprintk_ctx("TUX is used by " CPT_FID "\n", CPT_TID(tsk));
		return -EBUSY;
	}
#endif
	return 0;
}

int cpt_skip_task(struct task_struct *tsk)
{
	if (tsk->flags & PF_KTHREAD)
		return 1;

	if (tsk == current)
		return 1;

	return 0;
}

static int dump_one_process(cpt_object_t *obj, struct cpt_context *ctx)
{
	struct task_struct *tsk = obj->o_obj;
	const struct cred *cred;
	int last_thread;
	struct cpt_task_image *v;
	cpt_object_t *tobj;
	cpt_object_t *tg_obj;
	loff_t saved_obj;
	int i;
	int err;
	struct timespec delta;
	struct mm_struct * tsk_mm;
	struct files_struct * tsk_files;
	struct fs_struct * tsk_fs;
	struct mnt_namespace * tsk_ns;

	if (cpt_skip_task(tsk))
		return 0;

	cpt_open_object(obj, ctx);

	v = cpt_get_buf(ctx);
	v->cpt_signal = CPT_NULL;
	tg_obj = lookup_cpt_object(CPT_OBJ_SIGNAL_STRUCT, tsk->signal, ctx);
	if (!tg_obj) BUG();

	v->cpt_next = CPT_NULL;
	v->cpt_object = CPT_OBJ_TASK;
	v->cpt_hdrlen = sizeof(*v);
	v->cpt_content = CPT_CONTENT_ARRAY;

	v->cpt_state = tsk->state;
	if (tsk->exit_state) {
		v->cpt_state = tsk->exit_state;
		if (tsk->state != TASK_DEAD) {
			eprintk_ctx("invalid tsk->state %ld/%d on" CPT_FID "\n",
				tsk->state, tsk->exit_state, CPT_TID(tsk));
			cpt_release_buf(ctx);
			return -EINVAL;
		}
	}
	if (cpt_check_unsupported(tsk, ctx)) {
		cpt_release_buf(ctx);
		return -EBUSY;
	}

	v->cpt_flags = tsk->flags & CPT_TASK_FLAGS_MASK;
	v->cpt_ptrace = tsk->ptrace;
	v->cpt_prio = tsk->prio;
	v->cpt_exit_code = tsk->exit_code;
	v->cpt_exit_signal = tsk->exit_signal;
	v->cpt_pdeath_signal = tsk->pdeath_signal;
	v->cpt_static_prio = tsk->static_prio;
	v->cpt_rt_priority = tsk->rt_priority;
	v->cpt_policy = tsk->policy;
	if (v->cpt_policy != SCHED_NORMAL && v->cpt_policy != SCHED_BATCH && v->cpt_policy != SCHED_IDLE) {
		eprintk_ctx("scheduler policy is not supported %d/%d(%s)\n",
				cpt_task_pid_nr(tsk, PIDTYPE_PID), tsk->pid, tsk->comm);
		cpt_release_buf(ctx);
		return -EINVAL;
	}

	/* Unpleasant moment. When leader of thread group exits,
	 * it remains in zombie state until all the group exits.
	 * We save not-NULL pointers to process mm/files/fs, so
	 * that we can restore this thread group.
	 */
	tsk_mm = tsk->mm;
	tsk_files = tsk->files;
	tsk_fs = tsk->fs;
	tsk_ns = tsk->nsproxy ? tsk->nsproxy->mnt_ns : NULL;

	if (tsk->exit_state && !thread_group_empty(tsk) &&
	    thread_group_leader(tsk)) {
		struct task_struct * p = tsk;

		read_lock(&tasklist_lock);
		do {
			if (p->mm)
				tsk_mm = p->mm;
			if (p->files)
				tsk_files = p->files;
			if (p->fs)
				tsk_fs = p->fs;
			if (p->nsproxy && p->nsproxy->mnt_ns)
				tsk_ns = p->nsproxy->mnt_ns;
			p = next_thread(p);
		} while (p != tsk);
		read_unlock(&tasklist_lock);
	}

	v->cpt_mm = CPT_NULL;
	if (tsk_mm) {
		tobj = lookup_cpt_object(CPT_OBJ_MM, tsk_mm, ctx);
		if (!tobj) BUG();
		v->cpt_mm = tobj->o_pos;
	}
	v->cpt_files = CPT_NULL;
	if (tsk_files) {
		tobj = lookup_cpt_object(CPT_OBJ_FILES, tsk_files, ctx);
		if (!tobj) BUG();
		v->cpt_files = tobj->o_pos;
	}
	v->cpt_fs = CPT_NULL;
	if (tsk_fs) {
		tobj = lookup_cpt_object(CPT_OBJ_FS, tsk_fs, ctx);
		if (!tobj) BUG();
		v->cpt_fs = tobj->o_pos;
	}
	v->cpt_namespace = CPT_NULL;
	if (tsk_ns) {
		tobj = lookup_cpt_object(CPT_OBJ_NAMESPACE, tsk_ns, ctx);
		if (!tobj) BUG();
		v->cpt_namespace = tobj->o_pos;
	}
	v->cpt_sysvsem_undo = CPT_NULL;
	if (tsk->sysvsem.undo_list && !tsk->exit_state) {
		tobj = lookup_cpt_object(CPT_OBJ_SYSVSEM_UNDO, tsk->sysvsem.undo_list, ctx);
		if (!tobj) BUG();
		v->cpt_sysvsem_undo = tobj->o_pos;
	}
	v->cpt_sighand = CPT_NULL;
	if (tsk->sighand) {
		tobj = lookup_cpt_object(CPT_OBJ_SIGHAND_STRUCT, tsk->sighand, ctx);
		if (!tobj) BUG();
		v->cpt_sighand = tobj->o_pos;
	}
	v->cpt_sigblocked = cpt_sigset_export(&tsk->blocked);
	v->cpt_sigrblocked = cpt_sigset_export(&tsk->real_blocked);
	v->cpt_sigsuspend_blocked = cpt_sigset_export(&tsk->saved_sigmask);

	v->cpt_posix_timers = CPT_NULL;
	if (thread_group_leader(tsk) && tsk->signal &&
	    !list_empty(&tsk->signal->posix_timers)) {
		tobj = lookup_cpt_object(CPT_OBJ_POSIX_TIMER_LIST,
					 &tsk->signal->posix_timers, ctx);
		if (!tobj) BUG();
		v->cpt_posix_timers = tobj->o_pos;
	}

	v->cpt_pid = cpt_task_pid_nr(tsk, PIDTYPE_PID);
	v->cpt_tgid = cpt_pid_nr(task_tgid(tsk));
	v->cpt_ppid = 0;
	if (tsk->parent) {
		if (tsk->parent != tsk->real_parent &&
		    !lookup_cpt_object(CPT_OBJ_TASK, tsk->parent, ctx)) {
			eprintk_ctx("task %d/%d(%s) is ptraced from ve0\n", tsk->pid,
					cpt_task_pid_nr(tsk, PIDTYPE_PID), tsk->comm);
			cpt_release_buf(ctx);
			return -EBUSY;
		}
		v->cpt_ppid = cpt_task_pid_nr(tsk->parent, PIDTYPE_PID);
	}
	v->cpt_rppid = tsk->real_parent ? cpt_task_pid_nr(tsk->real_parent, PIDTYPE_PID) : 0;
	v->cpt_pgrp = cpt_task_pid_nr(tsk, PIDTYPE_PGID);
	v->cpt_session = cpt_task_pid_nr(tsk, PIDTYPE_SID);
	v->cpt_old_pgrp = 0;
	if (tsk->signal->tty_old_pgrp)
		v->cpt_old_pgrp = cpt_pid_nr(tsk->signal->tty_old_pgrp);
	v->cpt_leader = tsk->group_leader ? cpt_task_pid_nr(tsk->group_leader, PIDTYPE_PID) : 0;
	v->cpt_set_tid = (unsigned long)tsk->set_child_tid;
	v->cpt_clear_tid = (unsigned long)tsk->clear_child_tid;
	memcpy(v->cpt_comm, tsk->comm, 16);

	cred = tsk->cred;
	v->cpt_user = cred->user->uid;
	v->cpt_uid = cred->uid;
	v->cpt_euid = cred->euid;
	v->cpt_suid = cred->suid;
	v->cpt_fsuid = cred->fsuid;
	v->cpt_gid = cred->gid;
	v->cpt_egid = cred->egid;
	v->cpt_sgid = cred->sgid;
	v->cpt_fsgid = cred->fsgid;
	v->cpt_ngids = 0;
	if (cred->group_info && cred->group_info->ngroups != 0) {
		int i = cred->group_info->ngroups;
		if (i > 32) {
			/* Shame... I did a simplified version and _forgot_
			 * about this. Later, later. */
			eprintk_ctx("too many of groups " CPT_FID "\n", CPT_TID(tsk));
			cpt_release_buf(ctx);
			return -EINVAL;
		}
		v->cpt_ngids = i;
		for (i--; i>=0; i--)
			v->cpt_gids[i] = cred->group_info->small_block[i];
	}
	v->cpt_prctl_uac = 0;
	v->cpt_prctl_fpemu = 0;
	v->__cpt_pad1 = 0;
#ifdef CONFIG_IA64
	v->cpt_prctl_uac = (tsk->thread.flags & IA64_THREAD_UAC_MASK) >> IA64_THREAD_UAC_SHIFT;
	v->cpt_prctl_fpemu = (tsk->thread.flags & IA64_THREAD_FPEMU_MASK) >> IA64_THREAD_FPEMU_SHIFT;
#endif
	memcpy(&v->cpt_ecap, &cred->cap_effective, 8);
	memcpy(&v->cpt_icap, &cred->cap_inheritable, 8);
	memcpy(&v->cpt_pcap, &cred->cap_permitted, 8);
	memcpy(&v->cpt_bcap, &cred->cap_bset, 8);
	v->cpt_keepcap = cred->securebits;

	v->cpt_did_exec = tsk->did_exec;
	v->cpt_exec_domain = -1;
	v->cpt_thrflags = task_thread_info(tsk)->flags & ~(1<<TIF_FREEZE);
	v->cpt_64bit = 0;
#ifdef CONFIG_X86_64
	/* Clear x86_64 specific flags */
	v->cpt_thrflags &= ~(_TIF_FORK|_TIF_IA32);
	if (!(task_thread_info(tsk)->flags & _TIF_IA32)) {
		ctx->tasks64++;
		v->cpt_64bit = 1;
	}
#endif
#ifdef CONFIG_IA64
	/* Clear ia64 specific flags */
	//// v->cpt_thrflags &= ~(_TIF_FORK|_TIF_ABI_PENDING|_TIF_IA32);
	if (!IS_IA32_PROCESS(task_pt_regs(tsk))) {
		ctx->tasks64++;
		v->cpt_64bit = 1;
	}
#endif
	v->cpt_thrstatus = task_thread_info(tsk)->status;
	v->cpt_addr_limit = -1;

	v->cpt_personality = tsk->personality;

#ifdef CONFIG_X86
	for (i=0; i<GDT_ENTRY_TLS_ENTRIES; i++) {
		if (i>=3) {
			eprintk_ctx("too many tls descs\n");
			cpt_release_buf(ctx);
			return -EINVAL;
		}
		v->cpt_tls[i] = (((u64)tsk->thread.tls_array[i].b)<<32) + tsk->thread.tls_array[i].a;
	}
#endif

	v->cpt_restart.fn = CPT_RBL_0;
	if (task_thread_info(tsk)->restart_block.fn != task_thread_info(current)->restart_block.fn) {
		struct restart_block *rb = &task_thread_info(tsk)->restart_block;
		ktime_t e;

		if (rb->fn == hrtimer_nanosleep_restart) {
			v->cpt_restart.fn = CPT_RBL_NANOSLEEP;

			e.tv64 = rb->nanosleep.expires;
			e = ktime_sub(e, timespec_to_ktime(ctx->cpt_monotonic_time));
			v->cpt_restart.arg0 = (__u64)rb->nanosleep.index;
			v->cpt_restart.arg1 = (unsigned long)rb->nanosleep.rmtp;
			v->cpt_restart.arg2 = 0;
			v->cpt_restart.arg3 = ktime_to_ns(e);
			dprintk_ctx(CPT_FID " %Lu\n", CPT_TID(tsk), (__u64)v->cpt_restart.arg0);
			goto continue_dump;
		}
#if defined(CONFIG_X86_64) && defined(CONFIG_COMPAT)
		if (rb->fn == compat_nanosleep_restart) {
			v->cpt_restart.fn = CPT_RBL_COMPAT_NANOSLEEP;

			e.tv64 = rb->nanosleep.expires;
			e = ktime_sub(e, timespec_to_ktime(ctx->cpt_monotonic_time));
			v->cpt_restart.arg0 = (__u64)rb->nanosleep.index;
			v->cpt_restart.arg1 = (__u64)rb->nanosleep.rmtp;
			v->cpt_restart.arg2 = (__u64)rb->nanosleep.compat_rmtp;
			v->cpt_restart.arg3 = ktime_to_ns(e);
			dprintk_ctx(CPT_FID " %Lu\n", CPT_TID(tsk), (__u64)v->cpt_restart.arg0);
			goto continue_dump;
		}
#endif
		if (rb->fn == do_restart_poll) {
			struct timespec ts;

			ts.tv_sec = rb->poll.tv_sec;
			ts.tv_nsec = rb->poll.tv_nsec;

			v->cpt_restart.fn = CPT_RBL_POLL;
			v->cpt_restart.arg0 = (unsigned long)rb->poll.ufds;
			v->cpt_restart.arg1 = (__u64)rb->poll.has_timeout << 32 | rb->poll.nfds;
			v->cpt_restart.arg2 = timespec_to_ns(&ts);
			v->cpt_restart.arg3 = 0;
			dprintk_ctx(CPT_FID " %Lu\n", CPT_TID(tsk), (__u64)v->cpt_restart.arg0);
			goto continue_dump;
		}
		if (rb->fn == futex_wait_restart) {
			v->cpt_restart.fn = CPT_RBL_FUTEX_WAIT;

			e.tv64 = rb->futex.time;
			e = ktime_sub(e, timespec_to_ktime(ctx->cpt_monotonic_time));
			v->cpt_restart.arg0 = (unsigned long)rb->futex.uaddr;
			v->cpt_restart.arg1 = rb->futex.val;
			v->cpt_restart.arg2 = ktime_to_ns(e);
			v->cpt_restart.arg3 = rb->futex.flags;
			goto continue_dump;
		}
		if (rb->fn == posix_cpu_nsleep_restart) {
			v->cpt_restart.fn = CPT_RBL_POSIX_CPU_NSLEEP;
			v->cpt_restart.arg0 = rb->arg0;
			v->cpt_restart.arg1 = rb->arg1;
			v->cpt_restart.arg2 = rb->arg2;
			v->cpt_restart.arg3 = rb->arg3;
			goto continue_dump;
		}
		eprintk_ctx("unknown restart block %pS\n", rb->fn);
		cpt_release_buf(ctx);
		return -EINVAL;
	}

continue_dump:
	v->cpt_it_real_incr = 0;
	v->cpt_it_prof_incr = 0;
	v->cpt_it_virt_incr = 0;
	v->cpt_it_real_value = 0;
	v->cpt_it_prof_value = 0;
	v->cpt_it_virt_value = 0;
	if (thread_group_leader(tsk) && tsk->exit_state == 0) {
		ktime_t rem;

		v->cpt_it_real_incr = ktime_to_ns(tsk->signal->it_real_incr);
		v->cpt_it_prof_incr = tsk->signal->it[CPUCLOCK_PROF].incr;
		v->cpt_it_virt_incr = tsk->signal->it[CPUCLOCK_VIRT].incr;

		rem = hrtimer_get_remaining(&tsk->signal->real_timer);

		if (hrtimer_active(&tsk->signal->real_timer)) {
			if (rem.tv64 <= 0)
				rem.tv64 = NSEC_PER_USEC;
			v->cpt_it_real_value = ktime_to_ns(rem);
			dprintk("cpt itimer " CPT_FID " %Lu\n", CPT_TID(tsk), (unsigned long long)v->cpt_it_real_value);
		}
		v->cpt_it_prof_value = tsk->signal->it[CPUCLOCK_PROF].expires;
		v->cpt_it_virt_value = tsk->signal->it[CPUCLOCK_VIRT].expires;
	}
	v->cpt_used_math = (tsk_used_math(tsk) != 0);

	if (tsk->notifier) {
		eprintk_ctx("task notifier is in use: process %d/%d(%s)\n",
				cpt_task_pid_nr(tsk, PIDTYPE_PID), tsk->pid, tsk->comm);
		cpt_release_buf(ctx);
		return -EINVAL;
	}

	v->cpt_utime = tsk->utime;
	v->cpt_stime = tsk->stime;
	delta = tsk->start_time;
	_set_normalized_timespec(&delta,
			delta.tv_sec - get_exec_env()->start_timespec.tv_sec,
			delta.tv_nsec - get_exec_env()->start_timespec.tv_nsec);
	v->cpt_starttime = cpt_timespec_export(&delta);
	v->cpt_nvcsw = tsk->nvcsw;
	v->cpt_nivcsw = tsk->nivcsw;
	v->cpt_min_flt = tsk->min_flt;
	v->cpt_maj_flt = tsk->maj_flt;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,8)
	v->cpt_cutime = tsk->cutime;
	v->cpt_cstime = tsk->cstime;
	v->cpt_cnvcsw = tsk->cnvcsw;
	v->cpt_cnivcsw = tsk->cnivcsw;
	v->cpt_cmin_flt = tsk->cmin_flt;
	v->cpt_cmaj_flt = tsk->cmaj_flt;

	if (RLIM_NLIMITS > CPT_RLIM_NLIMITS)
		__asm__("undefined\n");

	for (i=0; i<CPT_RLIM_NLIMITS; i++) {
		if (i < RLIM_NLIMITS) {
			v->cpt_rlim_cur[i] = tsk->rlim[i].rlim_cur;
			v->cpt_rlim_max[i] = tsk->rlim[i].rlim_max;
		} else {
			v->cpt_rlim_cur[i] = CPT_NULL;
			v->cpt_rlim_max[i] = CPT_NULL;
		}
	}
#else
	v->cpt_cutime = tsk->signal->cutime;
	v->cpt_cstime = tsk->signal->cstime;
	v->cpt_cnvcsw = tsk->signal->cnvcsw;
	v->cpt_cnivcsw = tsk->signal->cnivcsw;
	v->cpt_cmin_flt = tsk->signal->cmin_flt;
	v->cpt_cmaj_flt = tsk->signal->cmaj_flt;

	if (RLIM_NLIMITS > CPT_RLIM_NLIMITS)
		__asm__("undefined\n");

	for (i=0; i<CPT_RLIM_NLIMITS; i++) {
		if (i < RLIM_NLIMITS) {
			v->cpt_rlim_cur[i] = tsk->signal->rlim[i].rlim_cur;
			v->cpt_rlim_max[i] = tsk->signal->rlim[i].rlim_max;
		} else {
			v->cpt_rlim_cur[i] = CPT_NULL;
			v->cpt_rlim_max[i] = CPT_NULL;
		}
	}
#endif

#ifdef CONFIG_BEANCOUNTERS
	if (tsk->mm)
		v->cpt_mm_ub = cpt_lookup_ubc(mm_ub_top(tsk->mm), ctx);
	else
		v->cpt_mm_ub = CPT_NULL;
	v->cpt_task_ub = cpt_lookup_ubc(top_beancounter(tsk->task_bc.task_ub), ctx);
	v->cpt_exec_ub = cpt_lookup_ubc(top_beancounter(tsk->task_bc.exec_ub), ctx);
	v->cpt_fork_sub = v->cpt_exec_ub;
#endif

	v->cpt_ptrace_message = tsk->ptrace_message;
	v->cpt_stopped_state = tsk->stopped_state;

#ifdef CONFIG_X86_32
	if (tsk->thread.vm86_info) {
		eprintk_ctx("vm86 task is running\n");
		cpt_release_buf(ctx);
		return -EBUSY;
	}
#endif

	v->cpt_sigpending = cpt_sigset_export(&tsk->pending.signal);

	ctx->write(v, sizeof(*v), ctx);
	cpt_release_buf(ctx);

	cpt_push_object(&saved_obj, ctx);
	dump_kstack(tsk, ctx);
	cpt_pop_object(&saved_obj, ctx);

	cpt_push_object(&saved_obj, ctx);
	err = dump_registers(tsk, ctx);
	cpt_pop_object(&saved_obj, ctx);
	if (err)
		return err;

	if (tsk_used_math(tsk)) {
		cpt_push_object(&saved_obj, ctx);
		dump_fpustate(tsk, ctx);
		cpt_pop_object(&saved_obj, ctx);
	}

	if (tsk->last_siginfo &&
	    tsk->last_siginfo->si_code != SI_TIMER) {
		struct cpt_siginfo_image si;
		cpt_push_object(&saved_obj, ctx);

		si.cpt_next = sizeof(si);
		si.cpt_object = CPT_OBJ_LASTSIGINFO;
		si.cpt_hdrlen = sizeof(si);
		si.cpt_content = CPT_CONTENT_VOID;

		if (encode_siginfo(&si, tsk->last_siginfo))
			return -EINVAL;

		ctx->write(&si, sizeof(si), ctx);
		cpt_pop_object(&saved_obj, ctx);
	}

	if (tsk->sas_ss_size) {
		struct cpt_sigaltstack_image si;
		cpt_push_object(&saved_obj, ctx);

		si.cpt_next = sizeof(si);
		si.cpt_object = CPT_OBJ_SIGALTSTACK;
		si.cpt_hdrlen = sizeof(si);
		si.cpt_content = CPT_CONTENT_VOID;

		si.cpt_stack = tsk->sas_ss_sp;
		si.cpt_stacksize = tsk->sas_ss_size;

		ctx->write(&si, sizeof(si), ctx);
		cpt_pop_object(&saved_obj, ctx);
	}

	if (tsk->robust_list
#ifdef CONFIG_COMPAT
	    || tsk->compat_robust_list
#endif
	    ) {
		struct cpt_task_aux_image ai;
		cpt_push_object(&saved_obj, ctx);

		ai.cpt_next = sizeof(ai);
		ai.cpt_object = CPT_OBJ_TASK_AUX;
		ai.cpt_hdrlen = sizeof(ai);
		ai.cpt_content = CPT_CONTENT_VOID;

		ai.cpt_robust_list = (unsigned long)tsk->robust_list;
#ifdef CONFIG_X86_64
#ifdef CONFIG_COMPAT
		if (task_thread_info(tsk)->flags & _TIF_IA32)
			ai.cpt_robust_list = (unsigned long)tsk->compat_robust_list;
#endif
#endif
		ctx->write(&ai, sizeof(ai), ctx);
		cpt_pop_object(&saved_obj, ctx);
	}

	dump_sigqueue(&tsk->pending, ctx);

	last_thread = 1;
	read_lock(&tasklist_lock);
	do {
		struct task_struct * next = next_thread(tsk);
		if (next != tsk && !thread_group_leader(next))
			last_thread = 0;
	} while (0);
	read_unlock(&tasklist_lock);

	if (last_thread) {
		struct task_struct *prev_tsk;
		int err;
		loff_t pos = ctx->file->f_pos;

		cpt_push_object(&saved_obj, ctx);
		err = dump_one_signal_struct(tg_obj, ctx);
		cpt_pop_object(&saved_obj, ctx);
		if (err)
			return err;

		prev_tsk = tsk;
		for (;;) {
			if (prev_tsk->tgid == tsk->tgid) {
				loff_t tg_pos;

				tg_pos = obj->o_pos + offsetof(struct cpt_task_image, cpt_signal);
				ctx->pwrite(&pos, sizeof(pos), ctx, tg_pos);
				if (thread_group_leader(prev_tsk))
					break;
			}

			if (obj->o_list.prev == &ctx->object_array[CPT_OBJ_TASK]) {
				eprintk_ctx("bug: thread group leader is lost\n");
				return -EINVAL;
			}

			obj = list_entry(obj->o_list.prev, cpt_object_t, o_list);
			prev_tsk = obj->o_obj;
		}
	}

	cpt_close_object(ctx);
	return 0;
}

int cpt_dump_tasks(struct cpt_context *ctx)
{
	cpt_object_t *obj;

	cpt_open_section(ctx, CPT_SECT_TASKS);

	for_each_object(obj, CPT_OBJ_TASK) {
		int err;

		if ((err = dump_one_process(obj, ctx)) != 0)
			return err;
	}

	cpt_close_section(ctx);
	return 0;
}

int cpt_collect_signals(cpt_context_t *ctx)
{
	cpt_object_t *obj;

	/* Collect process fd sets */
	for_each_object(obj, CPT_OBJ_TASK) {
		struct task_struct *tsk = obj->o_obj;
		if (tsk->signal && cpt_object_add(CPT_OBJ_SIGNAL_STRUCT, tsk->signal, ctx) == NULL)
			return -ENOMEM;
		if (tsk->sighand && cpt_object_add(CPT_OBJ_SIGHAND_STRUCT, tsk->sighand, ctx) == NULL)
			return -ENOMEM;
	}
	return 0;
}


static int dump_one_sighand_struct(cpt_object_t *obj, struct cpt_context *ctx)
{
	struct sighand_struct *sig = obj->o_obj;
	struct cpt_sighand_image *v = cpt_get_buf(ctx);
	int i;

	cpt_open_object(obj, ctx);

	v->cpt_next = CPT_NULL;
	v->cpt_object = CPT_OBJ_SIGHAND_STRUCT;
	v->cpt_hdrlen = sizeof(*v);
	v->cpt_content = CPT_CONTENT_ARRAY;

	ctx->write(v, sizeof(*v), ctx);
	cpt_release_buf(ctx);

	for (i=0; i< _NSIG; i++) {
		if (sig->action[i].sa.sa_handler != SIG_DFL ||
		    sig->action[i].sa.sa_flags) {
			loff_t saved_obj;
			struct cpt_sighandler_image *o = cpt_get_buf(ctx);

			cpt_push_object(&saved_obj, ctx);
			cpt_open_object(NULL, ctx);

			o->cpt_next = CPT_NULL;
			o->cpt_object = CPT_OBJ_SIGHANDLER;
			o->cpt_hdrlen = sizeof(*o);
			o->cpt_content = CPT_CONTENT_VOID;

			o->cpt_signo = i;
			o->cpt_handler = (unsigned long)sig->action[i].sa.sa_handler;
			o->cpt_restorer = 0;
#ifdef CONFIG_X86
			o->cpt_restorer = (unsigned long)sig->action[i].sa.sa_restorer;
#endif
			o->cpt_flags = sig->action[i].sa.sa_flags;
			memcpy(&o->cpt_mask, &sig->action[i].sa.sa_mask, 8);
			ctx->write(o, sizeof(*o), ctx);
			cpt_release_buf(ctx);
			cpt_close_object(ctx);
			cpt_pop_object(&saved_obj, ctx);
		}
	}

	cpt_close_object(ctx);
	return 0;
}

int cpt_dump_sighand(struct cpt_context *ctx)
{
	cpt_object_t *obj;

	cpt_open_section(ctx, CPT_SECT_SIGHAND_STRUCT);

	for_each_object(obj, CPT_OBJ_SIGHAND_STRUCT) {
		int err;

		if ((err = dump_one_sighand_struct(obj, ctx)) != 0)
			return err;
	}

	cpt_close_section(ctx);
	return 0;
}

int cpt_collect_posix_timers(cpt_context_t *ctx)
{
	cpt_object_t *obj;

	for_each_object(obj, CPT_OBJ_TASK) {
		struct task_struct *tsk = obj->o_obj;

		if (!thread_group_leader(tsk) || !tsk->signal ||
		    list_empty(&tsk->signal->posix_timers))
			continue;

		if (!cpt_object_add(CPT_OBJ_POSIX_TIMER_LIST,
				    &tsk->signal->posix_timers, ctx))
			return -ENOMEM;
	}
	return 0;
}

static int dump_one_posix_timer_list(cpt_object_t *obj, struct cpt_context *ctx)
{
	struct list_head *timer_list = obj->o_obj;
	struct cpt_object_hdr v;
	struct k_itimer *timer;

	cpt_open_object(obj, ctx);

	v.cpt_next = CPT_NULL;
	v.cpt_object = CPT_OBJ_POSIX_TIMER_LIST;
	v.cpt_hdrlen = sizeof(v);
	v.cpt_content = CPT_CONTENT_ARRAY;

	ctx->write(&v, sizeof(v), ctx);

	list_for_each_entry(timer, timer_list, list) {
		loff_t saved_obj;
		struct timespec dump_time;
		struct itimerspec setting;
		int overrun, overrun_last;
		int signal_pending;
		struct cpt_posix_timer_image o;

		get_timer_setting(timer, &setting,
				  &overrun, &overrun_last, &signal_pending);

		cpt_push_object(&saved_obj, ctx);
		cpt_open_object(NULL, ctx);

		o.cpt_next = CPT_NULL;
		o.cpt_object = CPT_OBJ_POSIX_TIMER;
		o.cpt_hdrlen = sizeof(o);
		o.cpt_content = CPT_CONTENT_VOID;

		o.cpt_timer_id = timer->it_id;
		o.cpt_timer_clock = timer->it_clock;
		o.cpt_timer_overrun = overrun;
		o.cpt_timer_overrun_last = overrun_last;
		o.cpt_timer_signal_pending = signal_pending;
		o.cpt_timer_interval =
			cpt_timespec_export(&setting.it_interval);
		o.cpt_timer_value =
			cpt_timespec_export(&setting.it_value);

		o.cpt_sigev_value =
			cpt_ptr_export(timer->sigq->info.si_value.sival_ptr);
		o.cpt_sigev_signo = timer->sigq->info.si_signo;
		o.cpt_sigev_notify = timer->it_sigev_notify;
		o.cpt_sigev_notify_tid = cpt_pid_nr(timer->it_pid);

		do_gettimespec(&dump_time);
		o.cpt_dump_time = cpt_timespec_export(&dump_time);

		ctx->write(&o, sizeof(o), ctx);
		cpt_close_object(ctx);
		cpt_pop_object(&saved_obj, ctx);
	}

	cpt_close_object(ctx);
	return 0;
}

int cpt_dump_posix_timers(struct cpt_context *ctx)
{
	cpt_object_t *obj;

	cpt_open_section(ctx, CPT_SECT_POSIX_TIMERS);

	for_each_object(obj, CPT_OBJ_POSIX_TIMER_LIST) {
		int err;

		err = dump_one_posix_timer_list(obj, ctx);
		if (err)
			return err;
	}

	cpt_close_section(ctx);
	return 0;
}
