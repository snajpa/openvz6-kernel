/*
 *
 *  kernel/cpt/cpt_kernel.c
 *
 *  Copyright (C) 2000-2005  SWsoft
 *  All rights reserved.
 *
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#define __KERNEL_SYSCALLS__ 1

#include <linux/version.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/kernel.h>
#ifdef CONFIG_X86
#include <asm/cpufeature.h>
#endif
#include <linux/cpt_image.h>

#include "cpt_kernel.h"
#include "cpt_syscalls.h"

int debug_level = 1;
int swap_percent = 25;

#ifdef CONFIG_X86_32

/*
 * Create a kernel thread
 */
extern void kernel_thread_helper(void);
int asm_kernel_thread(int (*fn)(void *), void * arg, unsigned long flags, pid_t pid)
{
	struct pt_regs regs;

	memset(&regs, 0, sizeof(regs));

	regs.bx = (unsigned long) fn;
	regs.dx = (unsigned long) arg;

	regs.ds = __USER_DS;
	regs.es = __USER_DS;
	regs.fs = __KERNEL_PERCPU;
	regs.gs = __KERNEL_STACK_CANARY;
	regs.orig_ax = -1;
	regs.ip = (unsigned long) kernel_thread_helper;
	regs.cs = __KERNEL_CS | get_kernel_rpl();
	regs.flags = X86_EFLAGS_IF | X86_EFLAGS_SF | X86_EFLAGS_PF | 0x2;

	/* Ok, create the new process.. */
	return do_fork_pid(flags | CLONE_UNTRACED, 0, &regs, 0, NULL, NULL, pid);
}
#endif

#ifdef CONFIG_IA64
pid_t
asm_kernel_thread (int (*fn)(void *), void *arg, unsigned long flags, pid_t pid)
{
	extern void start_kernel_thread (void);
	unsigned long *helper_fptr = (unsigned long *) &start_kernel_thread;
	struct {
		struct switch_stack sw;
		struct pt_regs pt;
	} regs;

	memset(&regs, 0, sizeof(regs));
	regs.pt.cr_iip = helper_fptr[0];	/* set entry point (IP) */
	regs.pt.r1 = helper_fptr[1];		/* set GP */
	regs.pt.r9 = (unsigned long) fn;	/* 1st argument */
	regs.pt.r11 = (unsigned long) arg;	/* 2nd argument */
	/* Preserve PSR bits, except for bits 32-34 and 37-45, which we can't read.  */
	regs.pt.cr_ipsr = ia64_getreg(_IA64_REG_PSR) | IA64_PSR_BN;
	regs.pt.cr_ifs = 1UL << 63;		/* mark as valid, empty frame */
	regs.sw.ar_fpsr = regs.pt.ar_fpsr = ia64_getreg(_IA64_REG_AR_FPSR);
	regs.sw.ar_bspstore = (unsigned long) current + IA64_RBS_OFFSET;
	regs.sw.pr = (1 << 2 /*PRED_KERNEL_STACK*/);
	return do_fork_pid(flags | CLONE_UNTRACED, 0, &regs.pt, 0, NULL, NULL, pid);
}
#endif

int local_kernel_thread(int (*fn)(void *), void * arg, unsigned long flags, pid_t pid)
{
	pid_t ret;

	if (current->fs == NULL) {
		/* do_fork_pid() hates processes without fs, oopses. */
		printk("CPT BUG: local_kernel_thread: current->fs==NULL\n");
		return -EINVAL;
	}
	if (!try_module_get(THIS_MODULE))
		return -EBUSY;

	ret = asm_kernel_thread(fn, arg, flags, pid);
	if (ret < 0)
		module_put(THIS_MODULE);
	return ret;
}

unsigned int test_cpu_caps_and_features(void)
{
#define has_cpu_cap(cap) test_bit((cap), (unsigned long *)caps)

	u32 caps[RHNCAPINTS];
	unsigned int flags = 0;

#ifdef CONFIG_X86
	get_cpu_cap_masked(caps);

	if (has_cpu_cap(X86_FEATURE_CMOV))
		flags |= 1 << CPT_CPU_X86_CMOV;
	if (has_cpu_cap(X86_FEATURE_FXSR))
		flags |= 1 << CPT_CPU_X86_FXSR;
	if (has_cpu_cap(X86_FEATURE_XMM))
		flags |= 1 << CPT_CPU_X86_SSE;
#ifndef CONFIG_X86_64
	if (has_cpu_cap(X86_FEATURE_XMM2))
#endif
		flags |= 1 << CPT_CPU_X86_SSE2;
	if (has_cpu_cap(X86_FEATURE_XMM4_1))
		flags |= 1 << CPT_CPU_X86_SSE4_1;
	if (has_cpu_cap(X86_FEATURE_XMM4_2))
		flags |= 1 << CPT_CPU_X86_SSE4_2;
	if (has_cpu_cap(X86_FEATURE_MMX))
		flags |= 1 << CPT_CPU_X86_MMX;
	if (has_cpu_cap(X86_FEATURE_3DNOW))
		flags |= 1 << CPT_CPU_X86_3DNOW;
	if (has_cpu_cap(X86_FEATURE_3DNOWEXT))
		flags |= 1 << CPT_CPU_X86_3DNOW2;
	if (has_cpu_cap(X86_FEATURE_SSE4A))
		flags |= 1 << CPT_CPU_X86_SSE4A;
	if (has_cpu_cap(X86_FEATURE_SYSCALL))
		flags |= 1 << CPT_CPU_X86_SYSCALL;
#ifdef CONFIG_X86_64
	if (has_cpu_cap(X86_FEATURE_SYSCALL) &&
			boot_cpu_data.x86_vendor != X86_VENDOR_INTEL)
		flags |= 1 << CPT_CPU_X86_SYSCALL32;
#endif
	if (has_cpu_cap(X86_FEATURE_SEP)
#ifdef CONFIG_X86_64
			&& boot_cpu_data.x86_vendor == X86_VENDOR_INTEL
#endif
	   )
		flags |= ((1 << CPT_CPU_X86_SEP) | (1 << CPT_CPU_X86_SEP32));

	if (has_cpu_cap(X86_FEATURE_XSAVE))
		flags |= 1 << CPT_CPU_X86_XSAVE;

	if (has_cpu_cap(X86_FEATURE_AVX))
		flags |= 1 << CPT_CPU_X86_AVX;

	if (has_cpu_cap(X86_FEATURE_AES))
		flags |= 1 << CPT_CPU_X86_AESNI;

	if (has_cpu_cap(X86_FEATURE_RDRAND))
		flags |= 1 << CPT_CPU_X86_RDRAND;

#ifdef CONFIG_X86_64
	flags |= 1 << CPT_CPU_X86_EMT64;
#endif
#endif
#ifdef CONFIG_IA64
	flags |= 1 << CPT_CPU_X86_IA64;
	flags |= 1 << CPT_CPU_X86_FXSR;
#endif
	if (!is_sock_registered(PF_INET6))
		flags |= 1 << CPT_NO_IPV6;

	flags |= 1 << CPT_NAMESPACES;

	return flags;

#undef has_cpu_cap
}

unsigned int test_kernel_config(void)
{
	unsigned int flags = 0;
#ifdef CONFIG_X86
#if defined(CONFIG_X86_PAE) || defined(CONFIG_X86_64)
	flags |= 1 << CPT_KERNEL_CONFIG_PAE;
#endif
#endif
	return flags;
}
