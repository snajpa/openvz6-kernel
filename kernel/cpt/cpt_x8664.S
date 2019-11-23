#define ASSEMBLY 1

#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/cache.h>
#include <asm/errno.h>
#include <asm/dwarf2.h>
#include <asm/calling.h>
#include <asm/msr.h>
#include <asm/unistd.h>
#include <asm/thread_info.h>
#include <asm/hw_irq.h>
#include <asm/errno.h>

	.code64

	.macro FAKE_STACK_FRAME child_rip
	/* push in order ss, rsp, eflags, cs, rip */
	xorq %rax, %rax
	pushq $__KERNEL_DS /* ss */
	pushq %rax /* rsp */
	pushq $(1<<9) /* eflags - interrupts on */
	pushq $__KERNEL_CS /* cs */
	pushq \child_rip /* rip */
	pushq	%rax /* orig rax */
	.endm

	.macro UNFAKE_STACK_FRAME
	addq $8*6, %rsp
	.endm

ENTRY(asm_kernel_thread)
	CFI_STARTPROC
	FAKE_STACK_FRAME $child_rip
	SAVE_ALL

	# rdi: flags, rsi: usp, rdx: will be &pt_regs
	movq %rdx,%rdi
	orq  $0x00800000,%rdi
	movq $-1, %rsi
	movq %rsp, %rdx

	xorl %r8d,%r8d
	xorl %r9d,%r9d
	pushq %rcx
	call do_fork_pid
	addq $8, %rsp
	/* call do_fork */
	movq %rax,RAX(%rsp)
	xorl %edi,%edi
	RESTORE_ALL
	UNFAKE_STACK_FRAME
	ret
	CFI_ENDPROC
ENDPROC(asm_kernel_thread)

child_rip:
	pushq $0		# fake return address
	CFI_STARTPROC
	movq %rdi, %rax
	movq %rsi, %rdi
	call *%rax
	movq %rax, %rdi
	call do_exit
	CFI_ENDPROC
ENDPROC(child_rip)

