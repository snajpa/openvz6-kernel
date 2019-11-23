#include <linux/init.h>

__INITDATA

	.globl vdso_rhel5_start, vdso_rhel5_end
vdso_rhel5_start:
	.incbin "arch/x86/vdso/vdso-rhel5.so"
vdso_rhel5_end:

__FINIT
