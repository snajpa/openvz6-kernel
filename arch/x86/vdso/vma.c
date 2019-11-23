/*
 * Set up the VMAs to tell the VM about the vDSO.
 * Copyright 2007 Andi Kleen, SUSE Labs.
 * Subject to the GPL, v.2
 */
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/random.h>
#include <linux/elf.h>
#include <asm/vsyscall.h>
#include <asm/vgtod.h>
#include <asm/proto.h>
#include <asm/vdso.h>

#include <linux/utsname.h>
#include <linux/version.h>
#include <linux/ve.h>

#include "vextern.h"		/* Just for VMAGIC.  */
#undef VEXTERN

unsigned int __read_mostly vdso_enabled = 1;

extern char vdso_start[], vdso_end[];
extern char vdso_rhel5_start[], vdso_rhel5_end[];
extern unsigned short vdso_sync_cpuid;

static struct page **vdso_pages;
static unsigned vdso_size;

static struct page **vdso_rhel5_pages;
static unsigned vdso_rhel5_size;

static inline void *var_ref(void *p, char *name)
{
	if (*(void **)p != (void *)VMAGIC) {
		printk("VDSO: variable %s broken\n", name);
		vdso_enabled = 0;
	}
	return p;
}

static int __init init_vdso_vars(void)
{
	int npages = (vdso_end - vdso_start + PAGE_SIZE - 1) / PAGE_SIZE;
	int i;
	char *vbase;

	vdso_size = npages << PAGE_SHIFT;
	vdso_pages = kmalloc(sizeof(struct page *) * npages, GFP_KERNEL);
	if (!vdso_pages)
		goto oom;
	for (i = 0; i < npages; i++) {
		struct page *p;
		p = alloc_page(GFP_KERNEL);
		if (!p)
			goto oom;
		vdso_pages[i] = p;
		copy_page(page_address(p), vdso_start + i*PAGE_SIZE);
	}

	vbase = vmap(vdso_pages, npages, 0, PAGE_KERNEL);
	if (!vbase)
		goto oom;

	if (memcmp(vbase, "\177ELF", 4)) {
		printk("VDSO: I'm broken; not ELF\n");
		vdso_enabled = 0;
	}

	init_uts_ns.vdso.addr		= vbase;
	init_uts_ns.vdso.pages		= vdso_pages;
	init_uts_ns.vdso.nr_pages	= npages;
	init_uts_ns.vdso.size		= vdso_size;
	init_uts_ns.vdso.version_off	= (unsigned long)VDSO64_SYMBOL(0, linux_version_code);

#define VEXTERN(x) \
	*(typeof(__ ## x) **) var_ref(VDSO64_SYMBOL(vbase, x), #x) = &__ ## x;
#include "vextern.h"
#undef VEXTERN
	return 0;

 oom:
	printk("Cannot allocate vdso\n");
	vdso_enabled = 0;
	return -ENOMEM;
}
__initcall(init_vdso_vars);

static int __init init_vdso_rhel5_vars(void)
{
	int npages = (vdso_rhel5_end - vdso_rhel5_start + PAGE_SIZE - 1) / PAGE_SIZE;
	int i;
	char *vbase;

	vdso_rhel5_size = npages << PAGE_SHIFT;
	vdso_rhel5_pages = kmalloc(sizeof(struct page *) * npages, GFP_KERNEL);
	if (!vdso_rhel5_pages)
		goto oom;
	for (i = 0; i < npages; i++) {
		struct page *p;
		p = alloc_page(GFP_KERNEL);
		if (!p)
			goto oom;
		vdso_rhel5_pages[i] = p;
		copy_page(page_address(p), vdso_rhel5_start + i*PAGE_SIZE);
	}

	vbase = vmap(vdso_rhel5_pages, npages, 0, PAGE_KERNEL);
	if (!vbase)
		goto oom;

	if (memcmp(vbase, "\177ELF", 4)) {
		printk("VDSO: I'm broken; not ELF\n");
		vdso_enabled = 0;
	}

#define VEXTERN(x) \
	*(typeof(__ ## x) **) var_ref(VDSO64_SYMBOL(vbase, rhel5_ ## x), #x) = &__ ## x;
#include "vextern.h"
#undef VEXTERN
	return 0;

 oom:
	printk("Cannot allocate vdso\n");
	vdso_enabled = 0;
	return -ENOMEM;
}
__initcall(init_vdso_rhel5_vars);

struct linux_binprm;

/* 
 * Put the vdso above the (randomized) stack with another randomized
 * offset.  This way there is no hole in the middle of address space.
 * To save memory make sure it is still in the same PTE as the stack
 * top.  This doesn't give that many random bits.
 *
 * Note that this algorithm is imperfect: the distribution of the vdso
 * start address within a PMD is biased toward the end.
 *
 * Only used for the 64-bit and x32 vdsos.
 */
static unsigned long vdso_addr(unsigned long start, unsigned len)
{
	unsigned long addr, end;
	unsigned offset;

	/*
	 * Round up the start address.  It can start out unaligned as a result
	 * of stack start randomization.
	 */
	start = PAGE_ALIGN(start);

	/* Round the lowest possible end address up to a PMD boundary. */
	end = (start + len + PMD_SIZE - 1) & PMD_MASK;
	if (end >= TASK_SIZE_MAX)
		end = TASK_SIZE_MAX;
	end -= len;

	if (end > start) {
		offset = get_random_int() % (((end - start) >> PAGE_SHIFT) + 1);
		addr = start + (offset << PAGE_SHIFT);
	} else {
		addr = start;
	}

	/*
	 * Forcibly align the final address in case we have a hardware
	 * issue that requires alignment for performance reasons.
	 */
	addr = align_addr(addr, NULL, ALIGN_VDSO);

	return addr;
}

/* Setup a VMA at program startup for the vsyscall page.
   Not called for compat tasks */
int __arch_setup_additional_pages(struct linux_binprm *bprm, int uses_interp,
				unsigned long map_address, struct page ** vdso_pages,
				unsigned vdso_size)
{
	struct mm_struct *mm = current->mm;
	unsigned long addr;
	int ret;

	if (!vdso_enabled && map_address == 0) {
		current->mm->context.vdso = NULL;
		return 0;
	}

	down_write(&mm->mmap_sem);
	if (map_address)
		addr = map_address;
	else
		addr = vdso_addr(mm->start_stack, vdso_size);
	addr = get_unmapped_area(NULL, addr, vdso_size, 0, 0);
	if (IS_ERR_VALUE(addr)) {
		ret = addr;
		goto up_fail;
	}

	current->mm->context.vdso = (void *)addr;

	ret = install_special_mapping(mm, addr, vdso_size,
				      VM_READ|VM_EXEC|
				      VM_MAYREAD|VM_MAYWRITE|VM_MAYEXEC,
				      vdso_pages);
	if (ret) {
		current->mm->context.vdso = NULL;
		goto up_fail;
	}

up_fail:
	up_write(&mm->mmap_sem);
	return ret;
}

static DEFINE_MUTEX(vdso_mutex);

static int uts_arch_setup_additional_pages(struct linux_binprm *bprm,
					   int uses_interp,
					   unsigned long map_address)
{
	struct uts_namespace *uts_ns = current->nsproxy->uts_ns;
	struct ve_struct *ve = get_exec_env();
	int i, n1, n2, n3, new_version;
	struct page **new_pages, **p;

	/*
	 * For node or in case we've not changed UTS simply
	 * map preallocated original vDSO.
	 *
	 * In turn if we already allocated one for this UTS
	 * simply reuse it. It improves speed significantly.
	 */
	if (uts_ns == &init_uts_ns)
		goto map_init_uts;

	/*
	 * Dirty lockless hack. Strictly speaking
	 * we need to return @p here if it's non-nil,
	 * but since there only one trasition possible
	 * { =0 ; !=0 } we simply return @uts_ns->vdso.pages
	 */
	p = ACCESS_ONCE(uts_ns->vdso.pages);
	smp_read_barrier_depends();
	if (p)
		goto map_uts;

	if (sscanf(uts_ns->name.release, "%d.%d.%d", &n1, &n2, &n3) == 3) {
		/*
		 * If there were no changes on version simply reuse
		 * preallocated one.
		 */
		new_version = KERNEL_VERSION(n1, n2, n3);
		if (new_version == LINUX_VERSION_CODE)
			goto map_init_uts;
	} else {
		/*
		 * If admin is passed malformed string here
		 * lets warn him once but continue working
		 * not using vDSO virtualization at all. It's
		 * better than walk out with error.
		 */
		pr_warn_once("Wrong release uts name format detected."
			     " Ignoring vDSO virtualization.\n");
		goto map_init_uts;
	}

	mutex_lock(&vdso_mutex);
	if (uts_ns->vdso.pages) {
		mutex_unlock(&vdso_mutex);
		goto map_uts;
	}

	uts_ns->vdso.nr_pages	= init_uts_ns.vdso.nr_pages;
	uts_ns->vdso.size	= init_uts_ns.vdso.size;
	uts_ns->vdso.version_off= init_uts_ns.vdso.version_off;
	new_pages		= kmalloc(sizeof(struct page *) * init_uts_ns.vdso.nr_pages, GFP_KERNEL);
	if (!new_pages) {
		pr_err("Can't allocate vDSO pages array for VE %d\n", ve->veid);
		goto out_unlock;
	}

	for (i = 0; i < uts_ns->vdso.nr_pages; i++) {
		struct page *p = alloc_page(GFP_KERNEL);
		if (!p) {
			pr_err("Can't allocate page for VE %d\n", ve->veid);
			for (; i > 0; i--)
				put_page(new_pages[i - 1]);
			kfree(new_pages);
			goto out_unlock;
		}
		new_pages[i] = p;
		copy_page(page_address(p), page_address(init_uts_ns.vdso.pages[i]));
	}

	uts_ns->vdso.addr = vmap(new_pages, uts_ns->vdso.nr_pages, 0, PAGE_KERNEL);
	if (!uts_ns->vdso.addr) {
		pr_err("Can't map vDSO pages for VE %d\n", ve->veid);
		for (i = 0; i < uts_ns->vdso.nr_pages; i++)
			put_page(new_pages[i]);
		kfree(new_pages);
		goto out_unlock;
	}

	*((int *)(uts_ns->vdso.addr + uts_ns->vdso.version_off)) = new_version;
	smp_wmb();
	uts_ns->vdso.pages = new_pages;
	mutex_unlock(&vdso_mutex);

	pr_debug("vDSO version transition %d -> %d for VE %d\n",
		 LINUX_VERSION_CODE, new_version, ve->veid);

map_uts:
	return __arch_setup_additional_pages(bprm, uses_interp, map_address,
					     uts_ns->vdso.pages, uts_ns->vdso.size);
map_init_uts:
	return __arch_setup_additional_pages(bprm, uses_interp, map_address,
					     init_uts_ns.vdso.pages, init_uts_ns.vdso.size);
out_unlock:
	mutex_unlock(&vdso_mutex);
	return -ENOMEM;
}

int arch_setup_additional_pages(struct linux_binprm *bprm, int uses_interp,
				unsigned long map_address)
{
	return uts_arch_setup_additional_pages(bprm, uses_interp, map_address);
}
EXPORT_SYMBOL(arch_setup_additional_pages);

int arch_setup_additional_pages_rhel5(struct linux_binprm *bprm, int uses_interp,
				unsigned long map_address)
{
	return __arch_setup_additional_pages(bprm, uses_interp, map_address,
					vdso_rhel5_pages, vdso_rhel5_size);
}
EXPORT_SYMBOL(arch_setup_additional_pages_rhel5);

int vdso_is_rhel5(struct page *page)
{
	return page == vdso_rhel5_pages[0];
}
EXPORT_SYMBOL(vdso_is_rhel5);

static __init int vdso_setup(char *s)
{
	vdso_enabled = simple_strtoul(s, NULL, 0);
	return 0;
}
__setup("vdso=", vdso_setup);
