/* -*- linux-c -*-
 *
 *	$Id: sysrq.c,v 1.15 1998/08/23 14:56:41 mj Exp $
 *
 *	Linux Magic System Request Key Hacks
 *
 *	(c) 1997 Martin Mares <mj@atrey.karlin.mff.cuni.cz>
 *	based on ideas by Pavel Machek <pavel@atrey.karlin.mff.cuni.cz>
 *
 *	(c) 2000 Crutcher Dunnavant <crutcher+kernel@datastacks.com>
 *	overhauled to use key registration
 *	based upon discusions in irc://irc.openprojects.net/#kernelnewbies
 */

#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/tty.h>
#include <linux/mount.h>
#include <linux/kdev_t.h>
#include <linux/major.h>
#include <linux/reboot.h>
#include <linux/sysrq.h>
#include <linux/kbd_kern.h>
#include <linux/proc_fs.h>
#include <linux/nmi.h>
#include <linux/quotaops.h>
#include <linux/perf_event.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/suspend.h>
#include <linux/writeback.h>
#include <linux/buffer_head.h>		/* for fsync_bdev() */
#include <linux/swap.h>
#include <linux/spinlock.h>
#include <linux/vt_kern.h>
#include <linux/workqueue.h>
#include <linux/hrtimer.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/oom.h>
#include <linux/nospec.h>
#include <linux/nmi.h>
#include <net/dst.h>

#include <bc/oom_kill.h>

#include <asm/ptrace.h>
#include <asm/irq_regs.h>

/* Whether we react on sysrq keys or just ignore them */
int __read_mostly __sysrq_enabled = 1;

static int __read_mostly sysrq_always_enabled;

int sysrq_on(void)
{
	return __sysrq_enabled || sysrq_always_enabled;
}

/*
 * A value of 1 means 'all', other nonzero values are an op mask:
 */
static inline int sysrq_on_mask(int mask)
{
	return sysrq_always_enabled || __sysrq_enabled == 1 ||
						(__sysrq_enabled & mask);
}

static int __init sysrq_always_enabled_setup(char *str)
{
	sysrq_always_enabled = 1;
	printk(KERN_INFO "debug: sysrq always enabled.\n");

	return 1;
}

__setup("sysrq_always_enabled", sysrq_always_enabled_setup);


static void sysrq_handle_loglevel(int key, struct tty_struct *tty)
{
	int i;
	i = key - '0';
	console_loglevel = 7;
	printk("Loglevel set to %d\n", i);
	console_loglevel = i;
}
static struct sysrq_key_op sysrq_loglevel_op = {
	.handler	= sysrq_handle_loglevel,
	.help_msg	= "loglevel(0-9)",
	.action_msg	= "Changing Loglevel",
	.enable_mask	= SYSRQ_ENABLE_LOG,
};

#ifdef CONFIG_VT
static void sysrq_handle_SAK(int key, struct tty_struct *tty)
{
	struct work_struct *SAK_work = &vc_cons[fg_console].SAK_work;
	schedule_work(SAK_work);
}
static struct sysrq_key_op sysrq_SAK_op = {
	.handler	= sysrq_handle_SAK,
	.help_msg	= "saK",
	.action_msg	= "SAK",
	.enable_mask	= SYSRQ_ENABLE_KEYBOARD,
};
#else
#define sysrq_SAK_op (*(struct sysrq_key_op *)0)
#endif

#ifdef CONFIG_VT
static void sysrq_handle_unraw(int key, struct tty_struct *tty)
{
	struct kbd_struct *kbd = &kbd_table[fg_console];

	if (kbd)
		kbd->kbdmode = default_utf8 ? VC_UNICODE : VC_XLATE;
}
static struct sysrq_key_op sysrq_unraw_op = {
	.handler	= sysrq_handle_unraw,
	.help_msg	= "unRaw",
	.action_msg	= "Keyboard mode set to system default",
	.enable_mask	= SYSRQ_ENABLE_KEYBOARD,
};
#else
#define sysrq_unraw_op (*(struct sysrq_key_op *)0)
#endif /* CONFIG_VT */

static void sysrq_handle_crash(int key, struct tty_struct *tty)
{
	char *killer = NULL;

	panic_on_oops = 1;	/* force panic */
	wmb();
	*killer = 1;
}
static struct sysrq_key_op sysrq_crash_op = {
	.handler	= sysrq_handle_crash,
	.help_msg	= "Crash",
	.action_msg	= "Trigger a crash",
	.enable_mask	= SYSRQ_ENABLE_DUMP,
};

static void sysrq_handle_reboot(int key, struct tty_struct *tty)
{
	lockdep_off();
	local_irq_enable();
	emergency_restart();
}
static struct sysrq_key_op sysrq_reboot_op = {
	.handler	= sysrq_handle_reboot,
	.help_msg	= "reBoot",
	.action_msg	= "Resetting",
	.enable_mask	= SYSRQ_ENABLE_BOOT,
};

static void sysrq_handle_sync(int key, struct tty_struct *tty)
{
	emergency_sync();
}
static struct sysrq_key_op sysrq_sync_op = {
	.handler	= sysrq_handle_sync,
	.help_msg	= "Sync",
	.action_msg	= "Emergency Sync",
	.enable_mask	= SYSRQ_ENABLE_SYNC,
};

static void sysrq_handle_show_timers(int key, struct tty_struct *tty)
{
	sysrq_timer_list_show();
}

static struct sysrq_key_op sysrq_show_timers_op = {
	.handler	= sysrq_handle_show_timers,
	.help_msg	= "show-all-timers(Q)",
	.action_msg	= "Show clockevent devices & pending hrtimers (no others)",
};

static void sysrq_handle_mountro(int key, struct tty_struct *tty)
{
	emergency_remount();
}
static struct sysrq_key_op sysrq_mountro_op = {
	.handler	= sysrq_handle_mountro,
	.help_msg	= "Unmount",
	.action_msg	= "Emergency Remount R/O",
	.enable_mask	= SYSRQ_ENABLE_REMOUNT,
};

#ifdef CONFIG_LOCKDEP
static void sysrq_handle_showlocks(int key, struct tty_struct *tty)
{
	debug_show_all_locks();
}

static struct sysrq_key_op sysrq_showlocks_op = {
	.handler	= sysrq_handle_showlocks,
	.help_msg	= "show-all-locks(D)",
	.action_msg	= "Show Locks Held",
};
#else
#define sysrq_showlocks_op (*(struct sysrq_key_op *)0)
#endif

#ifdef CONFIG_SCHED_DEBUG
static void sysrq_handle_sched_debug(int key, struct tty_struct *tty)
{
	show_sched_debug();
}

static struct sysrq_key_op sysrq_sched_debug_op = {
	.handler	= sysrq_handle_sched_debug,
	.help_msg	= "show-sched-state(A)",
	.action_msg	= "CPU Scheduler State",
};
#endif

#ifdef CONFIG_SMP
static DEFINE_SPINLOCK(show_lock);

static void showacpu(void *dummy)
{
	unsigned long flags;

	/* Idle CPUs have no interesting backtrace. */
	if (idle_cpu(smp_processor_id()))
		return;

	spin_lock_irqsave(&show_lock, flags);
	printk(KERN_INFO "CPU%d:\n", smp_processor_id());
	show_stack(NULL, NULL);
	spin_unlock_irqrestore(&show_lock, flags);
}

static void sysrq_showregs_othercpus(struct work_struct *dummy)
{
	smp_call_function(showacpu, NULL, 0);
}

static DECLARE_WORK(sysrq_showallcpus, sysrq_showregs_othercpus);

static void sysrq_handle_showallcpus(int key, struct tty_struct *tty)
{
	/*
	 * Fall back to the workqueue based printing if the
	 * backtrace printing did not succeed or the
	 * architecture has no support for it:
	 */
	if (!trigger_all_cpu_backtrace()) {
		struct pt_regs *regs = get_irq_regs();

		if (regs) {
			printk(KERN_INFO "CPU%d:\n", smp_processor_id());
			show_regs(regs);
		}
		schedule_work(&sysrq_showallcpus);
	}
}

static struct sysrq_key_op sysrq_showallcpus_op = {
	.handler	= sysrq_handle_showallcpus,
	.help_msg	= "show-backtrace-all-active-cpus(L)",
	.action_msg	= "Show backtrace of all active CPUs",
	.enable_mask	= SYSRQ_ENABLE_DUMP,
};
#endif

static void sysrq_handle_showregs(int key, struct tty_struct *tty)
{
	struct pt_regs *regs = get_irq_regs();

	nmi_show_regs(regs, 0);
	perf_event_print_debug();
}
static struct sysrq_key_op sysrq_showregs_op = {
	.handler	= sysrq_handle_showregs,
	.help_msg	= "show-registers(P)",
	.action_msg	= "Show Regs",
	.enable_mask	= SYSRQ_ENABLE_DUMP,
};

static void sysrq_handle_showstate(int key, struct tty_struct *tty)
{
	show_state();
}
static struct sysrq_key_op sysrq_showstate_op = {
	.handler	= sysrq_handle_showstate,
	.help_msg	= "show-task-states(T)",
	.action_msg	= "Show State",
	.enable_mask	= SYSRQ_ENABLE_DUMP,
};

static void sysrq_handle_showstate_blocked(int key, struct tty_struct *tty)
{
	show_state_filter(TASK_UNINTERRUPTIBLE);
}
static struct sysrq_key_op sysrq_showstate_blocked_op = {
	.handler	= sysrq_handle_showstate_blocked,
	.help_msg	= "show-blocked-tasks(W)",
	.action_msg	= "Show Blocked State",
	.enable_mask	= SYSRQ_ENABLE_DUMP,
};

#ifdef CONFIG_TRACING
#include <linux/ftrace.h>

static void sysrq_ftrace_dump(int key, struct tty_struct *tty)
{
	ftrace_dump();
}
static struct sysrq_key_op sysrq_ftrace_dump_op = {
	.handler	= sysrq_ftrace_dump,
	.help_msg	= "dump-ftrace-buffer(Z)",
	.action_msg	= "Dump ftrace buffer",
	.enable_mask	= SYSRQ_ENABLE_DUMP,
};
#else
#define sysrq_ftrace_dump_op (*(struct sysrq_key_op *)0)
#endif

static void sysrq_handle_showmem(int key, struct tty_struct *tty)
{
	struct user_beancounter *ub;

	rcu_read_lock();
	for_each_top_beancounter(ub)
		show_ub_mem(ub);
	rcu_read_unlock();

	show_mem(0);
	show_slab_info();
}
static struct sysrq_key_op sysrq_showmem_op = {
	.handler	= sysrq_handle_showmem,
	.help_msg	= "show-memory-usage(M)",
	.action_msg	= "Show Memory",
	.enable_mask	= SYSRQ_ENABLE_DUMP,
};

/*
 * Signal sysrq helper function.  Sends a signal to all user processes.
 */
static void send_sig_all(int sig)
{
	struct task_struct *p;

	for_each_process_all(p) {
		if (p->mm && !is_global_init(p))
			/* Not swapper, init nor kernel thread */
			force_sig(sig, p);
	}
}

static void sysrq_handle_term(int key, struct tty_struct *tty)
{
	send_sig_all(SIGTERM);
	console_loglevel = 8;
}
static struct sysrq_key_op sysrq_term_op = {
	.handler	= sysrq_handle_term,
	.help_msg	= "terminate-all-tasks(E)",
	.action_msg	= "Terminate All Tasks",
	.enable_mask	= SYSRQ_ENABLE_SIGNAL,
};

static void moom_callback(struct work_struct *ignored)
{
	ub_oom_start(&global_oom_ctrl);
	global_oom_ctrl.kill_counter = 0;
	out_of_memory(node_zonelist(0, GFP_KERNEL), GFP_KERNEL, 0, NULL);
}

static DECLARE_WORK(moom_work, moom_callback);

static void sysrq_handle_moom(int key, struct tty_struct *tty)
{
	schedule_work(&moom_work);
}
static struct sysrq_key_op sysrq_moom_op = {
	.handler	= sysrq_handle_moom,
	.help_msg	= "memory-full-oom-kill(F)",
	.action_msg	= "Manual OOM execution",
	.enable_mask	= SYSRQ_ENABLE_SIGNAL,
};

#ifdef CONFIG_BLOCK
static void sysrq_handle_thaw(int key, struct tty_struct *tty)
{
	emergency_thaw_all();
}
static struct sysrq_key_op sysrq_thaw_op = {
	.handler	= sysrq_handle_thaw,
	.help_msg	= "thaw-filesystems(J)",
	.action_msg	= "Emergency Thaw of all frozen filesystems",
	.enable_mask	= SYSRQ_ENABLE_SIGNAL,
};
#endif

static void sysrq_handle_kill(int key, struct tty_struct *tty)
{
	send_sig_all(SIGKILL);
	console_loglevel = 8;
}
static struct sysrq_key_op sysrq_kill_op = {
	.handler	= sysrq_handle_kill,
	.help_msg	= "kill-all-tasks(I)",
	.action_msg	= "Kill All Tasks",
	.enable_mask	= SYSRQ_ENABLE_SIGNAL,
};

static void sysrq_handle_unrt(int key, struct tty_struct *tty)
{
	normalize_rt_tasks();
}
static struct sysrq_key_op sysrq_unrt_op = {
	.handler	= sysrq_handle_unrt,
	.help_msg	= "nice-all-RT-tasks(N)",
	.action_msg	= "Nice All RT Tasks",
	.enable_mask	= SYSRQ_ENABLE_RTNICE,
};

/* Key Operations table and lock */
static DEFINE_SPINLOCK(sysrq_key_table_lock);

#define SYSRQ_KEY_TABLE_LENGTH 37
static struct sysrq_key_op **sysrq_key_table;
static struct sysrq_key_op *sysrq_default_key_table[];

#ifdef CONFIG_SYSRQ_DEBUG
#define SYSRQ_NAMELEN_MAX	64
#define SYSRQ_DUMP_LINES	32

static struct sysrq_key_op *sysrq_debug_key_table[];
static struct sysrq_key_op *sysrq_input_key_table[];
static unsigned long *dump_address;
static struct kmem_cache *dump_slab_ptr;
static int orig_console_loglevel;
static void (*sysrq_input_return)(char *) = NULL;

static unsigned long dump_offset, dump_index, dump_count;

static bool dump_skip(void)
{
	if (!dump_count || ++dump_index <= dump_offset)
		return true;
	dump_count--;
	return false;
}

static void dump_mem(void)
{
	unsigned long value[4];
	mm_segment_t old_fs;
	int line, err;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = 0;

	for (line = 0; line < SYSRQ_DUMP_LINES; line++) {
		err |= __get_user(value[0], dump_address++);
		err |= __get_user(value[1], dump_address++);
		err |= __get_user(value[2], dump_address++);
		err |= __get_user(value[3], dump_address++);
		if (err) {
			printk("Invalid address %p\n", dump_address - 4);
			break;
		}
#if BITS_PER_LONG == 32
		printk("0x%p: %08lx %08lx %08lx %08lx\n",
				dump_address - 4,
				value[0], value[1], value[2], value[3]);
#else
		printk("0x%p: %016lx %016lx %016lx %016lx\n",
				dump_address - 4,
				value[0], value[1], value[2], value[3]);
#endif
	}
	set_fs(old_fs);
}

static void write_mem(unsigned long val)
{
	mm_segment_t old_fs;
	unsigned long old_val;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	if (__get_user(old_val, dump_address)) {
		printk("Invalid address %p\n", dump_address);
		goto out;
	}

#if BITS_PER_LONG == 32
	printk("Changing [%p] from %08lx to %08lx\n",
			dump_address, old_val, val);
#else
	printk("Changing [%p] from %016lx to %016lx\n",
			dump_address, old_val, val);
#endif
	__put_user(val, dump_address);
out:
	set_fs(old_fs);
}

static void handle_read(int key, struct tty_struct *tty)
{
	static int pos;
	static int upper_case;
	static char str[SYSRQ_NAMELEN_MAX];

	if (key == 0) {
		/* actually 0 is not shift only... */
		upper_case = 1;
		return;
	}

	if (key == 0x0d || pos == SYSRQ_NAMELEN_MAX - 1) {
		/* enter */
		sysrq_key_table = sysrq_debug_key_table;
		str[pos] = '\0';
		pos = upper_case = 0;
		printk("\n");
		if (sysrq_input_return == NULL)
			printk("No return handler!!!\n");
		else
			sysrq_input_return(str);
		return;
	};

	/* check for alowed symbols */
	if (key == '-') {
		if (upper_case)
			key = '_';
		goto correct;
	};
	if (key >= 'a' && key <= 'z') {
		if (upper_case)
			key = key - 'a' + 'A';
		goto correct;
	};
	if (key >= '0' && key <= '9')
		goto correct;

	upper_case = 0;
	return;

correct:
	str[pos] = key;
	printk("%c", (char)key);
	pos++;
	upper_case = 0;
}

static struct sysrq_key_op input_read = {
	.handler	= handle_read,
	.help_msg	= "",
	.action_msg	= NULL,
};

static struct sysrq_key_op *sysrq_input_key_table[SYSRQ_KEY_TABLE_LENGTH] = {
	[0 ... SYSRQ_KEY_TABLE_LENGTH - 1] = &input_read,
};

static void return_dump_mem(char *str)
{
	unsigned long address;
	char *end;

	address = simple_strtoul(str, &end, 0);
	if (*end != '\0') {
		printk("Bad address [%s]\n", str);
		return;
	}

	dump_address = (unsigned long *)address;
	dump_mem();
}

static void handle_dump_mem(int key, struct tty_struct *tty)
{
	sysrq_input_return = return_dump_mem;
	sysrq_key_table = sysrq_input_key_table;
}

static struct sysrq_key_op debug_dump_mem = {
	.handler	= handle_dump_mem,
	.help_msg	= "Dump",
	.action_msg	= "Enter address:",
};

static void dump_slab_obj(void *obj)
{
	struct user_beancounter *ubc = NULL;

	if (dump_skip())
		return;

	if (dump_slab_ptr->flags & SLAB_UBC)
		ubc = *ub_slab_ptr(dump_slab_ptr, obj);

	printk(KERN_DEBUG"obj %p idx %lu ubc %p\n", obj, dump_index, ubc);
	print_hex_dump(KERN_DEBUG, "", DUMP_PREFIX_OFFSET,
			16, sizeof(long), obj, dump_slab_ptr->buffer_size, false);
}

static void dump_slab(void)
{
	dump_index = 0;
	dump_count = 100;
	slab_obj_walk(dump_slab_ptr, dump_slab_obj);
	dump_offset = dump_index;
}

static void return_dump_slab(char *str)
{
	unsigned long address;
	char *end;

	address = simple_strtoul(str, &end, 0);
	if (*end != '\0') {
		printk("Bad address [%s]\n", str);
		return;
	}

	dump_slab_ptr = (struct kmem_cache *)address;
	if (!virt_addr_valid(dump_slab_ptr) ||
	    !PageSlab(virt_to_page(dump_slab_ptr))) {
		printk("Non-slab address [%s]\n", str);
		dump_slab_ptr = NULL;
		return;
	}

	printk(KERN_DEBUG "SLAB %p %s size %d objuse %d\n",
			dump_slab_ptr, dump_slab_ptr->name,
			dump_slab_ptr->buffer_size, dump_slab_ptr->objuse);

	dump_address = NULL;
	dump_offset = 0;
	dump_slab();
}

static void handle_dump_slab(int key, struct tty_struct *tty)
{
	sysrq_input_return = return_dump_slab;
	sysrq_key_table = sysrq_input_key_table;
}

static struct sysrq_key_op debug_dump_slab = {
	.handler	= handle_dump_slab,
	.help_msg	= "Slab",
	.action_msg	= "Enter address:",
};

static void handle_dump_net(int key, struct tty_struct *tty)
{
	dst_cache_dump();
}

static struct sysrq_key_op debug_dump_net = {
	.handler	= handle_dump_net,
	.help_msg	= "Net",
	.action_msg	= "Dumping networking guts:",
};

static void return_resolve(char *str)
{
	unsigned long address;

	address = kallsyms_lookup_name(str);
	printk("%s : %lx\n", str, address);
	if (address) {
		dump_address = (unsigned long *)address;
		printk("Now you can dump it via X\n");
	}
}

static void handle_resolve(int key, struct tty_struct *tty)
{
	sysrq_input_return = return_resolve;
	sysrq_key_table = sysrq_input_key_table;
}

static struct sysrq_key_op debug_resolve = {
	.handler	= handle_resolve,
	.help_msg	= "Resolve",
	.action_msg	= "Enter symbol name:",
};

static void return_write_mem(char *str)
{
	unsigned long address;
	unsigned long value;
	char *end;

	address = simple_strtoul(str, &end, 0);
	if (*end != '-') {
		printk("Bad address in %s\n", str);
		return;
	}
	value = simple_strtoul(end + 1, &end, 0);
	if (*end != '\0') {
		printk("Bad value in %s\n", str);
		return;
	}

	dump_address = (unsigned long *)address;
	write_mem(value);
}

static void handle_write_mem(int key, struct tty_struct *tty)
{
	sysrq_input_return = return_write_mem;
	sysrq_key_table = sysrq_input_key_table;
}

static struct sysrq_key_op debug_write_mem = {
	.handler	= handle_write_mem,
	.help_msg	= "Writemem",
	.action_msg	= "Enter address-value:",
};

static void handle_next(int key, struct tty_struct *tty)
{
	if (dump_address)
		dump_mem();
	else if (dump_slab_ptr)
		dump_slab();
}

static struct sysrq_key_op debug_next = {
	.handler	= handle_next,
	.help_msg	= "neXt",
	.action_msg	= "continuing",
};

static void handle_quit(int key, struct tty_struct *tty)
{
	sysrq_key_table = sysrq_default_key_table;
	console_loglevel = orig_console_loglevel;
}

static struct sysrq_key_op debug_quit = {
	.handler	= handle_quit,
	.help_msg	= "Quit",
	.action_msg	= "Thank you for using debugger",
};

static struct sysrq_key_op *sysrq_debug_key_table[SYSRQ_KEY_TABLE_LENGTH] = {
	[13] = &debug_dump_mem,		/* d */
	[23] = &debug_dump_net,		/* n */
	[26] = &debug_quit,		/* q */
	[27] = &debug_resolve,		/* r */
	[28] = &debug_dump_slab,	/* s */
	[32] = &debug_write_mem,	/* w */
	[33] = &debug_next,		/* x */
};

static void sysrq_handle_debug(int key, struct tty_struct *tty)
{
	orig_console_loglevel = console_loglevel;
	console_loglevel = 8;
	sysrq_key_table = sysrq_debug_key_table;
	printk("Welcome sysrq debugging mode\n"
			"Press H for help\n");
}

static struct sysrq_key_op sysrq_debug_op = {
	.handler        = sysrq_handle_debug,
	.help_msg       = "debuG",
	.action_msg     = "Select desired action",
};
#endif

static struct sysrq_key_op *sysrq_default_key_table[SYSRQ_KEY_TABLE_LENGTH] = {
	&sysrq_loglevel_op,		/* 0 */
	&sysrq_loglevel_op,		/* 1 */
	&sysrq_loglevel_op,		/* 2 */
	&sysrq_loglevel_op,		/* 3 */
	&sysrq_loglevel_op,		/* 4 */
	&sysrq_loglevel_op,		/* 5 */
	&sysrq_loglevel_op,		/* 6 */
	&sysrq_loglevel_op,		/* 7 */
	&sysrq_loglevel_op,		/* 8 */
	&sysrq_loglevel_op,		/* 9 */

	/*
	 * a: Don't use for system provided sysrqs, it is handled specially on
	 * sparc and will never arrive.
	 */
#ifdef CONFIG_SCHED_DEBUG
	&sysrq_sched_debug_op,		/* a */
#else
	NULL,				/* a */
#endif
	&sysrq_reboot_op,		/* b */
	&sysrq_crash_op,		/* c & ibm_emac driver debug */
	&sysrq_showlocks_op,		/* d */
	&sysrq_term_op,			/* e */
	&sysrq_moom_op,			/* f */
	/* g: May be registered for the kernel debugger */
#ifdef CONFIG_SYSRQ_DEBUG
	&sysrq_debug_op,		/* g */
#else
	NULL,				/* g */
#endif
	NULL,				/* h - reserved for help */
	&sysrq_kill_op,			/* i */
#ifdef CONFIG_BLOCK
	&sysrq_thaw_op,			/* j */
#else
	NULL,				/* j */
#endif
	&sysrq_SAK_op,			/* k */
#ifdef CONFIG_SMP
	&sysrq_showallcpus_op,		/* l */
#else
	NULL,				/* l */
#endif
	&sysrq_showmem_op,		/* m */
	&sysrq_unrt_op,			/* n */
	/* o: This will often be registered as 'Off' at init time */
	NULL,				/* o */
	&sysrq_showregs_op,		/* p */
	&sysrq_show_timers_op,		/* q */
	&sysrq_unraw_op,		/* r */
	&sysrq_sync_op,			/* s */
	&sysrq_showstate_op,		/* t */
	&sysrq_mountro_op,		/* u */
	/* v: May be registered for frame buffer console restore */
	NULL,				/* v */
	&sysrq_showstate_blocked_op,	/* w */
	/* x: May be registered on ppc/powerpc for xmon */
	NULL,				/* x */
	/* y: May be registered on sparc64 for global register dump */
	NULL,				/* y */
	&sysrq_ftrace_dump_op,		/* z */
	NULL,				/* for debugger */
};

static struct sysrq_key_op **sysrq_key_table = sysrq_default_key_table;

/* key2index calculation, -1 on invalid index */
static int sysrq_key_table_key2index(int key)
{
	int retval;

	if ((key >= '0') && (key <= '9'))
		retval = key - '0';
	else if ((key >= 'a') && (key <= 'z'))
		retval = key + 10 - 'a';
#ifdef CONFIG_SYSRQ_DEBUG
	else if (key == 0 || key == 0x0d || key == '-')
		retval = SYSRQ_KEY_TABLE_LENGTH - 1;
#endif
	else
		retval = -1;
	return retval;
}

/*
 * get and put functions for the table, exposed to modules.
 */
struct sysrq_key_op *__sysrq_get_key_op(int key)
{
	struct sysrq_key_op *op_p = NULL;
	int i;

	i = sysrq_key_table_key2index(key);
	if (i != -1) {
		i = array_index_nospec(i, SYSRQ_KEY_TABLE_LENGTH);
		op_p = sysrq_key_table[i];
	}
	return op_p;
}

static void __sysrq_put_key_op(int key, struct sysrq_key_op *op_p)
{
	int i = sysrq_key_table_key2index(key);

	if (i != -1)
		sysrq_key_table[i] = op_p;
}

/*
 * This is the non-locking version of handle_sysrq.  It must/can only be called
 * by sysrq key handlers, as they are inside of the lock
 */
void __handle_sysrq(int key, struct tty_struct *tty, int check_mask)
{
	struct sysrq_key_op *op_p;
	int orig_log_level;
	int i;
	unsigned long flags;

	spin_lock_irqsave(&sysrq_key_table_lock, flags);
	/*
	 * Raise the apparent loglevel to maximum so that the sysrq header
	 * is shown to provide the user with positive feedback.  We do not
	 * simply emit this at KERN_EMERG as that would change message
	 * routing in the consumers of /proc/kmsg.
	 */
	orig_log_level = console_loglevel;
	console_loglevel = 7;

	op_p = __sysrq_get_key_op(key);
	if (op_p) {
		/*
		 * Should we check for enabled operations (/proc/sysrq-trigger
		 * should not) and is the invoked operation enabled?
		 */
		if (!check_mask || sysrq_on_mask(op_p->enable_mask)) {
			if (op_p->action_msg)
				printk("%s\n", op_p->action_msg);
			console_loglevel = orig_log_level;
			op_p->handler(key, tty);
		} else {
			printk("This sysrq operation is disabled.\n");
		}
	} else {
		printk("SysRq HELP : ");
		/* Only print the help msg once per handler */
		for (i = 0; i < SYSRQ_KEY_TABLE_LENGTH; i++) {
			if (sysrq_key_table[i]) {
				int j;

				for (j = 0; sysrq_key_table[i] !=
						sysrq_key_table[j]; j++)
					;
				if (j != i)
					continue;
				printk("%s ", sysrq_key_table[i]->help_msg);
			}
		}
		printk("\n");
		console_loglevel = orig_log_level;
	}
	spin_unlock_irqrestore(&sysrq_key_table_lock, flags);
}

/*
 * This function is called by the keyboard handler when SysRq is pressed
 * and any other keycode arrives.
 */
void handle_sysrq(int key, struct tty_struct *tty)
{
	if (sysrq_on())
		__handle_sysrq(key, tty, 1);
}
EXPORT_SYMBOL(handle_sysrq);

static int __sysrq_swap_key_ops(int key, struct sysrq_key_op *insert_op_p,
				struct sysrq_key_op *remove_op_p)
{

	int retval;
	unsigned long flags;

	spin_lock_irqsave(&sysrq_key_table_lock, flags);
	if (__sysrq_get_key_op(key) == remove_op_p) {
		__sysrq_put_key_op(key, insert_op_p);
		retval = 0;
	} else {
		retval = -1;
	}
	spin_unlock_irqrestore(&sysrq_key_table_lock, flags);
	return retval;
}

int register_sysrq_key(int key, struct sysrq_key_op *op_p)
{
	return __sysrq_swap_key_ops(key, op_p, NULL);
}
EXPORT_SYMBOL(register_sysrq_key);

int unregister_sysrq_key(int key, struct sysrq_key_op *op_p)
{
	return __sysrq_swap_key_ops(key, NULL, op_p);
}
EXPORT_SYMBOL(unregister_sysrq_key);

#ifdef CONFIG_PROC_FS
/*
 * writing 'C' to /proc/sysrq-trigger is like sysrq-C
 */
static ssize_t write_sysrq_trigger(struct file *file, const char __user *buf,
				   size_t count, loff_t *ppos)
{
	struct ve_struct *cur = get_exec_env();
	static int pnum = 10;

	if (count) {
		int i, cnt;
		char c[32];

		cnt = min(count, sizeof(c));
		if (copy_from_user(c, buf, cnt))
			return -EFAULT;


		for (i = 0; i < cnt && c[i] != '\n'; i++) {
			if (!ve_is_super(cur))	{
				if (!pnum)
					continue;
				printk("SysRq: CT#%u sent '%c' magic key.\n",
						cur->veid, c[i]);
				pnum--;
				continue;
			}
			__handle_sysrq(c[i], NULL, 0);
		}
	}
	return count;
}

static const struct file_operations proc_sysrq_trigger_operations = {
	.write		= write_sysrq_trigger,
};

static int __init sysrq_init(void)
{
	proc_create("sysrq-trigger", S_IWUSR, &glob_proc_root, &proc_sysrq_trigger_operations);
	return 0;
}
module_init(sysrq_init);
#endif
