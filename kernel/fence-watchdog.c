/*
 * Provide userspace with an interface to forbid kernel to work
 * without an userspace daemon.
 *
 * The daemon should write number of seconds before fencing to the
 * file /sys/kernel/watchdog_timer, and must renew it, until the
 * time elapses.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kobject.h>
#include <linux/jiffies.h>
#include <linux/reboot.h>
#include <linux/fence-watchdog.h>
#include <linux/device.h>
#include <linux/kmsg_dump.h>

#define MAX_U64			(~(u64)0)
#define MAX_JIFFIES_DELTA	(10 * 365UL * 24UL * 3600UL * HZ)
#define __section_fence_wdog	__attribute__ ((unused, \
			__section__ (".fence_wdog_jiffies64"), aligned(16)))
#define ACTION_NAME_LEN		16

enum {
	FENCE_WDOG_CRASH = 0,
	FENCE_WDOG_REBOOT = 1,
	FENCE_WDOG_POWEROFF = 2,
	FENCE_WDOG_NETFILTER = 3,
};

const char *action_names[] = {"crash", "reboot", "halt", "netfilter", NULL};

unsigned long volatile __fence_wdog_jiffies64 __section_fence_wdog = MAX_U64;
extern unsigned long volatile fence_wdog_jiffies64;
static int fence_wdog_action = FENCE_WDOG_CRASH;
static atomic_t not_fenced = ATOMIC_INIT(-1);

static void do_halt(struct work_struct *dummy)
{
	printk(KERN_EMERG"fence-watchdog: %s\n",
	       action_names[fence_wdog_action]);
	kernel_halt();
}

static DECLARE_WORK(halt_work, do_halt);

void fence_wdog_do_fence(void)
{
	char *killer = NULL;

	if (fence_wdog_action != FENCE_WDOG_POWEROFF &&
			fence_wdog_action != FENCE_WDOG_NETFILTER) {
		bust_spinlocks(1);
		printk(KERN_EMERG"fence-watchdog: %s\n",
			action_names[fence_wdog_action]);
		bust_spinlocks(0);
	}

	switch (fence_wdog_action) {
	case FENCE_WDOG_CRASH:
		panic_on_oops = 1;
		wmb();
		*killer = 1;
		break;
	case FENCE_WDOG_REBOOT:
		lockdep_off();
		local_irq_enable();
		emergency_restart();
		break;
	case FENCE_WDOG_POWEROFF:
		schedule_work(&halt_work);
		break;
	}
}

inline int fence_wdog_check_timer(void)
{
	if (unlikely(get_jiffies_64() > fence_wdog_jiffies64 &&
			fence_wdog_action != FENCE_WDOG_NETFILTER)) {
		if (atomic_inc_not_zero(&not_fenced))
			fence_wdog_do_fence();
		return 1;
	}

	return 0;
}

bool fence_wdog_tmo_match(void)
{
	return get_jiffies_64() > fence_wdog_jiffies64;
}
EXPORT_SYMBOL(fence_wdog_tmo_match);

static ssize_t fence_wdog_timer_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	ssize_t ret;
	u64 jiffies_delta = fence_wdog_jiffies64 - get_jiffies_64();
	struct timespec t;

	if (jiffies_delta > MAX_JIFFIES_DELTA) {
		ret =  sprintf(buf, "inf\n");
	} else {
		jiffies_to_timespec(jiffies_delta, &t);
		ret =  sprintf(buf, "%ld\n", t.tv_sec);
	}

	return ret;
}

static ssize_t fence_wdog_timer_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	unsigned long long val;
	unsigned long jiffies_delta;
	struct timespec t;

	if (strict_strtoull(buf, 10, &val))
		return -EINVAL;

	if (val == 0) {
		fence_wdog_jiffies64 = MAX_U64;
		return count;
	}

	t.tv_sec = val;
	t.tv_nsec = 0;

	jiffies_delta = timespec_to_jiffies(&t);
	if (jiffies_delta > MAX_JIFFIES_DELTA)
		return -EINVAL;

	fence_wdog_jiffies64 = get_jiffies_64() + jiffies_delta;

	return count;
}

static ssize_t fence_wdog_action_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%s\n", action_names[fence_wdog_action]);
}

static ssize_t fence_wdog_action_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	char str_action[ACTION_NAME_LEN];
	int i = 0;

	if (sscanf(buf, "%15s", str_action) != 1)
		return -EINVAL;

	for (i = 0; action_names[i]; i++) {
		if ((!strnicmp(str_action, action_names[i], ACTION_NAME_LEN))) {
			fence_wdog_action = i;
			return count;
		}
	}

	return -EINVAL;
}

static ssize_t fence_wdog_available_actions_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	int i, ret = 0;

	for (i = 0; action_names[i] != NULL; i++)
		ret += sprintf(&buf[ret], "%s ", action_names[i]);

	ret += sprintf(&buf[ret], "\n");
	return ret;
}

static struct kobj_attribute fence_wdog_timer_attr =
	__ATTR(watchdog_timer, 0644,
		fence_wdog_timer_show, fence_wdog_timer_store);

static struct kobj_attribute fence_wdog_action_attr =
	__ATTR(watchdog_action, 0644,
		fence_wdog_action_show, fence_wdog_action_store);

static struct kobj_attribute fence_wdog_available_actions_attr =
	__ATTR(watchdog_available_actions, 0644,
		fence_wdog_available_actions_show, NULL);

static struct attribute *fence_wdog_attrs[] = {
	&fence_wdog_timer_attr.attr,
	&fence_wdog_action_attr.attr,
	&fence_wdog_available_actions_attr.attr,
	NULL,
};

static struct attribute_group fence_wdog_attr_group = {
	.attrs = fence_wdog_attrs,
};

static int __init fence_wdog_init(void)
{
	sysfs_update_group(kernel_kobj, &fence_wdog_attr_group);
	return 0;
}

module_init(fence_wdog_init)
