/*
 * device_cgroup.c - device cgroup subsystem
 *
 * Copyright 2007 IBM Corp
 */

#include <linux/device_cgroup.h>
#include <linux/cgroup.h>
#include <linux/ctype.h>
#include <linux/list.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/rcupdate.h>
#include <linux/mutex.h>
#include <linux/ve.h>
#include <linux/vzcalluser.h>
#include <linux/major.h>

#define ACC_MKNOD 1
#define ACC_READ  2
#define ACC_WRITE 4
#define ACC_QUOTA 8
#define ACC_HIDDEN 16
#define ACC_MOUNT 64
#define ACC_MASK (ACC_MKNOD | ACC_READ | ACC_WRITE | ACC_QUOTA | ACC_MOUNT)

static inline int convert_bits(int acc)
{
	/* ...10x <-> ...01x   trial: guess hwy */
	return ((((acc & 06) == 00) || ((acc & 06) == 06)) ? acc : acc ^06) &
		(ACC_READ | ACC_WRITE | ACC_QUOTA | ACC_MOUNT);
}

#define DEV_BLOCK 1
#define DEV_CHAR  2
#define DEV_ALL   4  /* this represents all devices */

static DEFINE_MUTEX(devcgroup_mutex);

/*
 * exception list locking rules:
 * hold devcgroup_mutex for update/read.
 * hold rcu_read_lock() for read.
 */

struct dev_exception_item {
	u32 major, minor;
	short type;
	short access;
	struct list_head list;
	struct rcu_head rcu;
};

struct dev_cgroup {
	struct cgroup_subsys_state css;
	struct list_head exceptions;
	enum {
		DEVCG_DEFAULT_ALLOW,
		DEVCG_DEFAULT_DENY,
	} behavior;
};

static inline struct dev_cgroup *css_to_devcgroup(struct cgroup_subsys_state *s)
{
	return container_of(s, struct dev_cgroup, css);
}

static inline struct dev_cgroup *cgroup_to_devcgroup(struct cgroup *cgroup)
{
	return css_to_devcgroup(cgroup_subsys_state(cgroup, devices_subsys_id));
}

static inline struct dev_cgroup *task_devcgroup(struct task_struct *task)
{
	return css_to_devcgroup(task_subsys_state(task, devices_subsys_id));
}

struct cgroup_subsys devices_subsys;

static int devcgroup_can_attach(struct cgroup_subsys *ss,
		struct cgroup *new_cgroup, struct task_struct *task)
{
	if (current != task && !capable(CAP_SYS_ADMIN) && !capable(CAP_VE_SYS_ADMIN))
			return -EPERM;

	return 0;
}

/*
 * called under devcgroup_mutex
 */
static int dev_exceptions_copy(struct list_head *dest, struct list_head *orig)
{
	struct dev_exception_item *ex, *tmp, *new;

	list_for_each_entry(ex, orig, list) {
		new = kmemdup(ex, sizeof(*ex), GFP_KERNEL);
		if (!new)
			goto free_and_exit;
		list_add_tail(&new->list, dest);
	}

	return 0;

free_and_exit:
	list_for_each_entry_safe(ex, tmp, dest, list) {
		list_del(&ex->list);
		kfree(ex);
	}
	return -ENOMEM;
}

/*
 * called under devcgroup_mutex
 */
static int dev_exception_add(struct dev_cgroup *dev_cgroup,
			     struct dev_exception_item *ex)
{
	struct dev_exception_item *excopy, *walk;

	excopy = kmemdup(ex, sizeof(*ex), GFP_KERNEL);
	if (!excopy)
		return -ENOMEM;

	list_for_each_entry(walk, &dev_cgroup->exceptions, list) {
		if (walk->type != ex->type)
			continue;
		if (walk->major != ex->major)
			continue;
		if (walk->minor != ex->minor)
			continue;

		walk->access |= ex->access;
		kfree(excopy);
		excopy = NULL;
	}

	if (excopy != NULL)
		list_add_tail_rcu(&excopy->list, &dev_cgroup->exceptions);
	return 0;
}

/*
 * called under devcgroup_mutex
 */
static int dev_exception_change(struct dev_cgroup *dev_cgroup,
			struct dev_exception_item *ex)
{
	struct dev_exception_item *excopy, *walk, *tmp;

	if (ex->access != 0) {
		excopy = kmemdup(ex, sizeof(*ex), GFP_KERNEL);
		if (!excopy)
			return -ENOMEM;
	} else
		excopy = NULL;

	list_for_each_entry_safe(walk, tmp, &dev_cgroup->exceptions, list) {
		if (walk->type != ex->type)
			continue;
		if (walk->major != ex->major)
			continue;
		if (walk->minor != ex->minor)
			continue;

		if (ex->access == 0) {
			list_del_rcu(&walk->list);
			kfree_rcu(walk, rcu);
		} else {
			walk->access = ex->access;
			kfree(excopy);
			excopy = NULL;
		}
	}

	if (excopy != NULL)
		list_add_tail_rcu(&excopy->list, &dev_cgroup->exceptions);

	return 0;
}

/*
 * called under devcgroup_mutex
 */
static void dev_exception_rm(struct dev_cgroup *dev_cgroup,
			     struct dev_exception_item *ex)
{
	struct dev_exception_item *walk, *tmp;

	list_for_each_entry_safe(walk, tmp, &dev_cgroup->exceptions, list) {
		if (walk->type == DEV_ALL)
			goto remove;
		if (walk->type != ex->type)
			continue;
		if (walk->major != ex->major)
			continue;
		if (walk->minor != ex->minor)
			continue;

remove:
		walk->access &= ~ex->access;
		if (!walk->access) {
			list_del_rcu(&walk->list);
			kfree_rcu(walk, rcu);
		}
	}
}

/**
 * dev_exception_clean - frees all entries of the exception list
 * @dev_cgroup: dev_cgroup with the exception list to be cleaned
 *
 * called under devcgroup_mutex
 */
static void dev_exception_clean(struct dev_cgroup *dev_cgroup)
{
	struct dev_exception_item *ex, *tmp;

	list_for_each_entry_safe(ex, tmp, &dev_cgroup->exceptions, list) {
		list_del_rcu(&ex->list);
		kfree_rcu(ex, rcu);
	}
}

/*
 * called from kernel/cgroup.c with cgroup_lock() held.
 */
static struct cgroup_subsys_state *devcgroup_create(struct cgroup_subsys *ss,
						struct cgroup *cgroup)
{
	struct dev_cgroup *dev_cgroup, *parent_dev_cgroup;
	struct cgroup *parent_cgroup;
	int ret;

	dev_cgroup = kzalloc(sizeof(*dev_cgroup), GFP_KERNEL);
	if (!dev_cgroup)
		return ERR_PTR(-ENOMEM);
	INIT_LIST_HEAD(&dev_cgroup->exceptions);
	parent_cgroup = cgroup->parent;

	if (parent_cgroup == NULL) {
		dev_cgroup->behavior = DEVCG_DEFAULT_ALLOW;
	} else {
		parent_dev_cgroup = cgroup_to_devcgroup(parent_cgroup);
		mutex_lock(&devcgroup_mutex);
		ret = dev_exceptions_copy(&dev_cgroup->exceptions,
					  &parent_dev_cgroup->exceptions);
		dev_cgroup->behavior = parent_dev_cgroup->behavior;
		mutex_unlock(&devcgroup_mutex);
		if (ret) {
			kfree(dev_cgroup);
			return ERR_PTR(ret);
		}
	}

	return &dev_cgroup->css;
}

static void devcgroup_destroy(struct cgroup_subsys *ss,
			struct cgroup *cgroup)
{
	struct dev_cgroup *dev_cgroup;

	dev_cgroup = cgroup_to_devcgroup(cgroup);
	dev_exception_clean(dev_cgroup);
	kfree(dev_cgroup);
}

#define DEVCG_ALLOW 1
#define DEVCG_DENY 2
#define DEVCG_LIST 3

#define MAJMINLEN 13
#define ACCLEN 4

static void set_access(char *acc, short access)
{
	int idx = 0;
	memset(acc, 0, ACCLEN);
	if (access & ACC_READ)
		acc[idx++] = 'r';
	if (access & ACC_WRITE)
		acc[idx++] = 'w';
	if (access & ACC_MKNOD)
		acc[idx++] = 'm';
}

static char type_to_char(short type)
{
	if (type == DEV_ALL)
		return 'a';
	if (type == DEV_CHAR)
		return 'c';
	if (type == DEV_BLOCK)
		return 'b';
	return 'X';
}

static void set_majmin(char *str, unsigned m)
{
	if (m == ~0)
		strcpy(str, "*");
	else
		sprintf(str, "%u", m);
}

static int devcgroup_seq_read(struct cgroup *cgroup, struct cftype *cft,
				struct seq_file *m)
{
	struct dev_cgroup *devcgroup = cgroup_to_devcgroup(cgroup);
	struct dev_exception_item *ex;
	char maj[MAJMINLEN], min[MAJMINLEN], acc[ACCLEN];

	rcu_read_lock();
	/*
	 * To preserve the compatibility:
	 * - Only show the "all devices" when the default policy is to allow
	 * - List the exceptions in case the default policy is to deny
	 * This way, the file remains as a "whitelist of devices"
	 */
	if (devcgroup->behavior == DEVCG_DEFAULT_ALLOW) {
		set_access(acc, ACC_MASK);
		set_majmin(maj, ~0);
		set_majmin(min, ~0);
		seq_printf(m, "%c %s:%s %s\n", type_to_char(DEV_ALL),
			   maj, min, acc);
	} else {
		list_for_each_entry_rcu(ex, &devcgroup->exceptions, list) {
			set_access(acc, ex->access);
			set_majmin(maj, ex->major);
			set_majmin(min, ex->minor);

			if (cft != NULL)
				seq_printf(m, "%c %s:%s %s\n",
					   type_to_char(ex->type),
					   maj, min, acc);
			else if (!(ex->access & ACC_HIDDEN)) {
				int access;

				access = convert_bits(ex->access);
				if (access & (ACC_READ | ACC_WRITE))
					access |= S_IXOTH;

				seq_printf(m, "%10u %c %03o %s:%s\n",
					   (unsigned)(unsigned long)m->private,
					   type_to_char(ex->type),
					   access, maj, min);
			}
		}
	}
	rcu_read_unlock();

	return 0;
}

/**
 * may_access - verifies if a new exception is part of what is allowed
 *		by a dev cgroup based on the default policy +
 *		exceptions. This is used to make sure a child cgroup
 *		won't have more privileges than its parent or to
 *		verify if a certain access is allowed.
 * @dev_cgroup: dev cgroup to be tested against
 * @refex: new exception
 */
static int may_access(struct dev_cgroup *dev_cgroup,
		      struct dev_exception_item *refex)
{
	struct dev_exception_item *ex;
	bool match = false;

	list_for_each_entry_rcu(ex, &dev_cgroup->exceptions, list) {
		short mismatched_bits;
		bool allowed_mount;

		if (ex->type & DEV_ALL)
 			goto found;
		if ((refex->type & DEV_BLOCK) && !(ex->type & DEV_BLOCK))
			continue;
		if ((refex->type & DEV_CHAR) && !(ex->type & DEV_CHAR))
			continue;
		if (ex->major != ~0 && ex->major != refex->major)
			continue;
		if (ex->minor != ~0 && ex->minor != refex->minor)
			continue;
found:
		mismatched_bits = refex->access & (~ex->access) & ~ACC_MOUNT;
		allowed_mount = !(mismatched_bits & ~ACC_WRITE) &&
				(ex->access & ACC_MOUNT) &&
				(refex->access & ACC_MOUNT);

		if (mismatched_bits && !allowed_mount)
			continue;
		match = true;
		break;
	}

	/*
	 * In two cases we'll consider this new exception valid:
	 * - the dev cgroup has its default policy to allow + exception list:
	 *   the new exception should *not* match any of the exceptions
	 *   (behavior == DEVCG_DEFAULT_ALLOW, !match)
	 * - the dev cgroup has its default policy to deny + exception list:
	 *   the new exception *should* match the exceptions
	 *   (behavior == DEVCG_DEFAULT_DENY, match)
	 */
	if ((dev_cgroup->behavior == DEVCG_DEFAULT_DENY) == match)
		return 1;
	return 0;
}

/*
 * parent_has_perm:
 * when adding a new allow rule to a device exception list, the rule
 * must be allowed in the parent device
 */
static int parent_has_perm(struct dev_cgroup *childcg,
				  struct dev_exception_item *ex)
{
	struct cgroup *pcg = childcg->css.cgroup->parent;
	struct dev_cgroup *parent;

	if (!pcg)
		return 1;
	parent = cgroup_to_devcgroup(pcg);
	return may_access(parent, ex);
}

/**
 * may_allow_all - checks if it's possible to change the behavior to
 *		   allow based on parent's rules.
 * @parent: device cgroup's parent
 * returns: != 0 in case it's allowed, 0 otherwise
 */
static inline int may_allow_all(struct dev_cgroup *parent)
{
	if (!parent)
		return 1;
	return parent->behavior == DEVCG_DEFAULT_ALLOW;
}

/*
 * Modify the exception list using allow/deny rules.
 * CAP_SYS_ADMIN is needed for this.  It's at least separate from CAP_MKNOD
 * so we can give a container CAP_MKNOD to let it create devices but not
 * modify the exception list.
 * It seems likely we'll want to add a CAP_CONTAINER capability to allow
 * us to also grant CAP_SYS_ADMIN to containers without giving away the
 * device exception list controls, but for now we'll stick with CAP_SYS_ADMIN
 *
 * Taking rules away is always allowed (given CAP_SYS_ADMIN).  Granting
 * new access is only allowed if you're in the top-level cgroup, or your
 * parent cgroup has the access you're asking for.
 */
static int devcgroup_update_access(struct dev_cgroup *devcgroup,
				   int filetype, const char *buffer)
{
	const char *b;
	char temp[12];		/* 11 + 1 characters needed for a u32 */
	int count, rc;
	struct dev_exception_item ex;
	struct cgroup *p = devcgroup->css.cgroup;
	struct dev_cgroup *parent = NULL;

	if (!capable(CAP_SYS_ADMIN) && !capable(CAP_VE_SYS_ADMIN))
		return -EPERM;

	if (p->parent)
		parent = cgroup_to_devcgroup(p->parent);

	memset(&ex, 0, sizeof(ex));
	b = buffer;

	switch (*b) {
	case 'a':
		switch (filetype) {
		case DEVCG_ALLOW:
			if (!may_allow_all(parent)) {
				if (ve_is_super(get_exec_env()))
					return -EPERM;
				else
					/* Fooling docker in CT - silently exit */
					return 0;
			}
			dev_exception_clean(devcgroup);
			devcgroup->behavior = DEVCG_DEFAULT_ALLOW;
			if (!parent)
				break;

			rc = dev_exceptions_copy(&devcgroup->exceptions,
						 &parent->exceptions);
			if (rc)
				return rc;
			break;
		case DEVCG_DENY:
			dev_exception_clean(devcgroup);
			devcgroup->behavior = DEVCG_DEFAULT_DENY;
			break;
		default:
			return -EINVAL;
		}
		return 0;
	case 'b':
		ex.type = DEV_BLOCK;
		break;
	case 'c':
		ex.type = DEV_CHAR;
		break;
	default:
		return -EINVAL;
	}
	b++;
	if (!isspace(*b))
		return -EINVAL;
	b++;
	if (*b == '*') {
		ex.major = ~0;
		b++;
	} else if (isdigit(*b)) {
		memset(temp, 0, sizeof(temp));
		for (count = 0; count < sizeof(temp) - 1; count++) {
			temp[count] = *b;
			b++;
			if (!isdigit(*b))
				break;
		}
		rc = kstrtou32(temp, 10, &ex.major);
		if (rc)
			return -EINVAL;
	} else {
		return -EINVAL;
	}
	if (*b != ':')
		return -EINVAL;
	b++;

	/* read minor */
	if (*b == '*') {
		ex.minor = ~0;
		b++;
	} else if (isdigit(*b)) {
		memset(temp, 0, sizeof(temp));
		for (count = 0; count < sizeof(temp) - 1; count++) {
			temp[count] = *b;
			b++;
			if (!isdigit(*b))
				break;
		}
		rc = kstrtou32(temp, 10, &ex.minor);
		if (rc)
			return -EINVAL;
	} else {
		return -EINVAL;
	}
	if (!isspace(*b))
		return -EINVAL;
	for (b++, count = 0; count < 3; count++, b++) {
		switch (*b) {
		case 'r':
			ex.access |= ACC_READ;
			break;
		case 'w':
			ex.access |= ACC_WRITE;
			break;
		case 'm':
			ex.access |= ACC_MKNOD;
			break;
		case '\n':
		case '\0':
			count = 3;
			break;
		default:
			return -EINVAL;
		}
	}

	switch (filetype) {
	case DEVCG_ALLOW:
		if (!parent_has_perm(devcgroup, &ex))
			return -EPERM;
		/*
		 * If the default policy is to allow by default, try to remove
		 * an matching exception instead. And be silent about it: we
		 * don't want to break compatibility
		 */
		if (devcgroup->behavior == DEVCG_DEFAULT_ALLOW) {
			dev_exception_rm(devcgroup, &ex);
			return 0;
		}
		return dev_exception_add(devcgroup, &ex);
	case DEVCG_DENY:
		/*
		 * If the default policy is to deny by default, try to remove
		 * an matching exception instead. And be silent about it: we
		 * don't want to break compatibility
		 */
		if (devcgroup->behavior == DEVCG_DEFAULT_DENY) {
			dev_exception_rm(devcgroup, &ex);
			return 0;
		}
		return dev_exception_add(devcgroup, &ex);
	default:
		return -EINVAL;
	}
	return 0;
}

static int devcgroup_access_write(struct cgroup *cgrp, struct cftype *cft,
				  const char *buffer)
{
	int retval;

	mutex_lock(&devcgroup_mutex);
	retval = devcgroup_update_access(cgroup_to_devcgroup(cgrp),
					 cft->private, buffer);
	mutex_unlock(&devcgroup_mutex);
	return retval;
}

static struct cftype dev_cgroup_files[] = {
	{
		.name = "allow",
		.write_string  = devcgroup_access_write,
		.private = DEVCG_ALLOW,
	},
	{
		.name = "deny",
		.write_string = devcgroup_access_write,
		.private = DEVCG_DENY,
	},
	{
		.name = "list",
		.read_seq_string = devcgroup_seq_read,
		.private = DEVCG_LIST,
	},
};

static int devcgroup_populate(struct cgroup_subsys *ss,
				struct cgroup *cgroup)
{
	return cgroup_add_files(cgroup, ss, dev_cgroup_files,
					ARRAY_SIZE(dev_cgroup_files));
}

struct cgroup_subsys devices_subsys = {
	.name = "devices",
	.can_attach = devcgroup_can_attach,
	.create = devcgroup_create,
	.destroy  = devcgroup_destroy,
	.populate = devcgroup_populate,
	.subsys_id = devices_subsys_id,
};

/**
 * __devcgroup_check_permission - checks if an inode operation is permitted
 * @dev_cgroup: the dev cgroup to be tested against
 * @type: device type
 * @major: device major number
 * @minor: device minor number
 * @access: combination of ACC_WRITE, ACC_READ and ACC_MKNOD
 *
 * returns 0 on success, -EPERM case the operation is not permitted
 */
static int __devcgroup_check_permission(short type, u32 major, u32 minor,
				        short access)
{
	struct dev_cgroup *dev_cgroup;
	struct dev_exception_item ex;
	int rc;

	memset(&ex, 0, sizeof(ex));
	ex.type = type;
	ex.major = major;
	ex.minor = minor;
	ex.access = access;

	rcu_read_lock();
	dev_cgroup = task_devcgroup(current);
	rc = may_access(dev_cgroup, &ex);
	rcu_read_unlock();

	if (!rc)
		return -EPERM;

	return 0;
}

int __devcgroup_inode_permission(struct inode *inode, int mask)
{
	short type, access = 0;

	if (S_ISBLK(inode->i_mode))
		type = DEV_BLOCK;
	if (S_ISCHR(inode->i_mode))
		type = DEV_CHAR;
	if (mask & MAY_WRITE)
		access |= ACC_WRITE;
	if (mask & MAY_READ)
		access |= ACC_READ;
	if (mask & MAY_MOUNT)
		access |= ACC_MOUNT;

	return __devcgroup_check_permission(type, imajor(inode), iminor(inode),
			access);
}

/* Returns 1 if exists, 0 otherwise */
int devcgroup_device_exist(struct cgroup *cgrp, unsigned type, dev_t device)
{
	struct dev_cgroup *dev_cgroup = cgroup_to_devcgroup(cgrp);
	struct dev_exception_item *ex;

	/*
	 * Let's pretend that the device exists if minor (or major) was not set
	 * in the rule. This will prevent the caller from mangling devtmpfs and
	 * sysfs.
	 */
	if ((type & VE_USE_MASK) != VE_USE_MINOR)
		return 1;

	rcu_read_lock();

	list_for_each_entry_rcu(ex, &dev_cgroup->exceptions, list) {
		if (ex->type & DEV_ALL)
			continue;
		if ((ex->type & DEV_BLOCK) && (type == S_IFCHR))
			continue;
		if ((ex->type & DEV_CHAR) && (type == S_IFBLK))
			continue;
		if (ex->major != MAJOR(device))
			continue;
		if (ex->minor != MINOR(device))
			continue;

		rcu_read_unlock();
		return 1;
	}

	rcu_read_unlock();
	return 0;
}

int devcgroup_device_visible(int type, int major, int start_minor, int nr_minors)
{
	struct dev_cgroup *dev_cgroup;
	struct dev_exception_item *ex;

	rcu_read_lock();
	dev_cgroup = task_devcgroup(current);

	if (dev_cgroup->behavior == DEVCG_DEFAULT_ALLOW) {
                rcu_read_unlock();
                return 1;
	}

	list_for_each_entry_rcu(ex, &dev_cgroup->exceptions, list) {
		if (ex->type & DEV_ALL)
			goto found;
		if ((ex->type & DEV_BLOCK) && (type == S_IFCHR))
			continue;
		if ((ex->type & DEV_CHAR) && (type == S_IFBLK))
			continue;
		if (ex->major != ~0 && ex->major != major)
			continue;
		if (ex->minor != ~0 && !(start_minor <= ex->minor &&
					ex->minor < start_minor + nr_minors))
			continue;
found:
		if (!(ex->access & (ACC_READ | ACC_WRITE | ACC_QUOTA)))
			continue;
		rcu_read_unlock();
		return 1;
	}

	rcu_read_unlock();
	return 0;
}

int devcgroup_inode_mknod(int mode, dev_t dev)
{
	short type;

	if (!S_ISBLK(mode) && !S_ISCHR(mode))
		return 0;

	if (S_ISBLK(mode))
		type = DEV_BLOCK;
	else
		type = DEV_CHAR;

	return __devcgroup_check_permission(type, MAJOR(dev), MINOR(dev),
			ACC_MKNOD);

}

#ifdef CONFIG_VE

static struct dev_exception_item ve_devcgroup_ex_items[] = {
	{ ~0,				~0,	DEV_ALL,  ACC_MKNOD				},
	{ UNIX98_PTY_MASTER_MAJOR,	~0,	DEV_CHAR, ACC_MKNOD | ACC_READ | ACC_WRITE	},
	{ UNIX98_PTY_SLAVE_MAJOR,	~0,	DEV_CHAR, ACC_MKNOD | ACC_READ | ACC_WRITE	},
	{ PTY_MASTER_MAJOR,		~0,	DEV_CHAR, ACC_MKNOD | ACC_READ | ACC_WRITE	},
	{ PTY_SLAVE_MAJOR,		~0,	DEV_CHAR, ACC_MKNOD | ACC_READ | ACC_WRITE	},
	{ MEM_MAJOR,			3,	DEV_CHAR, ACC_MKNOD | ACC_READ | ACC_WRITE	}, /* null */
	{ MEM_MAJOR,			5,	DEV_CHAR, ACC_MKNOD | ACC_READ | ACC_WRITE	}, /* zero */
	{ MEM_MAJOR,			7,	DEV_CHAR, ACC_MKNOD | ACC_READ | ACC_WRITE	}, /* full */
	{ TTYAUX_MAJOR,			0,	DEV_CHAR, ACC_MKNOD | ACC_READ | ACC_WRITE	}, /* tty */
	{ TTYAUX_MAJOR,			1,	DEV_CHAR, ACC_MKNOD | ACC_READ | ACC_WRITE	}, /* console */
	{ TTYAUX_MAJOR,			2,	DEV_CHAR, ACC_MKNOD | ACC_READ | ACC_WRITE	}, /* ptmx */
	{ MEM_MAJOR,			8,	DEV_CHAR, ACC_MKNOD | ACC_READ | ACC_WRITE	}, /* random */
	{ MEM_MAJOR,			9,	DEV_CHAR, ACC_MKNOD | ACC_READ | ACC_WRITE	}, /* urandom */
	{ MEM_MAJOR,			11,	DEV_CHAR, ACC_MKNOD | ACC_WRITE			}, /* kmsg */
};

static LIST_HEAD(ve_devcgroup_ex_list);

int ve_prep_devcgroup(struct ve_struct *ve)
{
	struct dev_cgroup *dev_cgroup = cgroup_to_devcgroup(ve->ve_cgroup);
	size_t i;
	int ret;

	if (unlikely(list_empty(&ve_devcgroup_ex_list))) {
		for (i = 0; i < ARRAY_SIZE(ve_devcgroup_ex_items); i++) {
			ve_devcgroup_ex_items[i].access |= ACC_HIDDEN;
			list_add(&ve_devcgroup_ex_items[i].list,
				 &ve_devcgroup_ex_list);
		}
	}

	/*
	 * When allowing device cgroup inside a container
	 * we use _very_ strict rules over them:
	 *
	 *  - DEVCG_DEFAULT_DENY is used for children behaviour
	 *  - we ship predefined "exception" items which are known
	 *    to be virtualized
	 */
	mutex_lock(&devcgroup_mutex);

	dev_cgroup->behavior = DEVCG_DEFAULT_DENY;

	dev_exception_clean(dev_cgroup);
	ret = dev_exceptions_copy(&dev_cgroup->exceptions,
				  &ve_devcgroup_ex_list);

	mutex_unlock(&devcgroup_mutex);
	return ret;
}
EXPORT_SYMBOL(ve_prep_devcgroup);

int get_device_perms_ve(int dev_type, dev_t dev, int access_mode)
{
	short access = 0;
	short type;

	if (dev_type == S_IFBLK)
		type = DEV_BLOCK;
	else
		type = DEV_CHAR;

	access |= (access_mode & FMODE_READ ? ACC_READ : 0);
	access |= (access_mode & FMODE_WRITE ? ACC_WRITE : 0);
	access |= (access_mode & FMODE_QUOTACTL ? ACC_QUOTA : 0);

	return __devcgroup_check_permission(type, MAJOR(dev), MINOR(dev),
					    access);
}
EXPORT_SYMBOL(get_device_perms_ve);

int set_device_perms_ve(struct ve_struct *ve,
		unsigned type, dev_t dev, unsigned mask)
{
	int err = -EINVAL;
	struct dev_exception_item new;

	if ((type & S_IFMT) == S_IFBLK)
		new.type = DEV_BLOCK;
	else if ((type & S_IFMT) == S_IFCHR)
		new.type = DEV_CHAR;
	else
		return -EINVAL;

	new.access = convert_bits(mask) | (mask ? ACC_MKNOD : 0);
	new.major = new.minor = ~0;

	switch (type & VE_USE_MASK) {
	default:
		new.minor = MINOR(dev);
	case VE_USE_MAJOR:
		new.major = MAJOR(dev);
	case 0:
		;
	}

	mutex_lock(&devcgroup_mutex);
	err = dev_exception_change(cgroup_to_devcgroup(ve->ve_cgroup), &new);
	mutex_unlock(&devcgroup_mutex);
	return err;
}
EXPORT_SYMBOL(set_device_perms_ve);

#ifdef CONFIG_PROC_FS
int devperms_seq_show(struct seq_file *m, void *v)
{
	struct ve_struct *ve = list_entry(v, struct ve_struct, ve_list);

	if (m->private == (void *)0) {
		seq_printf(m, "Version: 2.7\n");
		m->private = (void *)-1;
	}

	if (ve_is_super(ve)) {
		seq_printf(m, "%10u b 016 *:*\n%10u c 006 *:*\n", 0, 0);
		return 0;
	}

	m->private = (void *)(unsigned long)ve->veid;
	return devcgroup_seq_read(ve->ve_cgroup, NULL, m);
}
EXPORT_SYMBOL(devperms_seq_show);
#endif
#endif
