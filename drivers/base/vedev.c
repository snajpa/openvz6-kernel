#include <linux/sched.h>
#include <linux/kobject.h>
#include <linux/ve.h>
#include <linux/ve_proto.h>
#include <linux/genhd.h>
#include <linux/vzcalluser.h>

#include "base.h"

struct ve_device_link {
	char *name;
	struct kobject *kobj;
	struct list_head list;
};

struct ve_device {
	struct ve_struct *ve;
	struct device *dev;
	struct list_head kobj_list;
	struct list_head ve_list;
	struct kobject *kobj;
	struct list_head links;
	struct kobject* net_link;
	unsigned int perms_set : 1,
		     devtmpfs_node_created : 1;
};

static DECLARE_MUTEX(vedev_lock);

extern struct sysfs_dirent *sysfs_get_active(struct sysfs_dirent *sd);
extern void sysfs_put_active(struct sysfs_dirent *sd);

static void __ve_remove_netdev(struct ve_device *ve_dev);

static struct kobject *ve_kobj_path_lookup(char *path, bool create)
{
	char *e, *p = path;
	struct sysfs_dirent *sd, *parent_sd = get_exec_env()->_sysfs_root;
	struct kobject *k, *pk = NULL;

	if (*p == '/')
		p++;

	while (1) {
		e = strchr(p, '/');
		if (e)
			*e = '\0';
		sd = sysfs_get_dirent(parent_sd, p);
		if (sd == NULL) {
new:			if (!create) {
				kobject_put(pk);
				return ERR_PTR(-ENOENT);
			}
			k = kobject_create_and_add(p, pk);
			kobject_put(pk);
			if (!k)
				return ERR_PTR(-ENOMEM);
		} else {
			unsigned int f;
			bool my_parent_is_symlink = false;

follow_symlink:		f = sd->s_flags;
			if (!(f & SYSFS_DIR) && !(f & SYSFS_KOBJ_LINK)) {
				sysfs_put(sd);

				return (f & SYSFS_DIR_LINK) && create ?
					ERR_PTR(-EEXIST) : ERR_PTR(-EINVAL);
			}

			/*a directory may be deleted*/
			if (!sysfs_get_active(sd)) {
				sysfs_put(sd);
				if (my_parent_is_symlink) {
					kobject_put(pk);
					return create ? ERR_PTR(-EINVAL) :
						        ERR_PTR(-ENOENT);
				}
				goto new;
			}

			if (f & SYSFS_KOBJ_LINK) {
				struct sysfs_dirent *old_sd = sd;

				sd = sd->s_symlink.target_sd;
				sysfs_get(sd);

				sysfs_put_active(old_sd);
				sysfs_put(old_sd);
				my_parent_is_symlink = true;
				goto follow_symlink;
			}

			k = sd->s_dir.kobj;

			kobject_get(k);
			kobject_put(pk);
			sysfs_put_active(sd);
			sysfs_put(sd);
		}
		pk = k;
		parent_sd = k->sd;
		if (!e)
			break;

		p = e + 1;
	}

	return k;
}

static inline struct kobject *vedev_kobj_path_create(char *path, struct ve_device *ve_dev)
{
	struct kobject *obj;
	struct ve_struct *old_ve = set_exec_env(ve_dev->ve);
	obj = ve_kobj_path_lookup(path, true);
	set_exec_env(old_ve);
	return obj;
}

static int ve_device_add_symlink(struct kobject *kobj, const char *name, \
			struct ve_device *ve_dev)
{
	char *path;
	int ret = -ENOMEM;
	struct kobject *dev_kobj, *ve_kobj = NULL;
	struct ve_device_link *ve_link;

	path = kobject_get_path(kobj, GFP_KERNEL);
	if (!path)
		goto out;

	ve_kobj = vedev_kobj_path_create(path, ve_dev);
	kfree(path);
	if (IS_ERR(ve_kobj)) {
		ret = PTR_ERR(ve_kobj);
		ve_kobj = NULL;
		goto out;
	}

	ve_link = kmalloc(sizeof(struct ve_device_link), GFP_KERNEL);
	if (!ve_link)
		goto out;

	ve_link->name = kstrdup(name, GFP_KERNEL);
	if (!ve_link->name)
		goto out_free;

	if (ve_dev->kobj)
		dev_kobj = ve_dev->kobj;
	else
		dev_kobj = &ve_dev->dev->kobj;

	ret = sysfs_create_link(ve_kobj, dev_kobj, ve_link->name);
	if (ret)
		goto out_free_name;

	ve_link->kobj = ve_kobj;
	list_add(&ve_link->list, &ve_dev->links);

	return 0;

out_free_name:
	kfree(ve_link->name);
out_free:
	kfree(ve_link);
out:
	kobject_put(ve_kobj);
	return ret;
}

static void dirlink_kobj_release(struct kobject *kobj)
{
	kfree(kobj);
}

static struct kobj_type dirlink_kobj_ktype = {
	.release	= dirlink_kobj_release,
};

static struct kobject *kobject_link_create(struct kobject *parent, struct kobject *target)
{
	struct sysfs_dirent *sd;
	struct kobject *kobj;

	kobj = kzalloc(sizeof(*kobj), GFP_KERNEL);
	if (!kobj)
		return ERR_PTR(-ENOMEM);

	kobject_init(kobj, &dirlink_kobj_ktype);

	kobject_set_name(kobj, "%s", kobject_name(target));
	sd = sysfs_create_dirlink(parent->sd, target);
	if (IS_ERR(sd)) {
		kobject_put(kobj);
		kobj = (struct kobject *) sd;
		goto out;
	}
	kobj->sd = sd;
	kobj->parent = kobject_get(parent);
out:
	return kobj;
}

static void kobject_link_del(struct kobject *kobj, struct ve_struct *ve)
{
	struct ve_struct *old_ve;
	if (!kobj)
		return;
	if (kobj->sd) {
		old_ve = set_exec_env(ve);
		sysfs_remove_dirlink(kobj->sd);
		set_exec_env(old_ve);
	}
	kobj->sd = NULL;
	kobject_put(kobj->parent);
	kobject_put(kobj);
}

static int ve_device_link_kobj(struct ve_device *ve_dev)
{
	char *path, *p;
	int ret = 0;
	struct sysfs_dirent *sd;
	struct kobject *k = NULL, *pk = NULL;

	path = kobject_get_path(&ve_dev->dev->kobj, GFP_KERNEL);
	if (!path) {
		return -ENOMEM;
	}
	p = strrchr(path, '/');
	if (p && p != path) {
		*p = '\0';
		p++;
		pk = vedev_kobj_path_create(path, ve_dev);
		if (IS_ERR(pk)) {
			ret = PTR_ERR(pk);
			pk = NULL;
			goto out;
		}
	} else {
		ret = -EINVAL;
		goto out;
	}

	sd = sysfs_get_dirent(pk->sd, p);
	if (sd != NULL) {
		sysfs_put(sd);
		ret = -EEXIST;
		goto out;
	}

	k = kobject_link_create(pk, &ve_dev->dev->kobj);
	if (IS_ERR(k)) {
		ret = PTR_ERR(k);
		goto out;
	}
	ve_dev->kobj = k;

out:
	kobject_put(pk);
	kfree(path);
	return ret;
}

static int ve_device_link_bus(struct ve_device *ve_dev)
{
	struct kobject *devs_kobj = NULL;
	int ret = 0;

	if (ve_dev->dev->bus) {
		devs_kobj = &ve_dev->dev->bus->p->devices_kset->kobj;
		ret = ve_device_add_symlink(devs_kobj, dev_name(ve_dev->dev), ve_dev);
	}

	return ret;
}

static int ve_device_link_class(struct ve_device *ve_dev)
{
	struct kobject *devs_kobj = NULL;
	struct device *dev = ve_dev->dev;
	int ret = 0;

	if (!dev->class)
		return 0;

	if ((dev->kobj.parent != &dev->class->p->class_subsys.kobj)) {
		devs_kobj = &dev->class->p->class_subsys.kobj;
		ret = ve_device_add_symlink(devs_kobj, dev_name(dev), ve_dev);
	}

	return ret;
}

static int ve_device_link_dev_block(struct ve_device *ve_dev)
{
	struct device *dev = ve_dev->dev;
	char dev_nums[20];

	snprintf(dev_nums, sizeof(dev_nums), "%d:%d", MAJOR(dev->devt),
			MINOR(dev->devt));
	return ve_device_add_symlink(ve_dev->ve->dev_block_kobj, dev_nums,
					ve_dev);
}

static void ve_device_del_link(struct ve_device *ve_dev)
{
	struct ve_device_link *l, *t;
	list_for_each_entry_safe(l, t, &ve_dev->links, list) {
		sysfs_remove_link(l->kobj, l->name);
		kobject_put(l->kobj);
		kfree(l->name);
		kfree(l);
	}
	kobject_link_del(ve_dev->kobj, ve_dev->ve);
}

static int ve_device_create_link(struct ve_device *ve_dev)
{
	int ret;
	ret = ve_device_link_kobj(ve_dev);
	if (ret == -EEXIST)
		goto out;
	if (ret)
		goto err;
	ret = ve_device_link_bus(ve_dev);
	if (ret)
		goto err;
out:
	return 0;
err:
	ve_device_del_link(ve_dev);
	return ret;
}

static inline struct ve_device *__ve_device_find(struct list_head *head,
						struct ve_struct *ve)
{
	struct ve_device *ve_dev;

	list_for_each_entry(ve_dev, head, kobj_list)
		if (ve_dev->ve == ve)
			return ve_dev;

	return NULL;
}

static struct ve_device *__ve_device_subscribe(struct device *dev, struct ve_struct *ve)
{
	struct ve_device *ve_dev;

	ve_dev = kzalloc(sizeof(struct ve_device), GFP_KERNEL);

	if (!ve_dev)
		return ERR_PTR(-ENOMEM);

	ve_dev->ve = ve;
	ve_dev->dev = dev;
	get_device(dev);
	INIT_LIST_HEAD(&ve_dev->links);

	list_add(&ve_dev->kobj_list, &dev->kobj.env_head);
	list_add(&ve_dev->ve_list, &ve->devices);
	return ve_dev;
}

static struct ve_device *ve_device_subscribe(struct device *dev, struct ve_struct *ve)
{
	struct ve_device *ve_dev;

	down(&vedev_lock);

	if (__ve_device_find(&dev->kobj.env_head, ve)) {
		ve_dev = ERR_PTR(-EEXIST);
		goto out;
	}

	ve_dev = __ve_device_subscribe(dev, ve);
out:
	up(&vedev_lock);
	return ve_dev;
}

static int ve_devtmpfs_delete_node(struct ve_struct *ve, struct device *dev)
{
	struct ve_struct *old_ve = set_exec_env(ve);
	int err = devtmpfs_delete_node(dev);
	set_exec_env(old_ve);
	return err;
}

static void ve_device_del_one(struct ve_device *ve_dev, int event)
{
	struct ve_struct *old_ve;
	unsigned type;

	list_del(&ve_dev->ve_list);
	list_del(&ve_dev->kobj_list);

	if (event) {
		old_ve = set_exec_env(ve_dev->ve);
		kobject_uevent_env_one(&ve_dev->dev->kobj, KOBJ_REMOVE, NULL);
		set_exec_env(old_ve);
	}

	ve_device_del_link(ve_dev);

	if (ve_dev->perms_set) {
		type = ve_dev->dev->class == &block_class ? S_IFBLK : S_IFCHR;
		set_device_perms_ve(ve_dev->ve, type, ve_dev->dev->devt, 00);
	}

	if (ve_dev->devtmpfs_node_created)
		ve_devtmpfs_delete_node(ve_dev->ve, ve_dev->dev);

	put_device(ve_dev->dev);
	kfree(ve_dev);
}

void ve_device_del(struct device *dev, struct ve_struct *ve)
{
	struct ve_device *ve_dev, *tmp;
	down(&vedev_lock);
	list_for_each_entry_safe(ve_dev, tmp, &dev->kobj.env_head, kobj_list) {
		if (ve && ve_dev->ve != ve)
			continue;

		ve_device_del_one(ve_dev, 1);
	}
	up(&vedev_lock);
}

/*
 * Check that physical device is a NIC
 */
static inline int is_phydev_net(struct device *dev)
{
	struct sysfs_dirent *sd;

	sd = sysfs_get_dirent(dev->kobj.sd, "net");
	if (!sd)
		return 0;

	sysfs_put(sd);
	return 1;
}

static int ve_devtmpfs_create_node(struct ve_struct *ve, struct device *dev)
{
	struct ve_struct *old_ve = set_exec_env(ve);
	int err = devtmpfs_create_node(dev);
	set_exec_env(old_ve);
	return err;
}

static int ve_device_add(struct device *dev, struct ve_struct *ve,
			 unsigned mask)
{
	int ret = 0;
	struct ve_device *ve_dev;

	if (is_phydev_net(dev))
		return -EPERM;

	ve_dev = ve_device_subscribe(dev, ve);
	if (IS_ERR(ve_dev))
		return PTR_ERR(ve_dev);

	ret = ve_device_create_link(ve_dev);
	if (ret < 0)
		goto err;

	ret = ve_device_link_class(ve_dev);
	if (ret)
		goto err;

	/*
	 * Need some(see below) symlinks for block devices
	 * for lsblk to be able work in ve
	 */
	if (dev->class == &block_class) {

		/*
		 * There is a creation of "/sys/block" kobject for ve != ve0
		 * Note that for ve0 this kobject already created at init stage
		 * in function genhd_device_init()(/block/genhd.c)
		 */
		if ((ve->block_kobj == NULL) && !ve_is_super(ve)) {
			struct ve_struct *old_ve = set_exec_env(ve);

			/* ve_sysfs_block_kobj is ve->block_kobj here */
			ve_sysfs_block_kobj = kobject_create_and_add("block", NULL);
			set_exec_env(old_ve);

			if (ve->block_kobj == NULL) {
				ret = -ENOMEM;
				goto err;
			}
		}

		/*
		 * Make link /sys/block/devName ->
		 * ../devices/virtual/block/devName
		 */
		ret = ve_device_add_symlink(ve_dev->ve->block_kobj,
				dev_name(ve_dev->dev), ve_dev);
		if (ret)
			goto err;

		/*
		 * Make link /sys/dev/block/devMAJOR:devMINOR ->
		 * ../devices/virtual/block/devName
		 */
		ret = ve_device_link_dev_block(ve_dev);
		if (ret)
			goto err;
	}

	if (MAJOR(dev->devt)) {
		unsigned type = dev->class == &block_class ? S_IFBLK : S_IFCHR;
		type |= VE_USE_MINOR; /* see switch in set_device_perms_ve() */

		ret = ve_devtmpfs_create_node(ve, dev);
		if (ret < 0 && ret != -EEXIST)
			goto err;
		ve_dev->devtmpfs_node_created = 1;

		ret = set_device_perms_ve(ve, type, dev->devt, mask);
		if (ret < 0)
			goto err;
		ve_dev->perms_set = 1;
	}

	return ret;
err:
	down(&vedev_lock);
	ve_device_del_one(ve_dev, 0);
	up(&vedev_lock);
	return ret;
}

static void ve_device_uevent_add(struct device *dev, struct ve_struct *ve)
{
	struct ve_struct *old_ve = set_exec_env(ve);
	kobject_uevent_env_one(&dev->kobj, KOBJ_ADD, NULL);
	set_exec_env(old_ve);
}

ssize_t ve_device_handler(struct device *dev, struct device_attribute *attr,
			  const char *buf, size_t count)
{
	int ret;
	struct ve_struct *ve;
	envid_t veid;
	char cmd;

	if (!capable_setveid())
		return -EPERM;

	if (buf[count] != '\0')
		return -EINVAL;

	if (!strchr("+-", *buf))
		return -EINVAL;
	cmd = *buf;
	buf++;

	if (sscanf(buf, "%u", &veid) != 1)
		return -EINVAL;

	ve = get_ve_by_id(veid);

	ret = -ENOENT;
	if (!ve || !ve->is_running)
		goto out;

	if (cmd == '+') {
		ret = ve_device_add(dev, ve, 06);
		if (!ret)
			ve_device_uevent_add(dev, ve);
	} else {
		ve_device_del(dev, ve);
		ret = 0;
	}
out:
	put_ve(ve);
	if (unlikely(ret))
		return ret;

	return count;
}

static struct kobject *devt2kobj(dev_t devt, unsigned type)
{
	const int size = 32;
	char symlink_path[size];
	char *type_str;

	if ((type & S_IFMT) == S_IFBLK)
		type_str = "block";
	else if ((type & S_IFMT) == S_IFCHR)
		type_str = "char";
	else
		return ERR_PTR(-EINVAL);

	snprintf(symlink_path, size, "dev/%s/%d:%d",
		 type_str, MAJOR(devt), MINOR(devt));
	symlink_path[size-1] = 0;

	return ve_kobj_path_lookup(symlink_path, 0);
}

extern int devcgroup_device_exist(struct cgroup *cgrp, unsigned type,
				  dev_t device);

int ve_devt_add(struct ve_struct *ve, unsigned type, dev_t devt, unsigned mask)
{
	struct kobject *dev_kobj;
	struct device *dev;
	bool del = !(mask & (S_IRWXO | S_IXGRP));
	int err = 0;

	dev_kobj = devt2kobj(devt, type);
	if (IS_ERR(dev_kobj)) {
		err = PTR_ERR(dev_kobj);

		/* Do nothing if a special device (like vzlinkdev) was not
		 * registered as /sys/dev/{block|char}/MAJOR:MINOR on host */
		if (err == -ENOENT)
			err = set_device_perms_ve(ve, type, devt, mask);

		return err;
	}

	if (devcgroup_device_exist(ve->ve_cgroup, type, devt)) {
		err = set_device_perms_ve(ve, type, devt, mask);
		if (err || !del)
			goto err;
	}

	dev = container_of(dev_kobj, struct device, kobj);
	if (dev->devt != devt ||
	    (dev->class == &block_class ? S_IFBLK : S_IFCHR) !=
	    (type & S_IFMT)) {
		printk(KERN_ERR "/sys/dev/%s/%d:%d points to %d:%d block=%d\n",
		       (type & S_IFMT) == S_IFBLK ? "block" : "char",
		       MAJOR(devt), MINOR(devt),
		       MAJOR(dev->devt), MINOR(dev->devt),
		       dev->class == &block_class);
		err = -EINVAL;
		goto err;
	}

	if (del)
		ve_device_del(dev, ve);
	else
		err = ve_device_add(dev, ve, mask);
err:
	kobject_put(dev_kobj);
	return err;
}
EXPORT_SYMBOL(ve_devt_add);

void fini_ve_devices(struct ve_struct *ve)
{
	struct ve_device *ve_dev, *tmp;
	down(&vedev_lock);
	list_for_each_entry_safe(ve_dev, tmp, &ve->devices, ve_list) {
		/* network devices are removed in netdev_fixup_sysfs() */
		if (!ve_dev->net_link)
			ve_device_del_one(ve_dev, 0);
	}
	up(&vedev_lock);
}
EXPORT_SYMBOL(fini_ve_devices);

int ve_kobject_uevent_env(struct kobject *kobj,
			enum kobject_action action, char *envp_ext[])
{
	int err, ret = 0;
	struct ve_device *ve_dev;
	struct ve_struct *ve_old;

	down(&vedev_lock);
	list_for_each_entry(ve_dev, &kobj->env_head, kobj_list) {
		ve_old = set_exec_env(ve_dev->ve);
		err = kobject_uevent_env_one(kobj, action, envp_ext);
		if (err)
			ret = err;
		set_exec_env(ve_old);
	}
	up(&vedev_lock);

	return ret;
}

static int ve_netdev_create(struct kobject *net_obj, struct ve_struct *ve)
{
	struct ve_device *ve_dev;
	struct ve_struct *old_ve;
	struct kobject *phy_obj = net_obj->parent;
	struct device *phy_dev;
	char *path, *p;
	int err;
	struct kobject *k = NULL, *pk = NULL;

	/*
	 * ve_netdev_create should not be called with network
	 * interface not attached to physical device
	 */
	phy_dev = container_of(phy_obj, struct device, kobj);

	ve_dev = __ve_device_subscribe(phy_dev, ve);

	if (IS_ERR(ve_dev))
		return PTR_ERR(ve_dev);

	path = kobject_get_path(net_obj, GFP_KERNEL);

	if (!path) {
		err = -ENOMEM;
		goto error;
	}

	p = strrchr(path, '/');

	if (!p || (p == path)) {
		err = -EINVAL;
		kfree(path);
		goto error;
	}

	*p = '\0';
	old_ve = set_exec_env(ve);
	pk = ve_kobj_path_lookup(path, true);
	set_exec_env(old_ve);

	kfree(path);

	if (IS_ERR(pk)) {
		err = PTR_ERR(pk);
		goto error;
	}

	k = kobject_link_create(pk, net_obj);
	kobject_put(pk);

	if (IS_ERR(k)) {
		err = PTR_ERR(k);
		goto error;
	}

	ve_dev->net_link = k;
	return 0;

error:
	ve_device_del_one(ve_dev, 0);
	return err;
}

/*
 * Search for "device" symlink in object directory.
 * If it exists - return physical device, if not
 * this device is virtual one
 */
static struct kobject *netdev_get_phy(struct device *dev)
{
	struct sysfs_dirent *sd, *link;
	struct kobject *target = NULL;

	/* netdev_register_kobject doesn't call device_add for non-ve namespaces */
	if (!dev->parent)
		return NULL;

	sd = sysfs_get_dirent(dev->kobj.sd, "device");
	if (!sd)
		return NULL;

	if (unlikely(!(sd->s_flags & SYSFS_KOBJ_LINK))) {
		printk(KERN_ERR "device dirent of dev %s is not symlink.\n",
			dev_name(dev));
		goto exit;
	}

	link = sd->s_symlink.target_sd;

	if (!(link->s_flags & (SYSFS_DIR | SYSFS_DIR_LINK))) {
		printk(KERN_ERR "device link of %s is not describe phy dev\n",
			dev_name(dev));
		goto exit;
	}

	target = link->s_dir.kobj;

exit:
	sysfs_put(sd);
	return target;
}

int ve_netdev_add(struct device *dev, struct ve_struct *ve)
{
	int err = -EINVAL;
	struct ve_device *ve_dev;
	struct kobject *phy_dev;

	phy_dev = netdev_get_phy(dev);
	if (!phy_dev)
		/* Assume no phy object - virtual device */
		return 0;

	down(&vedev_lock);
	ve_dev = __ve_device_find(&phy_dev->env_head, ve);

	if (!ve_dev)
		err = ve_netdev_create(dev->kobj.parent, ve);

	up(&vedev_lock);
	return err;
}

static void __ve_remove_netdev(struct ve_device *ve_dev)
{
	kobject_link_del(ve_dev->net_link, ve_dev->ve);

	list_del(&ve_dev->ve_list);
	list_del(&ve_dev->kobj_list);

	put_device(ve_dev->dev);
	kfree(ve_dev);
}

int ve_netdev_delete(struct device *dev, struct ve_struct *ve)
{
	int err = 0;
	struct ve_device *ve_dev;
	struct kobject *phy_dev;

	phy_dev = netdev_get_phy(dev);
	if (!phy_dev)
		/* Assume no phy object - virtual device */
		return 0;

	down(&vedev_lock);

	ve_dev = __ve_device_find(&phy_dev->env_head, ve);

	if (!ve_dev || !ve_dev->net_link) {
		printk(KERN_ERR "Can't delete virtual device %s in case "
			"it is not present in VE.\n", kobject_name(phy_dev));
		err = -EINVAL;
		goto out;
	}

	__ve_remove_netdev(ve_dev);

out:
	up(&vedev_lock);
	return err;
}
