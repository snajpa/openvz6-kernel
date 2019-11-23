/*
 *  veth.c
 *
 *  Copyright (C) 2006  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

/*
 * Virtual ethernet device used to change VE ownership on packets
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/in.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/nsproxy.h>
#include <linux/tcp.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/io.h>
#include <asm/unistd.h>

#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <net/ip.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/if_ether.h>	/* For the statistics structure. */
#include <linux/if_arp.h>	/* For ARPHRD_ETHER */
#include <linux/if_bridge.h>
#include <linux/ethtool.h>
#include <linux/ve_proto.h>
#include <linux/veth.h>
#include <linux/vzctl.h>
#include <linux/vzctl_veth.h>

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/vzcalluser.h>

#include <linux/cpt_image.h>
#include <linux/cpt_export.h>

static LIST_HEAD(veth_hwaddr_list);
static DEFINE_RWLOCK(ve_hwaddr_lock);
static DECLARE_MUTEX(hwaddr_sem);

static struct net_device * veth_dev_start(char *dev_addr, char *name);

static struct veth_struct *hwaddr_entry_lookup(char *name)
{
	struct veth_struct *entry;

	list_for_each_entry(entry, &veth_hwaddr_list, hwaddr_list) {
		BUG_ON(entry->pair == NULL);
		if (strncmp(name, entry->pair->name, IFNAMSIZ) == 0)
			return entry;
	}
	return NULL;
}

static int veth_entry_add(struct ve_struct *ve, char *dev_addr, char *name,
		char *dev_addr_ve, char *name_ve)
{
	struct net_device *dev_ve;
	struct net_device *dev_ve0;
	struct ve_struct *old_env;
	char dev_name[IFNAMSIZ];
	int err;

	down(&hwaddr_sem);

	if (name[0] == '\0')
		snprintf(dev_name, sizeof(dev_name), "vz%d.%%d", ve->veid);
	else {
		memcpy(dev_name, name, IFNAMSIZ - 1);
		dev_name[IFNAMSIZ - 1] = '\0';
	}
	dev_ve0 = veth_dev_start(dev_addr, dev_name);
	if (IS_ERR(dev_ve0)) {
		err = PTR_ERR(dev_ve0);
		goto err;
	}

	old_env = set_exec_env(ve);
	if (name_ve[0] == '\0')
		sprintf(dev_name, "eth%%d");
	else {
		memcpy(dev_name, name_ve, IFNAMSIZ - 1);
		dev_name[IFNAMSIZ - 1] = '\0';
	}
	dev_ve = veth_dev_start(dev_addr_ve, dev_name);
	if (IS_ERR(dev_ve)) {
		err = PTR_ERR(dev_ve);
		goto err_ve;
	}
	set_exec_env(old_env);
	veth_from_netdev(dev_ve)->pair = dev_ve0;
	veth_from_netdev(dev_ve)->me = dev_ve;
	veth_from_netdev(dev_ve0)->pair = dev_ve;
	veth_from_netdev(dev_ve0)->me = dev_ve0;

	write_lock(&ve_hwaddr_lock);
	list_add(&(veth_from_netdev(dev_ve)->hwaddr_list), &veth_hwaddr_list);
	write_unlock(&ve_hwaddr_lock);

	up(&hwaddr_sem);
	return 0;

err_ve:
	set_exec_env(old_env);
	unregister_netdev(dev_ve0);
err:
	up(&hwaddr_sem);
	return err;
}

static void veth_pair_del(struct ve_struct *env, struct veth_struct *entry,
			  struct list_head *head)
{
	struct net_device *dev;
	struct ve_struct *old_env;

	write_lock(&ve_hwaddr_lock);
	list_del(&entry->hwaddr_list);
	write_unlock(&ve_hwaddr_lock);

	dev = entry->pair;
	BUG_ON(entry->pair == NULL);

	veth_from_netdev(dev)->pair = NULL;
	entry->pair = NULL;
	rtnl_lock();
	old_env = set_exec_env(dev->owner_env);
	dev_close(dev);

	/*
	 * Now device from VE0 does not send or receive anything,
	 * i.e. dev->hard_start_xmit won't be called.
	 */
	set_exec_env(env);
	unregister_netdevice_queue(veth_to_netdev(entry), head);
	set_exec_env(dev->owner_env);
	unregister_netdevice_queue(dev, head);
	set_exec_env(old_env);
	rtnl_unlock();
}

static int veth_entry_del(struct ve_struct *ve, char *name)
{
	struct veth_struct *found;
	int err;

	err = -ENODEV;
	down(&hwaddr_sem);
	found = hwaddr_entry_lookup(name);
	if (found == NULL)
		goto out;
	if (veth_to_netdev(found)->owner_env != ve)
		goto out;

	err = 0;
	veth_pair_del(ve, found, NULL);

out:
	up(&hwaddr_sem);
	return err;
}

static int veth_allow_change_mac(envid_t veid, char *name, int allow)
{
	struct ve_struct *ve;
	struct veth_struct *found;
	int err;

	err = -ESRCH;
	ve = get_ve_by_id(veid);
	if (!ve)
		return err;

	down_read(&ve->op_sem);
	if (!ve->is_running)
		goto out_ve;
	err = -ENODEV;
	down(&hwaddr_sem);
	found = hwaddr_entry_lookup(name);
	if (found == NULL)
		goto out_sem;
	if (veth_to_netdev(found)->owner_env != ve)
		goto out_sem;

	err = 0;
	found->allow_mac_change = allow;

out_sem:
	up(&hwaddr_sem);
out_ve:
	up_read(&ve->op_sem);
	put_ve(ve);
	return err;
}

/*
 * Device functions
 */

static int veth_open(struct net_device *dev)
{
	return 0;
}

static int veth_close(struct net_device *master)
{
	return 0;
}

static void veth_destructor(struct net_device *dev)
{
	free_percpu(veth_from_netdev(dev)->real_stats);
	free_netdev(dev);
}

static struct net_device_stats *get_stats(struct net_device *dev)
{
	int i;
	struct net_device_stats *stats;

	stats = &veth_from_netdev(dev)->stats;
	memset(stats, 0, sizeof(struct net_device_stats));
	for_each_possible_cpu(i) {
		struct net_device_stats *dev_stats;

		dev_stats = veth_stats(dev, i);
		stats->rx_bytes   += dev_stats->rx_bytes;
		stats->tx_bytes   += dev_stats->tx_bytes;
		stats->rx_packets += dev_stats->rx_packets;
		stats->tx_packets += dev_stats->tx_packets;
		stats->tx_dropped += dev_stats->tx_dropped;
	}

	return stats;
}

/*
 * The higher levels take care of making this non-reentrant (it's
 * called with bh's disabled).
 */
static int veth_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct net_device_stats *stats;
	struct net_device *rcv = NULL;
	struct veth_struct *entry;
	int length;

	stats = veth_stats(dev, smp_processor_id());
	if (unlikely(get_exec_env()->disable_net))
		goto outf;

	entry = veth_from_netdev(dev);
	rcv = entry->pair;
	if (!rcv)
		/* VE going down */
		goto outf;

	if (!(rcv->flags & IFF_UP)) {
		/* Target VE does not want to receive packets */
		goto outf;
	}

	if (unlikely(rcv->owner_env->disable_net))
		goto outf;
	/* Filtering */
	if (ve_is_super(dev->owner_env) &&
			!veth_from_netdev(rcv)->allow_mac_change) {
		/* from VE0 to VEX */
		if (ve_is_super(rcv->owner_env))
			goto out;
		if (is_multicast_ether_addr(
					((struct ethhdr *)skb->data)->h_dest))
			goto out;
		if (!rcv->br_port &&
			compare_ether_addr(((struct ethhdr *)skb->data)->h_dest, rcv->dev_addr))
				goto outf;
	} else if (!ve_is_super(dev->owner_env) &&
			!entry->allow_mac_change) {
		/* from VEX to VE0 */
		if (!skb->dev->br_port &&
			compare_ether_addr(((struct ethhdr *)skb->data)->h_source, dev->dev_addr))
				goto outf;
	}

out:
	skb->owner_env = rcv->owner_env;

	skb->pkt_type = PACKET_HOST;
	skb->protocol = eth_type_trans(skb, rcv);

	if (skb->protocol != __constant_htons(ETH_P_IP))
		skb_orphan(skb);

	nf_reset(skb);
	length = skb->len;

	if (unlikely(netif_rx(skb) != NET_RX_SUCCESS))
		goto dropped;

	stats->tx_bytes += length;
	stats->tx_packets++;
	if (rcv) {
		struct net_device_stats *rcv_stats;
		rcv_stats = veth_stats(rcv, smp_processor_id());
		rcv_stats->rx_bytes += length;
		rcv_stats->rx_packets++;
	}

	return 0;

outf:
	kfree_skb(skb);
dropped:
	stats->tx_dropped++;
	return 0;
}

static int veth_set_mac(struct net_device *dev, void *p)
{
	struct sockaddr *addr = p;

	if (!ve_is_super(dev->owner_env) &&
			!veth_from_netdev(dev)->allow_mac_change)
		return -EPERM;
	if (netif_running(dev))
		return -EBUSY;
	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;

	memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);

	return 0;
}

static int veth_init_dev(struct net_device *dev)
{
	veth_from_netdev(dev)->real_stats =
		alloc_percpu(struct net_device_stats);
	if (veth_from_netdev(dev)->real_stats == NULL)
		return -ENOMEM;

	return 0;
}

static int
veth_set_op(struct net_device *dev, u32 data,
	     int (*fop)(struct net_device *, u32))
{
	struct net_device *pair;
	int ret = 0;

	ret = fop(dev, data);
	if (ret < 0)
		goto out;

	pair = veth_from_netdev(dev)->pair;
	if (pair)
		ret = fop(pair, data);
out:
	return ret;
}

static int veth_op_set_sg(struct net_device *dev, u32 data)
{
	return veth_set_op(dev, data, ethtool_op_set_sg);
}

static int veth_op_set_tx_csum(struct net_device *dev, u32 data)
{
	return veth_set_op(dev, data, ethtool_op_set_tx_csum);
}

static int
veth_op_set_tso(struct net_device *dev, u32 data)
{
	return veth_set_op(dev, data, ethtool_op_set_tso);
}

#define veth_op_set_rx_csum veth_op_set_tx_csum

static struct ethtool_ops veth_ethtool_ops = {
	.get_sg = ethtool_op_get_sg,
	.set_sg = veth_op_set_sg,
	.get_tx_csum = ethtool_op_get_tx_csum,
	.set_tx_csum = veth_op_set_tx_csum,
	.get_rx_csum = ethtool_op_get_tx_csum,
	.set_rx_csum = veth_op_set_rx_csum,
	.get_tso = ethtool_op_get_tso,
	.set_tso = veth_op_set_tso,
};

static void veth_cpt(struct net_device *dev,
		struct cpt_ops *ops, struct cpt_context *ctx)
{
	struct cpt_veth_image v;
	struct veth_struct *veth;

	veth = veth_from_netdev(dev);

	v.cpt_next = CPT_NULL;
	v.cpt_object = CPT_OBJ_NET_VETH;
	v.cpt_hdrlen = sizeof(v);
	v.cpt_content = CPT_CONTENT_VOID;

	v.cpt_allow_mac_change = veth->allow_mac_change;

	ops->write(&v, sizeof(v), ctx);
}

static int veth_rst(loff_t pos, struct cpt_netdev_image *di,
		struct rst_ops *ops,
		struct cpt_context *ctx)

{
	int err;
	struct cpt_veth_image vi;
	struct veth_struct *veth;
	struct net_device *dev;

	pos = pos + di->cpt_hdrlen;
	err = ops->get_object(CPT_OBJ_NET_VETH, pos,
			&vi, sizeof(vi), ctx);
	if (err)
		return err;

	dev = __dev_get_by_name(get_exec_env()->ve_ns->net_ns, di->cpt_name);
	if (dev == NULL)
		return -ENODEV;

	veth = veth_from_netdev(dev);
	veth->allow_mac_change = vi.cpt_allow_mac_change;

	return 0;
}

static struct netdev_rst veth_netdev_rst = {
	.cpt_object = CPT_OBJ_NET_VETH,
	.ndo_rst = veth_rst,
};

static const struct net_device_ops veth_ops = {
	.ndo_init = veth_init_dev,
	.ndo_start_xmit = veth_xmit,
	.ndo_get_stats = get_stats,
	.ndo_open = veth_open,
	.ndo_stop = veth_close,
	.ndo_set_mac_address = veth_set_mac,
	.ndo_cpt = veth_cpt,
};

static void veth_setup(struct net_device *dev)
{
	ether_setup(dev);

	dev->netdev_ops = &veth_ops;
	dev->destructor = veth_destructor;
	dev->tx_queue_len = 0;

	/*
	 * No other features, as they are:
	 *  - checksumming is required, and nobody else will done our job
	 */
	dev->features |= NETIF_F_LLTX |	NETIF_F_HIGHDMA;
	dev->vz_features |= NETIF_F_VENET | NETIF_F_VIRTUAL;

	SET_ETHTOOL_OPS(dev, &veth_ethtool_ops);
}

#ifdef CONFIG_PROC_FS
#define ADDR_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define ADDR_ARG(x) (x)[0],(x)[1],(x)[2],(x)[3],(x)[4],(x)[5]
static int vehwaddr_seq_show(struct seq_file *m, void *v)
{
	struct list_head *p;
	struct veth_struct *entry;

	p = (struct list_head *)v;
	if (p == &veth_hwaddr_list) {
		seq_puts(m, "Version: 1.0\n");
		return 0;
	}
	entry = list_entry(p, struct veth_struct, hwaddr_list);
	seq_printf(m, ADDR_FMT " %16s ",
			ADDR_ARG(entry->pair->dev_addr), entry->pair->name);
	seq_printf(m, ADDR_FMT " %16s %10u %5s\n",
			ADDR_ARG(veth_to_netdev(entry)->dev_addr),
			veth_to_netdev(entry)->name,
			VEID(veth_to_netdev(entry)->owner_env),
			entry->allow_mac_change ? "allow" : "deny");
	return 0;
}

static void *vehwaddr_seq_start(struct seq_file *m, loff_t *pos)
{
	read_lock(&ve_hwaddr_lock);
	return seq_list_start_head(&veth_hwaddr_list, *pos);
}

static void *vehwaddr_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	return seq_list_next(v, &veth_hwaddr_list, pos);
}

static void vehwaddr_seq_stop(struct seq_file *m, void *v)
{
	read_unlock(&ve_hwaddr_lock);
}

static struct seq_operations vehwaddr_seq_op = {
	.start	= vehwaddr_seq_start,
	.next	= vehwaddr_seq_next,
	.stop	= vehwaddr_seq_stop,
	.show	= vehwaddr_seq_show,
};

static int vehwaddr_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &vehwaddr_seq_op);
}

static struct file_operations proc_vehwaddr_operations = {
	.open		= vehwaddr_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};
#endif

static int real_ve_hwaddr(envid_t veid, int op,
		unsigned char *dev_addr, int addrlen, char *name,
		unsigned char *dev_addr_ve, int addrlen_ve, char *name_ve)
{
	int err;
	struct ve_struct *ve;
	char ve_addr[ETH_ALEN];

	err = -EPERM;
	if (!capable(CAP_NET_ADMIN))
		goto out;

	err = -EINVAL;
	switch (op) {
	case VE_ETH_ADD:
		if (addrlen != ETH_ALEN)
			goto out;
		if (addrlen_ve != ETH_ALEN && addrlen_ve != 0)
			goto out;
		/* If ve addr is not set then we use dev_addr[3] & 0x80 for it */
		if (addrlen_ve == 0 && (dev_addr[3] & 0x80))
			goto out;
		if (addrlen_ve == 0) {
			memcpy(ve_addr, dev_addr, ETH_ALEN);
			ve_addr[3] |= 0x80;
		} else {
			memcpy(ve_addr, dev_addr_ve, ETH_ALEN);
		}

		ve = get_ve_by_id(veid);
		err = -ESRCH;
		if (!ve)
			goto out;

		down_read(&ve->op_sem);
		if (ve->is_running)
			err = veth_entry_add(ve, dev_addr, name, ve_addr, name_ve);
		up_read(&ve->op_sem);
		put_ve(ve);
		break;

	case VE_ETH_DEL:
		if (name[0] == '\0')
			goto out;
		ve = get_ve_by_id(veid);
		err = -ESRCH;
		if (!ve)
			goto out;

		down_read(&ve->op_sem);
		if (ve->is_running)
			err = veth_entry_del(ve, name);
		up_read(&ve->op_sem);
		put_ve(ve);
		break;
	case VE_ETH_ALLOW_MAC_CHANGE:
	case VE_ETH_DENY_MAC_CHANGE:
		err = veth_allow_change_mac(veid, name,
						op == VE_ETH_ALLOW_MAC_CHANGE);
		break;
	}

out:
	return err;
}

static int veth_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int err;

	err = -ENOTTY;
	switch(cmd) {
	case VETHCTL_VE_HWADDR: {
		struct vzctl_ve_hwaddr s;

		err = -EFAULT;
		if (copy_from_user(&s, (void __user *)arg, sizeof(s)))
			break;
		err = real_ve_hwaddr(s.veid, s.op, s.dev_addr, s.addrlen,
				     s.dev_name, s.dev_addr_ve, s.addrlen_ve,
				     s.dev_name_ve);
	}
	break;
	}
	return err;
}

static struct vzioctlinfo vethcalls = {
	.type		= VETHCTLTYPE,
	.ioctl		= veth_ioctl,
	.compat_ioctl	= veth_ioctl,
	.owner		= THIS_MODULE,
};

static struct net_device * veth_dev_start(char *dev_addr, char *name)
{
	struct net_device *dev;
	int err;

	if (!is_valid_ether_addr(dev_addr))
		return ERR_PTR(-EADDRNOTAVAIL);

	dev = alloc_netdev(sizeof(struct veth_struct), name, veth_setup);
	if (!dev)
		return ERR_PTR(-ENOMEM);
	dev->nd_net = get_exec_env()->ve_netns;
	if (strchr(dev->name, '%')) {
		err = dev_alloc_name(dev, dev->name);
		if (err < 0)
			goto err;
	}
	if ((err = register_netdev(dev)) != 0)
		goto err;

	memcpy(dev->dev_addr, dev_addr, ETH_ALEN);
	dev->addr_len = ETH_ALEN;

	return dev;
err:
	free_netdev(dev);
	printk(KERN_ERR "%s initialization error err=%d\n", name, err);
	return ERR_PTR(err);
}

static __net_exit void veth_exit_net(struct list_head *net_exit_list)
{
	struct net *net;
	struct veth_struct *entry, *tmp;
	LIST_HEAD(netdev_kill_list);

	down(&hwaddr_sem);
	list_for_each_entry(net, net_exit_list, exit_list) {
		struct ve_struct *old_env;

		old_env = set_exec_env(net->owner_ve);
		list_for_each_entry_safe(entry, tmp,
					 &veth_hwaddr_list, hwaddr_list)
			if (net == veth_to_netdev(entry)->nd_net)
				veth_pair_del(net->owner_ve, entry,
					      &netdev_kill_list);
		set_exec_env(old_env);
	}
	up(&hwaddr_sem);

	rtnl_lock();
	unregister_netdevice_many(&netdev_kill_list);
	rtnl_unlock();
}

static struct pernet_operations veth_net_ops = {
	.exit_batch = veth_exit_net,
};

static __init int veth_init(void)
{
	int err;
	struct proc_dir_entry *de;

	err = register_pernet_device(&veth_net_ops);
	if (err)
		return err;

#ifdef CONFIG_PROC_FS
	de = proc_create("veth", S_IFREG|S_IRUSR, proc_vz_dir,
			&proc_vehwaddr_operations);
	if (de == NULL)
		printk(KERN_WARNING "veth: can't make vehwaddr proc entry\n");
#endif

	register_netdev_rst(&veth_netdev_rst);
	vzioctl_register(&vethcalls);
	return 0;
}

static __exit void veth_exit(void)
{
	vzioctl_unregister(&vethcalls);
	unregister_pernet_device(&veth_net_ops);
	unregister_netdev_rst(&veth_netdev_rst);

#ifdef CONFIG_PROC_FS
	remove_proc_entry("veth", proc_vz_dir);
#endif
}

module_init(veth_init);
module_exit(veth_exit);

MODULE_AUTHOR("Andrey Mirkin <amirkin@sw.ru>");
MODULE_DESCRIPTION("Virtuozzo Virtual Ethernet Device");
MODULE_LICENSE("GPL v2");

