/*
 *  venet_core.c
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

/*
 * Common part for Virtuozzo virtual network devices
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
#include <net/addrconf.h>

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
#include <linux/ethtool.h>
#include <linux/venet.h>
#include <linux/ve_proto.h>
#include <linux/vzctl.h>
#include <linux/vzctl_venet.h>

struct hlist_head ip_entry_hash_table[VEIP_HASH_SZ];
DEFINE_SPINLOCK(veip_lock);
LIST_HEAD(veip_lh);

#define ip_entry_hash_function(ip)  (ntohl(ip) & (VEIP_HASH_SZ - 1))

void ip_entry_hash(struct ip_entry_struct *entry, struct veip_struct *veip)
{
	hlist_add_head_rcu(&entry->ip_hash,
			ip_entry_hash_table +
			ip_entry_hash_function(entry->addr.key[3]));
	list_add(&entry->ve_list, &veip->ip_lh);
}

static void ip_entry_free(struct rcu_head *rcu)
{
	struct ip_entry_struct *e;

	e = container_of(rcu, struct ip_entry_struct, rcu);
	kfree(e);
}

void ip_entry_unhash(struct ip_entry_struct *entry)
{
	list_del(&entry->ve_list);
	hlist_del_rcu(&entry->ip_hash);
	call_rcu(&entry->rcu, ip_entry_free);
}

static void veip_free(struct rcu_head *rcu)
{
	struct veip_struct *veip;

	veip = container_of(rcu, struct veip_struct, rcu);
	veip_pool_ops->veip_free(veip);
}

int veip_put(struct veip_struct *veip)
{
	if (!list_empty(&veip->ip_lh))
		return 0;
	if (!list_empty(&veip->src_lh))
		return 0;
	if (!list_empty(&veip->dst_lh))
		return 0;

	list_del(&veip->list);
	call_rcu(&veip->rcu, veip_free);
	return 1;
}

struct ip_entry_struct *venet_entry_lookup(struct ve_addr_struct *addr)
{
	struct ip_entry_struct *entry;
	struct hlist_node *n;

	hlist_for_each_entry_rcu(entry, n, ip_entry_hash_table +
			ip_entry_hash_function(addr->key[3]), ip_hash)
		if (memcmp(&entry->addr, addr, sizeof(*addr)) == 0)
			return entry;
	return NULL;
}

struct ext_entry_struct *venet_ext_lookup(struct ve_struct *ve,
		struct ve_addr_struct *addr)
{
	struct ext_entry_struct *entry;
	struct veip_struct *veip;

	veip = ACCESS_ONCE(ve->veip);
	if (veip == NULL)
		return NULL;

	list_for_each_entry_rcu (entry, &veip->ext_lh, list)
		if (memcmp(&entry->addr, addr, sizeof(*addr)) == 0)
			return entry;
	return NULL;
}

static int venet_ext_add(struct ve_struct *ve, struct ve_addr_struct *addr)
{
	struct ext_entry_struct *entry, *found;
	int err;

	if (ve->veip == NULL)
		return -ENONET;

	entry = kzalloc(sizeof(struct ext_entry_struct), GFP_KERNEL);
	if (entry == NULL)
		return -ENOMEM;

	spin_lock(&veip_lock);
	err = -EADDRINUSE;
	found = venet_ext_lookup(ve, addr);
	if (found != NULL)
		goto out_unlock;

	entry->addr = *addr;
	list_add_rcu(&entry->list, &ve->veip->ext_lh);
	err = 0;
	entry = NULL;
out_unlock:
	spin_unlock(&veip_lock);
	if (entry != NULL)
		kfree(entry);
	return err;
}

static void venet_ext_free(struct rcu_head *rcu)
{
	struct ext_entry_struct *e;

	e = container_of(rcu, struct ext_entry_struct, rcu);
	kfree(e);
}

static void venet_ext_release(struct ext_entry_struct *e)
{
	list_del_rcu(&e->list);
	call_rcu(&e->rcu, venet_ext_free);
}

static int venet_ext_del(struct ve_struct *ve, struct ve_addr_struct *addr)
{
	struct ext_entry_struct *found;
	int err;

	if (ve->veip == NULL)
		return -ENONET;

	err = -EADDRNOTAVAIL;
	spin_lock(&veip_lock);
	found = venet_ext_lookup(ve, addr);
	if (found == NULL)
		goto out;

	venet_ext_release(found);
	err = 0;
out:
	spin_unlock(&veip_lock);
	return err;
}

static void venet_ext_clean(struct ve_struct *ve)
{
	struct ext_entry_struct *entry, *tmp;

	if (ve->veip == NULL)
		return;

	spin_lock(&veip_lock);
	list_for_each_entry_safe (entry, tmp, &ve->veip->ext_lh, list)
		venet_ext_release(entry);
	spin_unlock(&veip_lock);
}

struct veip_struct *veip_find(envid_t veid)
{
	struct veip_struct *ptr;

	list_for_each_entry(ptr, &veip_lh, list) {
		if (ptr->veid != veid)
			continue;
		return ptr;
	}
	return NULL;
}

struct veip_struct *veip_findcreate(envid_t veid)
{
	struct veip_struct *ptr;

	ptr = veip_find(veid);
	if (ptr != NULL)
		return ptr;

	ptr = kmalloc(sizeof(struct veip_struct), GFP_ATOMIC);
	if (ptr == NULL)
		return NULL;
	memset(ptr, 0, sizeof(struct veip_struct));
	INIT_LIST_HEAD(&ptr->ip_lh);
	INIT_LIST_HEAD(&ptr->src_lh);
	INIT_LIST_HEAD(&ptr->dst_lh);
	INIT_LIST_HEAD(&ptr->ext_lh);
	ptr->veid = veid;
	list_add(&ptr->list, &veip_lh);
	return ptr;
}

static int veip_start(struct ve_struct *ve)
{
	int err, get;

	spin_lock(&veip_lock);

	get = ve->veip == NULL;
	err = veip_pool_ops->veip_create(ve);
	if (!err && get && !ve_is_super(ve))
		__module_get(THIS_MODULE);

	spin_unlock(&veip_lock);

	return err;
}

static void veip_stop(struct ve_struct *ve)
{
	struct list_head *p, *tmp;

	spin_lock(&veip_lock);
	if (ve->veip == NULL)
		goto unlock;
	list_for_each_safe(p, tmp, &ve->veip->ip_lh) {
		struct ip_entry_struct *ptr;
		ptr = list_entry(p, struct ip_entry_struct, ve_list);
		ptr->active_env = NULL;

		if (ptr->tgt_veip == NULL)
			ip_entry_unhash(ptr);
	}

	veip_pool_ops->veip_release(ve);
	if (!ve_is_super(ve))
		module_put(THIS_MODULE);
unlock:
	spin_unlock(&veip_lock);
}

static int veip_entry_conflict(struct ip_entry_struct *entry, struct ve_struct *ve)
{
	if (entry->active_env != NULL)
		return -EADDRINUSE;
	if (entry->tgt_veip && entry->tgt_veip->veid != ve->veid)
		return -EADDRNOTAVAIL;

	entry->active_env = ve;
	return 0;
}

static int veip_entry_add(struct ve_struct *ve, struct ve_addr_struct *addr)
{
	struct ip_entry_struct *entry, *found;
	int err;

	entry = kzalloc(sizeof(struct ip_entry_struct), GFP_KERNEL);
	if (entry == NULL)
		return -ENOMEM;

	if (ve->veip == NULL) {
		/* This can happen if we load venet AFTER ve was started */
	       	err = veip_start(ve);
		if (err < 0)
			goto out;
	}

	spin_lock(&veip_lock);
	found = venet_entry_lookup(addr);
	if (found != NULL) {
		err = veip_entry_conflict(found, ve);
		goto out_unlock;
	}

	entry->active_env = ve;
	entry->addr = *addr;
	ip_entry_hash(entry, ve->veip);

	err = 0;
	entry = NULL;
out_unlock:
	spin_unlock(&veip_lock);
out:
	if (entry != NULL)
		kfree(entry);

	return err;
}

static int veip_entry_del(envid_t veid, struct ve_addr_struct *addr)
{
	struct ip_entry_struct *found;
	int err;

	err = -EADDRNOTAVAIL;
	spin_lock(&veip_lock);
	found = venet_entry_lookup(addr);
	if (found == NULL)
		goto out;
	if (found->active_env == NULL)
		goto out;
	if (found->active_env->veid != veid)
		goto out;

	err = 0;
	found->active_env = NULL;

	if (found->tgt_veip == NULL)
		ip_entry_unhash(found);
out:
	spin_unlock(&veip_lock);
	return err;
}

static int convert_sockaddr(struct sockaddr *addr, int addrlen,
		struct ve_addr_struct *veaddr)
{
	int err;

	switch (addr->sa_family) {
	case AF_INET: {
		struct sockaddr_in *sin;

		err = -EINVAL;
		if (addrlen != sizeof(struct sockaddr_in))
			break;

		err = 0;
		sin = (struct sockaddr_in *)addr;
		veaddr->family = AF_INET;
		veaddr->key[0] = 0;
		veaddr->key[1] = 0;
		veaddr->key[2] = 0;
		veaddr->key[3] = sin->sin_addr.s_addr;
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6 *sin;

		err = -EINVAL;
		if (addrlen != sizeof(struct sockaddr_in6))
			break;

		err = 0;
		sin = (struct sockaddr_in6 *)addr;
		veaddr->family = AF_INET6;
		memcpy(veaddr->key, &sin->sin6_addr, sizeof(veaddr->key));
		break;
	}
	default:
		err = -EAFNOSUPPORT;
	}
	return err;
}

int sockaddr_to_veaddr(struct sockaddr __user *uaddr, int addrlen,
		struct ve_addr_struct *veaddr)
{
	int err;
	char addr[MAX_SOCK_ADDR];

	err = move_addr_to_kernel(uaddr, addrlen, (struct sockaddr *)&addr);
	if (err < 0)
		goto out;

	err = convert_sockaddr((struct sockaddr *)&addr, addrlen, veaddr);
out:
	return err;
}

void veaddr_print(char *str, int len, struct ve_addr_struct *a)
{
	if (a->family == AF_INET)
		snprintf(str, len, "%u.%u.%u.%u", NIPQUAD(a->key[3]));
	else
		snprintf(str, len, "%x:%x:%x:%x:%x:%x:%x:%x",
				ntohl(a->key[0])>>16, ntohl(a->key[0])&0xFFFF,
				ntohl(a->key[1])>>16, ntohl(a->key[1])&0xFFFF,
				ntohl(a->key[2])>>16, ntohl(a->key[2])&0xFFFF,
				ntohl(a->key[3])>>16, ntohl(a->key[3])&0xFFFF
			);
}

/*
 * Device functions
 */

static int venet_open(struct net_device *dev)
{
	if (!ve_is_super(get_exec_env()) && !try_module_get(THIS_MODULE))
		return -EBUSY;
	return 0;
}

static int venet_close(struct net_device *master)
{
	if (!ve_is_super(get_exec_env()))
		module_put(THIS_MODULE);
	return 0;
}

static void venet_destructor(struct net_device *dev)
{
	struct venet_stats *stats = (struct venet_stats *)dev->ml_priv;
	if (stats == NULL)
		return;
	free_percpu(stats->real_stats);
	kfree(stats);
	dev->ml_priv = NULL;
}

/*
 * The higher levels take care of making this non-reentrant (it's
 * called with bh's disabled).
 */
static int venet_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct net_device_stats *stats;
	struct net_device *rcv = NULL;
	struct ve_struct *ve;
	int length;

	stats = venet_stats(dev, smp_processor_id());
	ve = get_exec_env();
	if (unlikely(ve->disable_net))
		goto outf;

	if (skb->protocol == __constant_htons(ETH_P_IP)) {
		struct iphdr *iph;
		iph = ip_hdr(skb);
		if (ipv4_is_multicast(iph->daddr))
			goto outf;
	} else if (skb->protocol == __constant_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h;
		ip6h = ipv6_hdr(skb);
		if (ipv6_addr_is_multicast(&ip6h->daddr))
			goto outf;
		skb_orphan(skb);
	} else {
		goto outf;
	}

	ve = veip_pool_ops->veip_lookup(skb);
	if (IS_ERR(ve))
		goto outf;

	skb->owner_env = ve;
	if (unlikely(ve->disable_net))
		goto outf;

	rcv = ve->_venet_dev;
	if (!rcv)
		/* VE going down */
		goto outf;

	dev_hold(rcv);

	if (!(rcv->flags & IFF_UP))
		/* Target VE does not want to receive packets */
		goto outf;

	skb->pkt_type = PACKET_HOST;
	skb->dev = rcv;

	/*
	 * If there is not enough space for header we allocate one.
	 * Remember the traffic can reach VE from outside world and
	 * as result we have to cleanup mac address of such packet.
	 * The same applies to traffic which comes from inside of VE
	 * but if TUN is used and traffic get fragmented we might reach
	 * the point where is no L2 header at all and hard_header_len
	 * is simply ingnored (because this parameter is kind of a hint
	 * for upper net layers and never a guarantee that header will be
	 * provided). To unify the way how packets are seen after venet
	 * we always produce L2 header with zero'ified MAC.
	 */
	if (unlikely(skb_headroom(skb) < dev->hard_header_len)) {
		struct sk_buff *skb2;

		skb2 = skb_realloc_headroom(skb, LL_RESERVED_SPACE(dev));
		if (!skb2)
			goto outf;

		if (skb->sk)
			skb_set_owner_w(skb2, skb->sk);
		kfree_skb(skb);
		skb = skb2;
	}

	skb_reset_mac_header(skb);
	memset(skb->data - dev->hard_header_len, 0, dev->hard_header_len);

	nf_reset(skb);
	length = skb->len;

	if (unlikely(netif_rx(skb) != NET_RX_SUCCESS))
		goto dropped;

	stats->tx_bytes += length;
	stats->tx_packets++;
	if (rcv) {
		struct net_device_stats *rcv_stats;

		rcv_stats = venet_stats(rcv, smp_processor_id());
		rcv_stats->rx_bytes += length;
		rcv_stats->rx_packets++;
		dev_put(rcv);
	}

	return 0;

outf:
	kfree_skb(skb);
dropped:
	if (rcv)
		dev_put(rcv);
	++stats->tx_dropped;
	return 0;
}

static struct net_device_stats *get_stats(struct net_device *dev)
{
	int i;
	struct venet_stats *stats;

	stats = (struct venet_stats *)dev->ml_priv;
	memset(&stats->stats, 0, sizeof(struct net_device_stats));
	for_each_possible_cpu(i) {
		struct net_device_stats *dev_stats;

		dev_stats = venet_stats(dev, i);
		stats->stats.rx_bytes   += dev_stats->rx_bytes;
		stats->stats.tx_bytes   += dev_stats->tx_bytes;
		stats->stats.rx_packets += dev_stats->rx_packets;
		stats->stats.tx_packets += dev_stats->tx_packets;
		stats->stats.tx_dropped += dev_stats->tx_dropped;
	}

	return &stats->stats;
}

/* Initialize the rest of the LOOPBACK device. */
int venet_init_dev(struct net_device *dev)
{
	struct venet_stats *stats;

	stats = kzalloc(sizeof(struct venet_stats), GFP_KERNEL);
	if (stats == NULL)
		goto fail;
	stats->real_stats = alloc_percpu(struct net_device_stats);
	if (stats->real_stats == NULL)
		goto fail_free;
	dev->ml_priv = stats;

	/*
	 *	Fill in the generic fields of the device structure.
	 */
	dev->type		= ARPHRD_VOID;
	dev->hard_header_len 	= ETH_HLEN;
	dev->mtu		= 1500; /* eth_mtu */
	dev->tx_queue_len	= 0;

	memset(dev->broadcast, 0xFF, ETH_ALEN);

	/* New-style flags. */
	dev->flags		= IFF_BROADCAST|IFF_NOARP|IFF_POINTOPOINT;
	return 0;

fail_free:
	kfree(stats);
fail:
	return -ENOMEM;
}

static const struct net_device_ops venet_netdev_ops;

static int
venet_set_op(struct net_device *dev, u32 data,
	     int (*fop)(struct net_device *, u32))
{
	struct net_device *nd;
	struct net *net;
	int ret = 0;

	for_each_net(net) {
		for_each_netdev(net, nd) {
			if (nd->netdev_ops == &venet_netdev_ops)
				ret |= fop(nd, data);
				/* no rollback here! */
		}
	}
	return ret;
}

static unsigned long common_features;

static int venet_op_set_sg(struct net_device *dev, u32 data)
{
	if (!ve_is_super(get_exec_env()))
		return -EPERM;

	if (data)
		common_features |= NETIF_F_SG;
	else
		common_features &= ~NETIF_F_SG;

	return venet_set_op(dev, data, ethtool_op_set_sg);
}

static int venet_op_set_tx_csum(struct net_device *dev, u32 data)
{
	if (!ve_is_super(get_exec_env()))
		return -EPERM;

	if (data)
		common_features |= NETIF_F_IP_CSUM;
	else
		common_features &= ~NETIF_F_IP_CSUM;

	return venet_set_op(dev, data, ethtool_op_set_tx_csum);
}

static int
venet_op_set_tso(struct net_device *dev, u32 data)
{
	if (!ve_is_super(get_exec_env()))
		return -EPERM;

	if (data)
		common_features |= NETIF_F_TSO;
	else
		common_features &= ~NETIF_F_TSO;

	return venet_set_op(dev, data, ethtool_op_set_tso);
}

#define venet_op_set_rx_csum venet_op_set_tx_csum

static struct ethtool_ops venet_ethtool_ops = {
	.get_sg = ethtool_op_get_sg,
	.set_sg = venet_op_set_sg,
	.get_tx_csum = ethtool_op_get_tx_csum,
	.set_tx_csum = venet_op_set_tx_csum,
	.get_rx_csum = ethtool_op_get_tx_csum,
	.set_rx_csum = venet_op_set_rx_csum,
	.get_tso = ethtool_op_get_tso,
	.set_tso = venet_op_set_tso,
};

static void venet_cpt(struct net_device *dev,
		struct cpt_ops *ops, struct cpt_context *ctx)
{
}

static const struct net_device_ops venet_netdev_ops = {
	.ndo_start_xmit = venet_xmit,
	.ndo_get_stats = get_stats,
	.ndo_open = venet_open,
	.ndo_stop = venet_close,
	.ndo_init = venet_init_dev,
	.ndo_cpt = venet_cpt,
};

static void venet_setup(struct net_device *dev)
{
	/*
	 * No other features, as they are:
	 *  - checksumming is required, and nobody else will done our job
	 */
	dev->features |= NETIF_F_LLTX | NETIF_F_HIGHDMA | NETIF_F_VLAN_CHALLENGED;
	dev->vz_features |= NETIF_F_VENET | NETIF_F_VIRTUAL;

	dev->netdev_ops = &venet_netdev_ops;
	dev->destructor = venet_destructor;

	dev->features |= common_features;

	SET_ETHTOOL_OPS(dev, &venet_ethtool_ops);
}

#ifdef CONFIG_PROC_FS
static void veaddr_seq_print(struct seq_file *m, struct ve_struct *ve)
{
	struct ip_entry_struct *entry;
	struct veip_struct *veip;

	spin_lock(&veip_lock);
	veip = ACCESS_ONCE(ve->veip);
	if (veip == NULL)
		goto unlock;
	list_for_each_entry (entry, &veip->ip_lh, ve_list) {
		char addr[40];

		if (entry->active_env == NULL)
			continue;

		veaddr_print(addr, sizeof(addr), &entry->addr);
		if (entry->addr.family == AF_INET)
			seq_printf(m, " %15s", addr);
		else
			seq_printf(m, " %39s", addr);
	}
unlock:
	spin_unlock(&veip_lock);
}

static void *veip_seq_start(struct seq_file *m, loff_t *pos)
{
	loff_t l;
	struct hlist_node *p;
	struct ip_entry_struct *s;
	int i;

	l = *pos;
	rcu_read_lock();
	if (l == 0) {
		m->private = (void *)0;
		return SEQ_START_TOKEN;
	}

	for (i = 0; i < VEIP_HASH_SZ; i++) {
		hlist_for_each_entry_rcu(s, p, ip_entry_hash_table + i, ip_hash) {
			if (--l == 0) {
				m->private = (void *)(long)(i + 1);
				return p;
			}
		}
	}
	return NULL;
}

static void *veip_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct hlist_node *p;
	int i;

	if (v == SEQ_START_TOKEN)
		goto find;

	p = rcu_dereference(((struct hlist_node *)v)->next);
	if (p != NULL)
		goto found;

find:
	for (i = (int)(long)m->private; i < VEIP_HASH_SZ; i++) {
		p = rcu_dereference(ip_entry_hash_table[i].first);
		if (p != NULL) {
			m->private = (void *)(long)(i + 1);
found:
			(*pos)++;
			return p;
		}
	}

	return NULL;
}

static void veip_seq_stop(struct seq_file *m, void *v)
{
	rcu_read_unlock();
}

static int veip_seq_show(struct seq_file *m, void *v)
{
	struct hlist_node *p;
	struct ip_entry_struct *entry;
	struct veip_struct *veip;
	char s[40];

	if (v == SEQ_START_TOKEN) {
		seq_puts(m, "Version: 2.5\n");
		return 0;
	}

	p = (struct hlist_node *)v;
	entry = hlist_entry(p, struct ip_entry_struct, ip_hash);
	veaddr_print(s, sizeof(s), &entry->addr);
	veip = ACCESS_ONCE(entry->tgt_veip);
	seq_printf(m, "%39s %10u\n", s, veip == NULL ? 0 : veip->veid);
	return 0;
}

static struct seq_operations veip_seq_op = {
	.start	= veip_seq_start,
	.next	= veip_seq_next,
	.stop	= veip_seq_stop,
	.show	= veip_seq_show,
};

static int veip_open(struct inode *inode, struct file *file)
{
        return seq_open(file, &veip_seq_op);
}

static struct file_operations proc_veip_operations = {
	.open		= veip_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};
#endif

static int real_ve_ip_map(envid_t veid, int op, struct sockaddr __user *uaddr,
		int addrlen)
{
	int err;
	struct ve_struct *ve;
	struct ve_addr_struct addr;

	err = -EPERM;
	if (!capable_setveid())
		goto out;

	err = sockaddr_to_veaddr(uaddr, addrlen, &addr);
	if (err < 0)
		goto out;

	switch (op)
	{
		case VE_IP_ADD:
			ve = get_ve_by_id(veid);
			err = -ESRCH;
			if (!ve)
				goto out;

			down_read(&ve->op_sem);
			if (ve->is_running)
				err = veip_entry_add(ve, &addr);
			up_read(&ve->op_sem);
			put_ve(ve);
			break;

		case VE_IP_DEL:
			err = veip_entry_del(veid, &addr);
			break;
		case VE_IP_EXT_ADD:
			ve = get_ve_by_id(veid);
			err = -ESRCH;
			if (!ve)
				goto out;

			down_read(&ve->op_sem);
			err = venet_ext_add(ve, &addr);
			up_read(&ve->op_sem);
			put_ve(ve);
			break;
		case VE_IP_EXT_DEL:
			ve = get_ve_by_id(veid);
			err = -ESRCH;
			if (!ve)
				goto out;

			down_read(&ve->op_sem);
			err = venet_ext_del(ve, &addr);
			up_read(&ve->op_sem);
			put_ve(ve);
			break;
		default:
			err = -EINVAL;
	}

out:
	return err;
}

int venet_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int err;

	err = -ENOTTY;
	switch(cmd) {
	case VENETCTL_VE_IP_MAP: {
		struct vzctl_ve_ip_map s;
		err = -EFAULT;
		if (copy_from_user(&s, (void __user *)arg, sizeof(s)))
			break;
		err = real_ve_ip_map(s.veid, s.op, s.addr, s.addrlen);
		break;
	}
	}
	return err;
}

#ifdef CONFIG_COMPAT
int compat_venet_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int err;

	switch(cmd) {
	case VENETCTL_COMPAT_VE_IP_MAP: {
		struct compat_vzctl_ve_ip_map cs;

		err = -EFAULT;
		if (copy_from_user(&cs, (void *)arg, sizeof(cs)))
			break;

		err = real_ve_ip_map(cs.veid, cs.op, compat_ptr(cs.addr),
				cs.addrlen);
		break;
	}
	default:
		err = venet_ioctl(file, cmd, arg);
		break;
	}
	return err;
}
#endif

static struct vzioctlinfo venetcalls = {
	.type		= VENETCTLTYPE,
	.ioctl		= venet_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= compat_venet_ioctl,
#endif
	.owner		= THIS_MODULE,
};

int venet_dev_start(struct ve_struct *ve)
{
	struct net_device *dev_venet;
	int err;

	dev_venet = alloc_netdev(0, "venet%d", venet_setup);
	if (!dev_venet)
		return -ENOMEM;
	dev_net_set(dev_venet, ve->ve_netns);
	err = dev_alloc_name(dev_venet, dev_venet->name);
	if (err<0)
		goto err;

	dev_venet->features |= NETIF_F_NETNS_LOCAL;

	if ((err = register_netdev(dev_venet)) != 0)
		goto err;
	ve->_venet_dev = dev_venet;
	return 0;
err:
	free_netdev(dev_venet);
	printk(KERN_ERR "VENET initialization error err=%d\n", err);
	return err;
}

static __net_init int venet_init_net(struct net *net)
{
	struct ve_struct *env;
	int err;

	env = get_exec_env();
	if (env->ve_netns != NULL && net != env->ve_netns) {
		/* Don't create venet-s in sub net namespaces */
		return 0;
	}

	if (env->veip) {
		return -EEXIST;
	}

	env->ve_netns = net;

	err = veip_start(env);
	if (err != 0)
		goto err;

	err = venet_dev_start(env);
	if (err)
		goto err_free;
	return 0;

err_free:
	veip_stop(env);
err:
	env->ve_netns = NULL;
	return err;
}

static __net_exit void venet_exit_net(struct list_head *net_exit_list)
{
	struct net *net;
	struct ve_struct *env, *old_env;
	struct net_device *dev;
	LIST_HEAD(netdev_kill_list);

	list_for_each_entry(net, net_exit_list, exit_list) {
		env = net->owner_ve;
		old_env = set_exec_env(env);

		if (env->ve_netns != net)
			goto next;

		venet_ext_clean(env);
		veip_stop(env);

		dev = env->_venet_dev;
		if (dev == NULL)
			goto next;

		rtnl_lock();
		unregister_netdevice_queue(dev, &netdev_kill_list);
		rtnl_unlock();
next:
		set_exec_env(old_env);
	}

	rtnl_lock();
	unregister_netdevice_many(&netdev_kill_list);
	rtnl_unlock();

	list_for_each_entry(net, net_exit_list, exit_list) {
		env = net->owner_ve;

		if (env->ve_netns != net)
			continue;

		dev = env->_venet_dev;
		if (dev == NULL)
			continue;

		env->_venet_dev = NULL;

		old_env = set_exec_env(env);
		free_netdev(dev);
		set_exec_env(old_env);
	}
}

static struct pernet_operations venet_net_ops = {
	.init = venet_init_net,
	.exit_batch = venet_exit_net,
};

__init int venet_init(void)
{
#ifdef CONFIG_PROC_FS
	struct proc_dir_entry *de;
#endif
	int i, err;

	if (get_ve0()->_venet_dev != NULL)
		return -EEXIST;

	for (i = 0; i < VEIP_HASH_SZ; i++)
		INIT_HLIST_HEAD(ip_entry_hash_table + i);

	err = register_pernet_device(&venet_net_ops);
	if (err)
		return err;

#ifdef CONFIG_PROC_FS
	de = proc_create("veip", S_IFREG | S_IRUSR, proc_vz_dir,
			&proc_veip_operations);
	if (de == NULL)
		printk(KERN_WARNING "venet: can't make veip proc entry\n");
#endif

	vzioctl_register(&venetcalls);
	vzmon_register_veaddr_print_cb(veaddr_seq_print);
	return 0;
}

__exit void venet_exit(void)
{
	vzmon_unregister_veaddr_print_cb(veaddr_seq_print);
	vzioctl_unregister(&venetcalls);
	unregister_pernet_device(&venet_net_ops);

#ifdef CONFIG_PROC_FS
	remove_proc_entry("veip", proc_vz_dir);
#endif
	veip_cleanup();

	/* Ensure there are no outstanding rcu callbacks */
	rcu_barrier();

	BUG_ON(!list_empty(&veip_lh));
}

module_init(venet_init);
module_exit(venet_exit);

MODULE_AUTHOR("Virtuozzo");
MODULE_DESCRIPTION("Virtuozzo Virtual Network Device");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("vznet");

EXPORT_SYMBOL(veip_lock);
EXPORT_SYMBOL(ip_entry_hash);
EXPORT_SYMBOL(ip_entry_unhash);
EXPORT_SYMBOL(sockaddr_to_veaddr);
EXPORT_SYMBOL(veaddr_print);
EXPORT_SYMBOL(venet_entry_lookup);
EXPORT_SYMBOL(veip_find);
EXPORT_SYMBOL(veip_findcreate);
EXPORT_SYMBOL(veip_put);
EXPORT_SYMBOL(venet_ext_lookup);
EXPORT_SYMBOL(veip_lh);
EXPORT_SYMBOL(ip_entry_hash_table);
