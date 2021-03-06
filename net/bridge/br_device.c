/*
 *	Device handling code
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/netpoll.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/list.h>
#include <linux/nsproxy.h>
#include <linux/cpt_image.h>
#include <linux/cpt_export.h>

#include <asm/uaccess.h>
#include "br_private.h"

#define COMMON_FEATURES (NETIF_F_SG | NETIF_F_FRAGLIST | NETIF_F_HIGHDMA | \
			 NETIF_F_GSO_MASK | NETIF_F_HW_CSUM)

static struct device_type br_type = {
	.name	= "bridge",
};

/* net device transmit always called with no BH (preempt_disabled) */
netdev_tx_t br_dev_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct net_bridge *br = netdev_priv(dev);
	const unsigned char *dest = skb->data;
	struct net_bridge_fdb_entry *dst;
	struct net_bridge_mdb_entry *mdst;
	struct br_cpu_netstats *brstats = this_cpu_ptr(br->stats);

	u64_stats_update_begin(&brstats->syncp);
	brstats->tx_packets++;
	brstats->tx_bytes += skb->len;
	u64_stats_update_end(&brstats->syncp);

	BR_INPUT_SKB_CB(skb)->brdev = dev;

	skb_reset_mac_header(skb);
	skb_pull(skb, ETH_HLEN);

	skb->brmark = BR_ALREADY_SEEN;

	if (is_broadcast_ether_addr(dest))
		br_flood_deliver(br, skb);
	else if (is_multicast_ether_addr(dest)) {
		if (unlikely(netpoll_tx_running(dev))) {
			br_flood_deliver(br, skb);
			goto out;
		}
		if (br_multicast_rcv(br, NULL, skb)) {
			kfree_skb(skb);
			goto out;
		}

		mdst = br_mdb_get(br, skb);
		if ((mdst || BR_INPUT_SKB_CB(skb)->mrouters_only) &&
		    br_multicast_querier_exists(br, eth_hdr(skb)))
			br_multicast_deliver(mdst, skb);
		else
			br_flood_deliver(br, skb);
	} else if ((dst = __br_fdb_get(br, dest)) != NULL)
		br_deliver(dst->dst, skb, 1);
	else
		br_flood_deliver(br, skb);

out:
	return NETDEV_TX_OK;
}

static int br_dev_init(struct net_device *dev)
{
	struct net_bridge *br = netdev_priv(dev);
	struct net *net = dev_net(dev);

	if (!(net->owner_ve->features & VE_FEATURE_BRIDGE))
		return -EACCES;

	br->stats = alloc_percpu(struct br_cpu_netstats);
	if (!br->stats)
		return -ENOMEM;

	return 0;
}

static int br_dev_open(struct net_device *dev)
{
	struct net_bridge *br = netdev_priv(dev);

	netdev_update_features(dev);
	netif_start_queue(dev);
	br_stp_enable_bridge(br);
	br_multicast_open(br);

	return 0;
}

static void br_dev_set_multicast_list(struct net_device *dev)
{
}

static int br_dev_stop(struct net_device *dev)
{
	struct net_bridge *br = netdev_priv(dev);

	br_stp_disable_bridge(br);
	br_multicast_stop(br);

	netif_stop_queue(dev);

	return 0;
}

static struct rtnl_link_stats64 *br_get_stats64(struct net_device *dev,
						struct rtnl_link_stats64 *stats)
{
	struct net_bridge *br = netdev_priv(dev);
	struct br_cpu_netstats tmp, sum = { 0 };
	unsigned int cpu;

	for_each_possible_cpu(cpu) {
		unsigned int start;
		const struct br_cpu_netstats *bstats
			= per_cpu_ptr(br->stats, cpu);
		do {
			start = u64_stats_fetch_begin_irq(&bstats->syncp);
			memcpy(&tmp, bstats, sizeof(tmp));
		} while (u64_stats_fetch_retry_irq(&bstats->syncp, start));
		sum.tx_bytes   += tmp.tx_bytes;
		sum.tx_packets += tmp.tx_packets;
		sum.rx_bytes   += tmp.rx_bytes;
		sum.rx_packets += tmp.rx_packets;
	}

	stats->tx_bytes   = sum.tx_bytes;
	stats->tx_packets = sum.tx_packets;
	stats->rx_bytes   = sum.rx_bytes;
	stats->rx_packets = sum.rx_packets;

	return stats;
}

static int br_change_mtu(struct net_device *dev, int new_mtu)
{
	struct net_bridge *br = netdev_priv(dev);
	if (new_mtu < 68 || new_mtu > br_min_mtu(br))
		return -EINVAL;

	dev->mtu = new_mtu;

#ifdef CONFIG_BRIDGE_NETFILTER
	/* remember the MTU in the rtable for PMTU */
	br->fake_rtable.u.dst.metrics[RTAX_MTU - 1] = new_mtu;
#endif

	return 0;
}

/* Allow setting mac address to any valid ethernet address. */
static int br_set_mac_address(struct net_device *dev, void *p)
{
	struct net_bridge *br = netdev_priv(dev);
	struct sockaddr *addr = p;

	if (!is_valid_ether_addr(addr->sa_data))
		return -EINVAL;

	spin_lock_bh(&br->lock);
	if (compare_ether_addr(dev->dev_addr, addr->sa_data)) {
		memcpy(dev->dev_addr, addr->sa_data, ETH_ALEN);
		dev->addr_assign_type = NET_ADDR_PERM;
		br_fdb_change_mac_address(br, addr->sa_data);
		br_stp_change_bridge_id(br, addr->sa_data);
	}
	br->flags |= BR_SET_MAC_ADDR;
	spin_unlock_bh(&br->lock);

	return 0;
}

static void br_getinfo(struct net_device *dev, struct ethtool_drvinfo *info)
{
	strcpy(info->driver, "bridge");
	strcpy(info->version, BR_VERSION);
	strcpy(info->fw_version, "N/A");
	strcpy(info->bus_info, "N/A");
}

static u32 br_fix_features(struct net_device *dev, u32 features)
{
	struct net_bridge *br = netdev_priv(dev);

	return br_features_recompute(br, features);
}

#ifdef CONFIG_NET_POLL_CONTROLLER
static void br_poll_controller(struct net_device *br_dev)
{
}

static void br_netpoll_cleanup(struct net_device *dev)
{
	struct net_bridge *br = netdev_priv(dev);
	struct net_bridge_port *p, *n;

	list_for_each_entry_safe(p, n, &br->port_list, list) {
		br_netpoll_disable(p);
	}
}

static int br_netpoll_setup(struct net_device *dev, struct netpoll_info *ni,
			    gfp_t gfp)
{
	struct net_bridge *br = netdev_priv(dev);
	struct net_bridge_port *p, *n;
	int err = 0;

	br->dev->npinfo = NULL;
	list_for_each_entry_safe(p, n, &br->port_list, list) {
		if (!p->dev)
			continue;
		err = br_netpoll_enable(p, gfp);
		if (err)
			goto fail;
	}

out:
	return err;

fail:
	br_netpoll_cleanup(dev);
	goto out;
}

int br_netpoll_enable(struct net_bridge_port *p, gfp_t gfp)
{
	struct netpoll *np;
	int err = 0;

	np = kzalloc(sizeof(*p->np), gfp);
	err = -ENOMEM;
	if (!np)
		goto out;

	np->dev = p->dev;

	err = __netpoll_setup(np, p->dev, gfp);
	if (err) {
		kfree(np);
		goto out;
	}

	p->np = np;

out:
	return err;
}

void br_netpoll_disable(struct net_bridge_port *p)
{
	struct netpoll *np = p->np;

	if (!np)
		return;

	p->np = NULL;

	/* Wait for transmitting packets to finish before freeing. */
	synchronize_rcu_bh();

	__netpoll_cleanup(np);
	kfree(np);
}

#endif

static void br_vlan_rx_register(struct net_device *br_dev, struct vlan_group *grp)
{
	struct net_bridge *br = netdev_priv(br_dev);
	struct net_bridge_port *p, *n;
	const struct net_device_ops *ops;

	/* RHEL6 specific!
	 * Although vlan groups are no longer used in rx path due to vlan
	 * centralization, some drivers still turn on vlan accel
	 * only in case vlan group is registered to them. So do it here.
	 */

	br->vlgrp = grp;
	list_for_each_entry_safe(p, n, &br->port_list, list) {
		if (!p->dev)
			continue;

		ops = p->dev->netdev_ops;
		if (ops->ndo_vlan_rx_register && (p->dev->features & NETIF_F_HW_VLAN_RX))
			ops->ndo_vlan_rx_register(p->dev, grp);
	}
}

static int br_rst_nested_dev(loff_t start, struct cpt_br_image *bri,
			 struct net_bridge *br, struct rst_ops *ops,
			 struct cpt_context *ctx)
{
	struct net_device *dev;
	int ret = 0;
	loff_t pos;

	pos = start + bri->cpt_hdrlen;

	while (pos < start + bri->cpt_next) {
		struct cpt_br_nested_dev o;

		ret = ops->get_object(CPT_OBJ_NET_BR_DEV, pos, &o, sizeof(o), ctx);
		if (ret)
			break;

		dev = dev_get_by_name(dev_net(br->dev), o.name);
		if (!dev) {
			printk(KERN_ERR "%s: restore '%s' nested dev\n", __func__, o.name);
			WARN_ON(1);
			ret = -ENODEV;
			break;
		}

		ret = br_add_if(br, dev);
		dev_put(dev);
		if (ret)
			break;

		pos += o.cpt_next;
	}
	return ret;
}

int br_rst(loff_t start, struct cpt_netdev_image *di,
		struct rst_ops *ops, struct cpt_context *ctx)
{
	struct net *net = current->nsproxy->net_ns;
	struct cpt_br_image bri;
	struct net_device *dev;
	struct net_bridge *br;
	loff_t pos;
	int ret;

	pos = start + di->cpt_hdrlen;
	ret = ops->get_object(CPT_OBJ_NET_BR, pos,
			&bri, sizeof(bri), ctx);
	if (ret)
		goto out;

	dev = alloc_netdev(sizeof(struct net_bridge), di->cpt_name,
			   br_dev_setup);
	if (!dev)
		return -ENOMEM;

	dev_net_set(dev, net);
	br = netdev_priv(dev);

	memcpy(&br->designated_root, &bri.designated_root, 8);
	memcpy(&br->bridge_id, &bri.bridge_id, 8);
	br->root_path_cost = bri.root_path_cost;
	br->max_age = clock_t_to_jiffies(bri.max_age);
	br->hello_time = clock_t_to_jiffies(bri.hello_time);
	br->forward_delay = bri.forward_delay;
	br->bridge_max_age = bri.bridge_max_age;
	br->bridge_hello_time = bri.bridge_hello_time;
	br->bridge_forward_delay = clock_t_to_jiffies(bri.bridge_forward_delay);
	br->ageing_time = clock_t_to_jiffies(bri.ageing_time);
	br->root_port = bri.root_port;
	br->stp_enabled = bri.stp_enabled;
	br->via_phys_dev = bri.via_phys_dev;

	SET_NETDEV_DEVTYPE(dev, &br_type);

	ret = register_netdevice(dev);
	if (ret)
		goto out_free;

	ret = br_rst_nested_dev(pos, &bri, br, ops, ctx);
out:
	return ret;

out_free:
	free_netdev(dev);
	goto out;
}

static void br_cpt_nested_dev(struct net_bridge *br, struct cpt_ops *ops,
			      struct cpt_context *ctx)
{
	struct net_bridge_port *p;

	list_for_each_entry(p, &br->port_list, list) {
		struct cpt_br_nested_dev o;
		loff_t saved_obj;

		ops->push_object(&saved_obj, ctx);

		o.cpt_next = CPT_NULL;
		o.cpt_object = CPT_OBJ_NET_BR_DEV;
		o.cpt_hdrlen = sizeof(o);
		o.cpt_content = CPT_CONTENT_NAME;
		BUILD_BUG_ON(IFNAMSIZ != 16);
		memcpy(o.name, p->dev->name, IFNAMSIZ);

		ops->write(&o, sizeof(o), ctx);

		ops->pop_object(&saved_obj, ctx);
	}


}

static void br_cpt(struct net_device *dev, struct cpt_ops *ops, struct cpt_context *ctx)
{
	struct cpt_br_image v;
	struct net_bridge *br = netdev_priv(dev);

	v.cpt_next = CPT_NULL;
	v.cpt_object = CPT_OBJ_NET_BR;
	v.cpt_hdrlen = sizeof(v);
	v.cpt_content = CPT_CONTENT_VOID;

	memcpy(&v.designated_root, &br->designated_root, 8);
	memcpy(&v.bridge_id, &br->bridge_id, 8);
	v.root_path_cost = br->root_path_cost;
	v.max_age = jiffies_to_clock_t(br->max_age);
	v.hello_time = jiffies_to_clock_t(br->hello_time);
	v.forward_delay = br->forward_delay;
	v.bridge_max_age = br->bridge_max_age;
	v.bridge_hello_time = br->bridge_hello_time;
	v.bridge_forward_delay = jiffies_to_clock_t(br->bridge_forward_delay);
	v.ageing_time = jiffies_to_clock_t(br->ageing_time);
	v.root_port = br->root_port;
	v.stp_enabled = br->stp_enabled;
	v.via_phys_dev = br->via_phys_dev;

	ops->write(&v, sizeof(v), ctx);

	br_cpt_nested_dev(br, ops, ctx);
}

static const struct ethtool_ops br_ethtool_ops = {
	.get_drvinfo    = br_getinfo,
	.get_link	= ethtool_op_get_link,
};

static const struct net_device_ops br_netdev_ops = {
	.ndo_open		 = br_dev_open,
	.ndo_stop		 = br_dev_stop,
	.ndo_init		 = br_dev_init,
	.ndo_start_xmit		 = br_dev_xmit,
	.ndo_set_mac_address	 = br_set_mac_address,
	.ndo_set_multicast_list	 = br_dev_set_multicast_list,
	.ndo_change_mtu		 = br_change_mtu,
	.ndo_do_ioctl		 = br_dev_ioctl,
	.ndo_vlan_rx_register	 = br_vlan_rx_register,
	.ndo_cpt		 = br_cpt,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_netpoll_cleanup	 = br_netpoll_cleanup,
	.ndo_poll_controller	 = br_poll_controller,
#endif
};

static const struct net_device_ops_ext br_netdev_ops_ext = {
	.size			= sizeof(struct net_device_ops_ext),
	.ndo_get_stats64	= br_get_stats64,
	.ndo_fix_features	= br_fix_features,
};

static void br_dev_free(struct net_device *dev)
{
	struct net_bridge *br = netdev_priv(dev);

	free_percpu(br->stats);
	free_netdev(dev);
}

void br_dev_setup(struct net_device *dev)
{
	struct net_bridge *br = netdev_priv(dev);

	eth_hw_addr_random(dev);
	ether_setup(dev);

	dev->netdev_ops = &br_netdev_ops;
	set_netdev_ops_ext(dev, &br_netdev_ops_ext);
#ifdef CONFIG_NET_POLL_CONTROLLER
	netdev_extended(dev)->netpoll_data.ndo_netpoll_setup = br_netpoll_setup;
#endif
	dev->destructor = br_dev_free;
	SET_ETHTOOL_OPS(dev, &br_ethtool_ops);
	SET_NETDEV_DEVTYPE(dev, &br_type);
	dev->tx_queue_len = 0;
	dev->priv_flags = IFF_EBRIDGE;
	netdev_extended(dev)->ext_priv_flags &= ~IFF_TX_SKB_SHARING;

	dev->features = COMMON_FEATURES | NETIF_F_LLTX | NETIF_F_NETNS_LOCAL |
			NETIF_F_HW_VLAN_TX | NETIF_F_HW_VLAN_RX;
	netdev_extended(dev)->hw_features = COMMON_FEATURES | NETIF_F_HW_VLAN_TX | NETIF_F_HW_VLAN_RX;
	dev->vlan_features = COMMON_FEATURES;

	br->dev = dev;
	spin_lock_init(&br->lock);
	INIT_LIST_HEAD(&br->port_list);
	spin_lock_init(&br->hash_lock);

	br->bridge_id.prio[0] = 0x80;
	br->bridge_id.prio[1] = 0x00;

	memcpy(br->group_addr, br_reserved_address, ETH_ALEN);

	br->stp_enabled = BR_NO_STP;
	br->group_fwd_mask = BR_GROUPFWD_DEFAULT;

	br->designated_root = br->bridge_id;
	br->root_path_cost = 0;
	br->root_port = 0;
	br->bridge_max_age = br->max_age = 20 * HZ;
	br->bridge_hello_time = br->hello_time = 2 * HZ;
	br->bridge_forward_delay = br->forward_delay = 15 * HZ;
	br->topology_change = 0;
	br->topology_change_detected = 0;
	br->ageing_time = 300 * HZ;

	br_netfilter_rtable_init(br);

	INIT_LIST_HEAD(&br->age_list);

	br_stp_timer_init(br);
	br_multicast_init(br);
}
