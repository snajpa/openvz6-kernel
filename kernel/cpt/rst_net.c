/*
 *
 *  kernel/cpt/rst_net.c
 *
 *  Copyright (C) 2000-2005  SWsoft
 *  All rights reserved.
 *
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/nsproxy.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/socket.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/rtnetlink.h>
#include <linux/ve.h>
#include <linux/ve_proto.h>
#include <net/route.h>
#include <net/ip_fib.h>
#include <net/addrconf.h>
#include <linux/if_tun.h>
#include <linux/veth.h>
#include <linux/venet.h>
#include <linux/fdtable.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <linux/cpt_export.h>

#include <linux/cpt_obj.h>
#include <linux/cpt_context.h>
#include "cpt_kernel.h"
#include "cpt_net.h"
#include "cpt_files.h"

#include "cpt_syscalls.h"

extern struct in_ifaddr *inet_alloc_ifa(void);
extern int inet_insert_ifa(struct in_ifaddr *ifa);
extern struct in_device *inetdev_init(struct net_device *dev);

int rst_restore_ifaddr(struct cpt_context *ctx)
{
	struct net *net = get_exec_env()->ve_netns;
	int err;
	loff_t sec = ctx->sections[CPT_SECT_NET_IFADDR];
	loff_t endsec;
	struct cpt_section_hdr h;
	struct cpt_ifaddr_image di;
	struct net_device *dev;

	if (sec == CPT_NULL)
		return 0;

	err = ctx->pread(&h, sizeof(h), ctx, sec);
	if (err)
		return err;
	if (h.cpt_section != CPT_SECT_NET_IFADDR || h.cpt_hdrlen < sizeof(h))
		return -EINVAL;

	endsec = sec + h.cpt_next;
	sec += h.cpt_hdrlen;
	while (sec < endsec) {
		int cindex = -1;
		int err;
		err = rst_get_object(CPT_OBJ_NET_IFADDR, sec, &di, ctx);
		if (err)
			return err;
		cindex = di.cpt_index;
		rtnl_lock();
		dev = __dev_get_by_index(net, cindex);
		if (dev && di.cpt_family == AF_INET) {
			struct in_device *in_dev;
			struct in_ifaddr *ifa;
			if ((in_dev = __in_dev_get_rtnl(dev)) == NULL)
				in_dev = inetdev_init(dev);
			ifa = inet_alloc_ifa();
			if (ifa) {
				ifa->ifa_local = di.cpt_address[0];
				ifa->ifa_address = di.cpt_peer[0];
				ifa->ifa_broadcast = di.cpt_broadcast[0];
				ifa->ifa_prefixlen = di.cpt_masklen;
				ifa->ifa_mask = inet_make_mask(ifa->ifa_prefixlen);
				ifa->ifa_flags = di.cpt_flags;
				ifa->ifa_scope = di.cpt_scope;
				memcpy(ifa->ifa_label, di.cpt_label, IFNAMSIZ);
				in_dev_hold(in_dev);
				ifa->ifa_dev   = in_dev;
				err = inet_insert_ifa(ifa);
				if (err && err != -EEXIST) {
					rtnl_unlock();
					eprintk_ctx("add ifaddr err %d for %d %s\n", err, di.cpt_index, di.cpt_label);
					return err;
				}
			}
#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
		} else if (dev && di.cpt_family == AF_INET6) {
			__u32 prefered_lft;
			__u32 valid_lft;
			struct net *net = get_exec_env()->ve_ns->net_ns;

			if (!ipv6_is_enabled()) {
				rtnl_unlock();
				eprintk_ctx("IPv6 is disabled\n");
				return -ENOTSUPP;
			}

			prefered_lft = (di.cpt_flags & IFA_F_DEPRECATED) ?
				0 : di.cpt_prefered_lft;
			valid_lft = (di.cpt_flags & IFA_F_PERMANENT) ?
				0xFFFFFFFF : di.cpt_valid_lft;
			err = inet6_addr_add(net, dev->ifindex,
					     (struct in6_addr *)di.cpt_address,
					     di.cpt_masklen, 0,
					     prefered_lft,
					     valid_lft);
			if (err && err != -EEXIST) {
				rtnl_unlock();
				eprintk_ctx("add ifaddr6 err %d for %d %s\n", err, di.cpt_index, di.cpt_label);
				return err;
			}
#endif
		} else {
			rtnl_unlock();
			eprintk_ctx("unknown ifaddr 2 for %d\n", di.cpt_index);
			return -EINVAL;
		}
		rtnl_unlock();
		sec += di.cpt_next;
	}
	return 0;
}

static int rewrite_rtmsg(struct nlmsghdr *nlh, struct cpt_context *ctx)
{
	int min_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	struct rtmsg *rtm = NLMSG_DATA(nlh);
	__u32 prefix0 = 0;

	if (nlh->nlmsg_len > min_len) {
		int attrlen = nlh->nlmsg_len - NLMSG_ALIGN(min_len);
		struct rtattr *rta = (void*)nlh + NLMSG_ALIGN(min_len);

		while (RTA_OK(rta, attrlen)) {
			if (rta->rta_type == RTA_DST) {
				prefix0 = *(__u32*)RTA_DATA(rta);
			}
			rta = RTA_NEXT(rta, attrlen);
		}
	}
#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
	if (rtm->rtm_family == AF_INET6) {
		if (rtm->rtm_type == RTN_LOCAL)
			return 2;
		if (rtm->rtm_flags & RTM_F_CLONED)
			return 2;
		if (rtm->rtm_protocol == RTPROT_UNSPEC ||
		    rtm->rtm_protocol == RTPROT_RA ||
		    rtm->rtm_protocol == RTPROT_REDIRECT ||
		    rtm->rtm_protocol == RTPROT_KERNEL)
			return 2;
		if (rtm->rtm_protocol == RTPROT_BOOT &&
		    ((rtm->rtm_dst_len == 8 && prefix0 == htonl(0xFF000000)) ||
		     (rtm->rtm_dst_len == 64 && prefix0 == htonl(0xFE800000))))
			return 2;
	}
#endif
	return rtm->rtm_protocol == RTPROT_KERNEL;
}

int rst_restore_route(struct cpt_context *ctx)
{
	int err;
	struct socket *sock;
	struct msghdr msg;
	struct iovec iov;
	struct sockaddr_nl nladdr;
	mm_segment_t oldfs;
	loff_t sec = ctx->sections[CPT_SECT_NET_ROUTE];
	loff_t endsec;
	struct cpt_section_hdr h;
	struct cpt_object_hdr v;
	char *pg;

	if (sec == CPT_NULL)
		return 0;

	err = ctx->pread(&h, sizeof(h), ctx, sec);
	if (err)
		return err;
	if (h.cpt_section != CPT_SECT_NET_ROUTE || h.cpt_hdrlen < sizeof(h))
		return -EINVAL;

	if (h.cpt_hdrlen >= h.cpt_next)
		return 0;

	sec += h.cpt_hdrlen;
	err = rst_get_object(CPT_OBJ_NET_ROUTE, sec, &v, ctx);
	if (err < 0)
		return err;

	err = sock_create(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE, &sock);
	if (err)
		return err;

	pg = (char*)__get_free_page(GFP_KERNEL);
	if (pg == NULL) {
		err = -ENOMEM;
		goto out_sock;
	}

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;

	endsec = sec + v.cpt_next;
	sec += v.cpt_hdrlen;

	while (sec < endsec) {
		struct nlmsghdr *n;
		struct nlmsghdr nh;
		int kernel_flag;

		if (endsec - sec < sizeof(nh))
			break;

		err = ctx->pread(&nh, sizeof(nh), ctx, sec);
		if (err)
			goto out_sock_pg;
		if (nh.nlmsg_len < sizeof(nh) || nh.nlmsg_len > PAGE_SIZE ||
		    endsec - sec < nh.nlmsg_len) {
			err = -EINVAL;
			goto out_sock_pg;
		}
		err = ctx->pread(pg, nh.nlmsg_len, ctx, sec);
		if (err)
			goto out_sock_pg;

		n = (struct nlmsghdr*)pg;
		n->nlmsg_flags = NLM_F_REQUEST|NLM_F_APPEND|NLM_F_CREATE;

		err = rewrite_rtmsg(n, ctx);
		if (err < 0)
			goto out_sock_pg;
		kernel_flag = err;

		if (kernel_flag == 2)
			goto do_next;

		iov.iov_base=n;
		iov.iov_len=nh.nlmsg_len;
		msg.msg_name=&nladdr;
		msg.msg_namelen=sizeof(nladdr);
		msg.msg_iov=&iov;
		msg.msg_iovlen=1;
		msg.msg_control=NULL;
		msg.msg_controllen=0;
		msg.msg_flags=MSG_DONTWAIT;

		oldfs = get_fs(); set_fs(KERNEL_DS);
		err = sock_sendmsg(sock, &msg, nh.nlmsg_len);
		set_fs(oldfs);

		if (err < 0)
			goto out_sock_pg;
		err = 0;

		iov.iov_base=pg;
		iov.iov_len=PAGE_SIZE;

		oldfs = get_fs(); set_fs(KERNEL_DS);
		err = sock_recvmsg(sock, &msg, PAGE_SIZE, MSG_DONTWAIT);
		set_fs(oldfs);
		if (err != -EAGAIN) {
			if (n->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *e = NLMSG_DATA(n);
				if (e->error != -EEXIST || !kernel_flag)
					eprintk_ctx("NLMERR: %d\n", e->error);
			} else {
				eprintk_ctx("Res: %d %d\n", err, n->nlmsg_type);
			}
		}
do_next:
		err = 0;
		sec += NLMSG_ALIGN(nh.nlmsg_len);
	}

out_sock_pg:
	free_page((unsigned long)pg);
out_sock:
	sock_release(sock);
	return err;
}

int rst_resume_network(struct cpt_context *ctx)
{
	struct ve_struct *env;

	env = get_ve_by_id(ctx->ve_id);
	if (!env)
		return -ESRCH;
	env->disable_net = 0;
	put_ve(env);
	return 0;
}

static int rst_restore_netstats(loff_t pos, struct net_device *dev,
			struct cpt_context * ctx)
{
	struct cpt_netstats_image *n;
	struct net_device_stats *stats;
	int err;

	if (dev->netdev_ops->ndo_cpt == NULL) {
		err = -ENODEV;
		eprintk_ctx("Network device %s is not supported\n", dev->name);
		return err;
	}

	n = cpt_get_buf(ctx);
	err = rst_get_object(CPT_OBJ_NET_STATS, pos, n, ctx);
	if (err)
		goto out;
	BUG_ON(sizeof(struct cpt_netstats_image) != n->cpt_hdrlen);
	preempt_disable();

	stats = &dev->s_stats;

	stats->rx_packets = n->cpt_rx_packets;
	stats->tx_packets = n->cpt_tx_packets;
	stats->rx_bytes = n->cpt_rx_bytes;
	stats->tx_bytes = n->cpt_tx_bytes;
	stats->rx_errors = n->cpt_rx_errors;
	stats->tx_errors = n->cpt_tx_errors;
	stats->rx_dropped = n->cpt_rx_dropped;
	stats->tx_dropped = n->cpt_tx_dropped;
	stats->multicast = n->cpt_multicast;
	stats->collisions = n->cpt_collisions;
	stats->rx_length_errors = n->cpt_rx_length_errors;
	stats->rx_over_errors = n->cpt_rx_over_errors;
	stats->rx_crc_errors = n->cpt_rx_crc_errors;
	stats->rx_frame_errors = n->cpt_rx_frame_errors;
	stats->rx_fifo_errors = n->cpt_rx_fifo_errors;
	stats->rx_missed_errors = n->cpt_rx_missed_errors;
	stats->tx_aborted_errors = n->cpt_tx_aborted_errors;
	stats->tx_carrier_errors = n->cpt_tx_carrier_errors;
	stats->tx_fifo_errors = n->cpt_tx_fifo_errors;
	stats->tx_heartbeat_errors = n->cpt_tx_heartbeat_errors;
	stats->tx_window_errors = n->cpt_tx_window_errors;
	stats->rx_compressed = n->cpt_rx_compressed;
	stats->tx_compressed = n->cpt_tx_compressed;

	preempt_enable();
out:
	cpt_release_buf(ctx);
	return err;
}

static int rst_restore_idev_cnf(loff_t pos, struct net_device *dev,
			struct cpt_context *ctx)
{
	struct cpt_idev_cnf_image *d;
	struct in_device *in_dev;
	int err;

	d = cpt_get_buf(ctx);
	err = rst_get_object(CPT_OBJ_NET_IDEV_CNF, pos, d, ctx);
	if (err)
		goto out;

	if ((in_dev = __in_dev_get_rtnl(dev)) == NULL)
		if ((in_dev = inetdev_init(dev)) == NULL) {
			err = -ENOMEM;
			goto out;
		}

	memcpy(in_dev->cnf.data, d->cpt_data, sizeof(d->cpt_data));
out:
	cpt_release_buf(ctx);
	return err;
}

int rst_restore_netdev(struct cpt_context *ctx)
{
	struct net *net = get_exec_env()->ve_netns;
	int err;
	loff_t sec = ctx->sections[CPT_SECT_NET_DEVICE];
	loff_t endsec;
	struct cpt_section_hdr h;
	struct cpt_netdev_image di;
	struct net_device *dev;

	get_exec_env()->disable_net = 1;

	if (sec == CPT_NULL)
		return 0;

	err = ctx->pread(&h, sizeof(h), ctx, sec);
	if (err)
		return err;
	if (h.cpt_section != CPT_SECT_NET_DEVICE || h.cpt_hdrlen < sizeof(h))
		return -EINVAL;

	endsec = sec + h.cpt_next;
	sec += h.cpt_hdrlen;
	while (sec < endsec) {
		loff_t pos;
		struct net_device *dev_new;
		struct netdev_rst *ops;

		err = rst_get_object(CPT_OBJ_NET_DEVICE, sec, &di, ctx);
		if (err)
			return err;

		rtnl_lock();
		pos = sec + di.cpt_hdrlen;
		if (di.cpt_next > sizeof(di)) {
			struct cpt_object_hdr hdr;
			err = ctx->pread(&hdr, sizeof(struct cpt_object_hdr),
					ctx, sec + di.cpt_hdrlen);
			if (err)
				goto out;

			ops = NULL;
			while (1) {
				ops = netdev_find_rst(hdr.cpt_object, ops);
				if (ops == NULL)
					break;

				err = ops->ndo_rst(sec, &di, &rst_ops, ctx);
				if (!err) {
					pos += hdr.cpt_next;
					break;
				} else if (err < 0) {
					eprintk_ctx("netdev %d rst failed %d\n",
							hdr.cpt_object, err);
					goto out;
				}
			}
		}

		dev = __dev_get_by_name(net, di.cpt_name);
		if (dev) {
			if (dev->ifindex != di.cpt_index) {
				dev_new = __dev_get_by_index(net, di.cpt_index);
				if (!dev_new) {
					write_lock_bh(&dev_base_lock);
					hlist_del(&dev->index_hlist);
					if (dev->iflink == dev->ifindex)
						dev->iflink = di.cpt_index;
					dev->ifindex = di.cpt_index;
					hlist_add_head(&dev->index_hlist,
							dev_index_hash(net, dev->ifindex));
					write_unlock_bh(&dev_base_lock);
				} else {
					write_lock_bh(&dev_base_lock);
					hlist_del(&dev->index_hlist);
					hlist_del(&dev_new->index_hlist);
					if (dev_new->iflink == dev_new->ifindex)
						dev_new->iflink = dev->ifindex;
					dev_new->ifindex = dev->ifindex;
					if (dev->iflink == dev->ifindex)
						dev->iflink = di.cpt_index;
					dev->ifindex = di.cpt_index;
					hlist_add_head(&dev->index_hlist,
							dev_index_hash(net, dev->ifindex));
					hlist_add_head(&dev_new->index_hlist,
							dev_index_hash(net, dev_new->ifindex));
					write_unlock_bh(&dev_base_lock);
				}
			}
			if (di.cpt_flags^dev->flags) {
				err = dev_change_flags(dev, di.cpt_flags);
				if (err)
					eprintk_ctx("dev_change_flags err: %d\n", err);
			}
			if (cpt_object_has(&di, cpt_mtu))
				dev->mtu = di.cpt_mtu;
			while (pos < sec + di.cpt_next) {
				struct cpt_object_hdr hdr;
				err = ctx->pread(&hdr, sizeof(struct cpt_object_hdr),
						ctx, pos);
				if (err)
					goto out;
				if (hdr.cpt_object == CPT_OBJ_NET_HWADDR) {
					/* Restore hardware address */
					struct cpt_hwaddr_image hw;
					err = rst_get_object(CPT_OBJ_NET_HWADDR,
							pos, &hw, ctx);
					if (err)
						goto out;
					BUILD_BUG_ON(sizeof(hw.cpt_dev_addr) !=
							MAX_ADDR_LEN);
					memcpy(dev->dev_addr, hw.cpt_dev_addr,
							sizeof(hw.cpt_dev_addr));
				} else if (hdr.cpt_object == CPT_OBJ_NET_STATS) {
					err = rst_restore_netstats(pos, dev, ctx);
					if (err) {
						eprintk_ctx("rst stats %s: %d\n",
								di.cpt_name, err);
						goto out;
					}
				} else if (hdr.cpt_object == CPT_OBJ_NET_IDEV_CNF) {
					err = rst_restore_idev_cnf(pos, dev, ctx);
					if (err) {
						eprintk_ctx("rst idev config %s: %d\n",
						di.cpt_name, err);
						goto out;
					}
				}
				pos += hdr.cpt_next;
			}
		} else {
			eprintk_ctx("unknown interface 2 %s\n", di.cpt_name);
		}
		rtnl_unlock();
		sec += di.cpt_next;
	}
	return 0;
out:
	rtnl_unlock();
	return err;
}

struct args_t
{
	int *pfd;
	bool is_ipv6;
};

static int dumpfn(void *arg)
{
	int i;
	struct args_t *args = arg;
	int *pfd = args->pfd;
	char *argv[] = { "iptables-restore", "-c", NULL };
	const char *path1, *path2;

	if (!args->is_ipv6) {
		path1 = "/sbin/iptables-restore";
		path2 = "/usr/sbin/iptables-restore";
	} else {
		argv[0] = "ip6tables-restore";
		path1 = "/sbin/ip6tables-restore";
		path2 = "/usr/sbin/ip6tables-restore";
	}

	if (pfd[0] != 0)
		sc_dup2(pfd[0], 0);

	for (i=1; i<current->files->fdt->max_fds; i++)
		sc_close(i);

	module_put(THIS_MODULE);

	set_fs(KERNEL_DS);
	i = kernel_execve(path1, argv, NULL);
	if (i == -ENOENT)
		i = kernel_execve(path2, argv, NULL);
	eprintk("failed to exec %s: %d\n", argv[0], i);
	return 255 << 8;
}

static int rst_restore_xtables(struct cpt_context *ctx, loff_t *pos)
{
	int err;
	int pfd[2];
	struct file *f;
	struct cpt_object_hdr v;
	int n;
	loff_t end;
	int pid;
	int status;
	mm_segment_t oldfs;
	sigset_t ignore, blocked;
	struct args_t args;

	err = rst_get_object(CPT_OBJ_NAME, *pos, &v, ctx);
	if (err < 0)
		return err;

	err = sc_pipe(pfd);
	if (err < 0)
		return err;
	args.pfd = pfd;
	args.is_ipv6 = (v.cpt_content == CPT_CONTENT_NAME ? false : true);
	ignore.sig[0] = CPT_SIG_IGNORE_MASK;
	sigprocmask(SIG_BLOCK, &ignore, &blocked);
	pid = err = local_kernel_thread(dumpfn, (void*)&args, SIGCHLD, 0);
	if (err < 0) {
		eprintk_ctx("iptables local_kernel_thread: %d\n", err);
		goto out;
	}
	f = fget(pfd[1]);
	sc_close(pfd[1]);
	sc_close(pfd[0]);

	ctx->file->f_pos = *pos + v.cpt_hdrlen;
	end = *pos + v.cpt_next;
	do {
		char *p;
		char buf[16];

		n = end - ctx->file->f_pos;
		if (n > sizeof(buf))
			n = sizeof(buf);

		if (ctx->read(buf, n, ctx))
			break;
		if ((p = memchr(buf, 0, n)) != NULL)
			n = p - buf;
		oldfs = get_fs(); set_fs(KERNEL_DS);
		f->f_op->write(f, buf, n, &f->f_pos);
		set_fs(oldfs);
	} while (ctx->file->f_pos < end);

	fput(f);

	oldfs = get_fs(); set_fs(KERNEL_DS);
	if ((err = sc_waitx(pid, 0, &status)) < 0)
		eprintk_ctx("wait4: %d\n", err);
	else if ((status & 0x7f) == 0) {
		err = (status & 0xff00) >> 8;
		if (err != 0) {
			eprintk_ctx("iptables-restore exited with %d\n", err);
			eprintk_ctx("Most probably some iptables modules are not loaded\n");
			eprintk_ctx("or CT's iptables utilities are incompatible with this kernel (version is older than 1.4.0)\n");
			eprintk_ctx("(Offline migration and iptools upgrade might help).\n");
			err = -EINVAL;
		}
	} else {
		eprintk_ctx("iptables-restore terminated\n");
		err = -EINVAL;
	}
	set_fs(oldfs);
	sigprocmask(SIG_SETMASK, &blocked, NULL);

	*pos = end;

	return err;

out:
	if (pfd[1] >= 0)
		sc_close(pfd[1]);
	if (pfd[0] >= 0)
		sc_close(pfd[0]);
	sigprocmask(SIG_SETMASK, &blocked, NULL);
	return err;
}

static int rst_restore_iptables(struct cpt_context *ctx)
{
	loff_t sec = ctx->sections[CPT_SECT_NET_IPTABLES];
	struct cpt_section_hdr h;
	loff_t pos;
	int err;

	if (sec == CPT_NULL)
		return 0;

	err = ctx->pread(&h, sizeof(h), ctx, sec);
	if (err)
		return err;
	if (h.cpt_section != CPT_SECT_NET_IPTABLES || h.cpt_hdrlen < sizeof(h))
		return -EINVAL;

	if (h.cpt_hdrlen == h.cpt_next)
		return 0;
	if (h.cpt_hdrlen > h.cpt_next)
		return -EINVAL;
	pos = sec + h.cpt_hdrlen;

	err = rst_restore_xtables(ctx, &pos);
	if (err)
		return err;
	else if (pos == sec + h.cpt_next)
		return 0;

	return rst_restore_xtables(ctx, &pos);
}

static int rst_restore_snmp_stat(struct cpt_context *ctx, void *mib[], int n,
		loff_t *ppos, loff_t endpos)
{
	int err, in, i;
	struct cpt_object_hdr o;
	__u32 *stats;

	err = rst_get_object(CPT_OBJ_BITS, *ppos, &o, ctx);
	if (err)
		return err;

	in = o.cpt_next - o.cpt_hdrlen;
	if (in >= PAGE_SIZE - 4) {
		eprintk_ctx("Too long SNMP buf (%d)\n", in);
		return -EINVAL;
	}

	if (o.cpt_content != CPT_CONTENT_DATA) {
		if (o.cpt_content == CPT_CONTENT_VOID)
			return 1;

		eprintk_ctx("Corrupted SNMP stats\n");
		return -EINVAL;
	}

	stats = cpt_get_buf(ctx);
	err = ctx->pread(stats, in, ctx, (*ppos) + o.cpt_hdrlen);
	if (err)
		goto out;
	/*
	 * IPv6 can be not loaded or disabled.
	 */
	if (mib[0] == NULL)
		goto out;

	in /= sizeof(*stats);
	if (in > n)
		wprintk_ctx("SNMP stats trimmed\n");
	else
		n = in;

	for (i = 0; i < n; i++)
		*((unsigned long *)(per_cpu_ptr(mib[0], 0)) + i) = stats[i];

	*ppos += o.cpt_next;
	if (*ppos < endpos)
		err = 1; /* go on restoring */
out:
	cpt_release_buf(ctx);
	return err;
}

static int rst_restore_snmp(struct cpt_context *ctx)
{
	int err;
	loff_t sec = ctx->sections[CPT_SECT_SNMP_STATS];
	loff_t endsec;
	struct cpt_section_hdr h;
	struct ve_struct *ve;
	struct net *net;

	if (sec == CPT_NULL)
		return 0;

	err = ctx->pread(&h, sizeof(h), ctx, sec);
	if (err)
		return err;
	if (h.cpt_section != CPT_SECT_SNMP_STATS || h.cpt_hdrlen < sizeof(h))
		return -EINVAL;

	ve = get_exec_env();
	net = ve->ve_netns;
	endsec = sec + h.cpt_next;
	sec += h.cpt_hdrlen;
	if (sec >= endsec)
		goto out;

	err = rst_restore_snmp_stat(ctx, (void **)&net->mib.net_statistics,
			LINUX_MIB_MAX, &sec, endsec);
	if (err <= 0)
		goto out;
	err = rst_restore_snmp_stat(ctx, (void **)&net->mib.ip_statistics,
			IPSTATS_MIB_MAX, &sec, endsec);
	if (err <= 0)
		goto out;
	err = rst_restore_snmp_stat(ctx, (void **)&net->mib.tcp_statistics,
			TCP_MIB_MAX, &sec, endsec);
	if (err <= 0)
		goto out;
	err = rst_restore_snmp_stat(ctx, (void **)&net->mib.udp_statistics,
			UDP_MIB_MAX, &sec, endsec);
	if (err <= 0)
		goto out;
	err = rst_restore_snmp_stat(ctx, (void **)&net->mib.icmp_statistics,
			ICMP_MIB_MAX, &sec, endsec);
	if (err <= 0)
		goto out;
	err = rst_restore_snmp_stat(ctx, (void **)&net->mib.icmpmsg_statistics,
			ICMPMSG_MIB_MAX, &sec, endsec);
	if (err <= 0)
		goto out;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	err = rst_restore_snmp_stat(ctx, (void **)&net->mib.ipv6_statistics,
			IPSTATS_MIB_MAX, &sec, endsec);
	if (err <= 0)
		goto out;
	err = rst_restore_snmp_stat(ctx, (void **)&net->mib.udp_stats_in6,
			UDP_MIB_MAX, &sec, endsec);
	if (err <= 0)
		goto out;
	err = rst_restore_snmp_stat(ctx, (void **)&net->mib.icmpv6_statistics,
			ICMP6_MIB_MAX, &sec, endsec);
#endif
	if (err == 1)
		err = 0;
out:
	return err;
}

int rst_restore_net(struct cpt_context *ctx)
{
	int err;

	err = rst_restore_netdev(ctx);
	if (!err)
		err = rst_restore_ifaddr(ctx);
	if (!err)
		err = rst_restore_route(ctx);
	if (!err)
		err = rst_restore_iptables(ctx);
	if (!err)
		err = rst_restore_ip_conntrack(ctx);
	if (!err)
		err = rst_restore_snmp(ctx);
	return err;
}
