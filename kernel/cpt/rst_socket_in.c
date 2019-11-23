/*
 *
 *  kernel/cpt/rst_socket_in.c
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
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <linux/jhash.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <linux/ipv6.h>
#include <linux/igmp.h>
#include <net/addrconf.h>
#include <net/inet6_connection_sock.h>
#include <linux/nsproxy.h>

#include <linux/cpt_obj.h>
#include <linux/cpt_context.h>
#include "cpt_mm.h"
#include "cpt_socket.h"
#include "cpt_kernel.h"

static inline unsigned long jiffies_import(__u32 tmo)
{
	__s32 delta = tmo;
	return jiffies + (long)delta;
}

static inline __u32 tcp_jiffies_import(__u32 tmo)
{
	return ((__u32)jiffies) + tmo;
}


static int restore_queues(struct sock *sk, struct cpt_sock_image *si,
			  loff_t pos, struct cpt_context *ctx)
{
	loff_t endpos;

	endpos = pos + si->cpt_next;
	pos = pos + si->cpt_hdrlen;
	while (pos < endpos) {
		struct sk_buff *skb;
		__u32 type;
		int err;

		err = rst_sock_attr(&pos, sk, ctx);
		if (!err)
			continue;
		if (err < 0)
			return err;

		skb = rst_skb(sk, &pos, NULL, &type, ctx);
		if (IS_ERR(skb))
			return PTR_ERR(skb);

		if (sk->sk_type == SOCK_STREAM) {
			if (type == CPT_SKB_RQ) {
				skb_set_owner_r(skb, sk);
				ub_tcprcvbuf_charge_forced(sk, skb);
				skb_queue_tail(&sk->sk_receive_queue, skb);
			} else if (type == CPT_SKB_OFOQ) {
				struct tcp_sock *tp = tcp_sk(sk);
				skb_set_owner_r(skb, sk);
				ub_tcprcvbuf_charge_forced(sk, skb);
				tcp_rbtree_insert(&tp->out_of_order_queue, skb);
				tp->ooo_last_skb = skb;
			} else if (type == CPT_SKB_WQ) {
				sk->sk_wmem_queued += skb->truesize;
				sk->sk_forward_alloc -= skb->truesize;
				ub_tcpsndbuf_charge_forced(sk, skb);
				skb_queue_tail(&sk->sk_write_queue, skb);
			} else {
				wprintk_ctx("strange stream queue type %u\n", type);
				kfree_skb(skb);
			}
		} else {
			if (type == CPT_SKB_RQ) {
				skb_set_owner_r(skb, sk);
				skb_queue_tail(&sk->sk_receive_queue, skb);
			} else if (type == CPT_SKB_WQ) {
				struct inet_sock *inet = inet_sk(sk);
				if (inet->cork.fragsize) {
					skb_set_owner_w(skb, sk);
					skb_queue_tail(&sk->sk_write_queue, skb);
				} else {
					eprintk_ctx("cork skb is dropped\n");
					kfree_skb(skb);
				}
			} else {
				wprintk_ctx("strange dgram queue type %u\n", type);
				kfree_skb(skb);
			}
		}
	}
	return 0;
}

static struct sock *find_parent(__u16 sport, cpt_context_t *ctx)
{
	cpt_object_t *obj;
	for_each_object(obj, CPT_OBJ_SOCKET) {
		struct sock *sk = obj->o_obj;
		if (sk &&
		    sk->sk_state == TCP_LISTEN &&
		    (sk->sk_family == AF_INET || sk->sk_family == AF_INET6) &&
		    inet_sk(sk)->sport == sport)
			return sk;
	}
	return NULL;
}

static int rst_socket_tcp(struct cpt_sock_image *si, loff_t pos, struct sock *sk,
			  struct cpt_context *ctx)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	tp->pred_flags = si->cpt_pred_flags;
	tp->rcv_nxt = si->cpt_rcv_nxt;
	tp->snd_nxt = si->cpt_snd_nxt;
	tp->snd_una = si->cpt_snd_una;
	tp->snd_sml = si->cpt_snd_sml;
	tp->rcv_tstamp = tcp_jiffies_import(si->cpt_rcv_tstamp);
	tp->lsndtime = tcp_jiffies_import(si->cpt_lsndtime);
	tp->tcp_header_len = si->cpt_tcp_header_len;
	inet_csk(sk)->icsk_ack.pending = si->cpt_ack_pending;
	inet_csk(sk)->icsk_ack.quick = si->cpt_quick;
	inet_csk(sk)->icsk_ack.pingpong = si->cpt_pingpong;
	inet_csk(sk)->icsk_ack.blocked = si->cpt_blocked;
	inet_csk(sk)->icsk_ack.ato = si->cpt_ato;
	inet_csk(sk)->icsk_ack.timeout = jiffies_import(si->cpt_ack_timeout);
	inet_csk(sk)->icsk_ack.lrcvtime = tcp_jiffies_import(si->cpt_lrcvtime);
	inet_csk(sk)->icsk_ack.last_seg_size = si->cpt_last_seg_size;
	inet_csk(sk)->icsk_ack.rcv_mss = si->cpt_rcv_mss;
	tp->snd_wl1 = si->cpt_snd_wl1;
	tp->snd_wnd = si->cpt_snd_wnd;
	tp->max_window = si->cpt_max_window;
	inet_csk(sk)->icsk_pmtu_cookie = si->cpt_pmtu_cookie;
	tp->mss_cache = si->cpt_mss_cache;
	tp->rx_opt.mss_clamp = si->cpt_mss_clamp;
	inet_csk(sk)->icsk_ext_hdr_len = si->cpt_ext_header_len;
	inet_csk(sk)->icsk_ca_state = si->cpt_ca_state;
	inet_csk(sk)->icsk_retransmits = si->cpt_retransmits;
	tp->reordering = si->cpt_reordering;
	tp->frto_counter = si->cpt_frto_counter;
	tp->frto_highmark = si->cpt_frto_highmark;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
	// // tp->adv_cong = si->cpt_adv_cong;
#endif
	inet_csk(sk)->icsk_accept_queue.rskq_defer_accept = si->cpt_defer_accept;
	inet_csk(sk)->icsk_backoff = si->cpt_backoff;
	tp->srtt = si->cpt_srtt;
	tp->mdev = si->cpt_mdev;
	tp->mdev_max = si->cpt_mdev_max;
	tp->rttvar = si->cpt_rttvar;
	tp->rtt_seq = si->cpt_rtt_seq;
	inet_csk(sk)->icsk_rto = si->cpt_rto;
	tp->packets_out = si->cpt_packets_out;
	tp->retrans_out = si->cpt_retrans_out;
	tp->lost_out = si->cpt_lost_out;
	tp->sacked_out = si->cpt_sacked_out;
	tp->fackets_out = si->cpt_fackets_out;
	tp->snd_ssthresh = si->cpt_snd_ssthresh;
	tp->snd_cwnd = si->cpt_snd_cwnd;
	tp->snd_cwnd_cnt = si->cpt_snd_cwnd_cnt;
	tp->snd_cwnd_clamp = si->cpt_snd_cwnd_clamp;
	tp->snd_cwnd_used = si->cpt_snd_cwnd_used;
	tp->snd_cwnd_stamp = tcp_jiffies_import(si->cpt_snd_cwnd_stamp);
	inet_csk(sk)->icsk_timeout = tcp_jiffies_import(si->cpt_timeout);
	tp->rcv_wnd = si->cpt_rcv_wnd;
	tp->rcv_wup = si->cpt_rcv_wup;
	tp->write_seq = si->cpt_write_seq;
	tp->pushed_seq = si->cpt_pushed_seq;
	tp->copied_seq = si->cpt_copied_seq;
	tp->rx_opt.tstamp_ok = si->cpt_tstamp_ok;
	tp->rx_opt.wscale_ok = si->cpt_wscale_ok;
	tp->rx_opt.sack_ok = si->cpt_sack_ok;
	tp->rx_opt.saw_tstamp = si->cpt_saw_tstamp;
	tp->rx_opt.snd_wscale = si->cpt_snd_wscale;
	tp->rx_opt.rcv_wscale = si->cpt_rcv_wscale;
	tp->nonagle = si->cpt_nonagle;
	tp->keepalive_probes = si->cpt_keepalive_probes;
	tp->rx_opt.rcv_tsval = si->cpt_rcv_tsval;
	tp->rx_opt.rcv_tsecr = si->cpt_rcv_tsecr;
	tp->rx_opt.ts_recent = si->cpt_ts_recent;
	tp->rx_opt.ts_recent_stamp = si->cpt_ts_recent_stamp;
	tp->rx_opt.user_mss = si->cpt_user_mss;
	tp->rx_opt.dsack = si->cpt_dsack;
	tp->duplicate_sack[0].start_seq = si->cpt_sack_array[0];
	tp->duplicate_sack[0].end_seq = si->cpt_sack_array[1];
	tp->selective_acks[0].start_seq = si->cpt_sack_array[2];
	tp->selective_acks[0].end_seq = si->cpt_sack_array[3];
	tp->selective_acks[1].start_seq = si->cpt_sack_array[4];
	tp->selective_acks[1].end_seq = si->cpt_sack_array[5];
	tp->selective_acks[2].start_seq = si->cpt_sack_array[6];
	tp->selective_acks[2].end_seq = si->cpt_sack_array[7];
	tp->selective_acks[3].start_seq = si->cpt_sack_array[8];
	tp->selective_acks[3].end_seq = si->cpt_sack_array[9];

	tp->window_clamp = si->cpt_window_clamp;
	tp->rcv_ssthresh = si->cpt_rcv_ssthresh;
	inet_csk(sk)->icsk_probes_out = si->cpt_probes_out;
	tp->rx_opt.num_sacks = si->cpt_num_sacks;
	tp->advmss = si->cpt_advmss;
	inet_csk(sk)->icsk_syn_retries = si->cpt_syn_retries;
	tp->ecn_flags = si->cpt_ecn_flags;
	tp->prior_ssthresh = si->cpt_prior_ssthresh;
	tp->high_seq = si->cpt_high_seq;
	tp->retrans_stamp = si->cpt_retrans_stamp;
	tp->undo_marker = si->cpt_undo_marker;
	tp->undo_retrans = si->cpt_undo_retrans;
	tp->urg_seq = si->cpt_urg_seq;
	tp->urg_data = si->cpt_urg_data;
	inet_csk(sk)->icsk_pending = si->cpt_pending;
	tp->snd_up = si->cpt_snd_up;
	tp->keepalive_time = si->cpt_keepalive_time;
	tp->keepalive_intvl = si->cpt_keepalive_intvl;
	tp->linger2 = si->cpt_linger2;

	sk->sk_send_head = NULL;
	for (skb = skb_peek(&sk->sk_write_queue);
	     skb && skb != (struct sk_buff*)&sk->sk_write_queue;
	     skb = skb->next) {
		if (!after(tp->snd_nxt, TCP_SKB_CB(skb)->seq)) {
			sk->sk_send_head = skb;
			break;
		}
	}

	if (sk->sk_state != TCP_CLOSE && sk->sk_state != TCP_LISTEN) {
		struct inet_sock *inet = inet_sk(sk);
		if (inet->num == 0) {
			cpt_object_t *lobj = NULL;

			if ((int)si->cpt_parent != -1)
				lobj = lookup_cpt_obj_byindex(CPT_OBJ_SOCKET, si->cpt_parent, ctx);

			if (lobj && lobj->o_obj) {
				inet->num = ntohs(inet->sport);
				local_bh_disable();
				__inet_inherit_port(lobj->o_obj, sk);
				local_bh_enable();
				dprintk_ctx("port inherited from parent\n");
			} else {
				struct sock *lsk = find_parent(inet->sport, ctx);
				if (lsk) {
					inet->num = ntohs(inet->sport);
					local_bh_disable();
					__inet_inherit_port(lsk, sk);
					local_bh_enable();
					dprintk_ctx("port inherited\n");
				} else {
					eprintk_ctx("we are kinda lost...\n");
				}
			}
		}

		sk->sk_prot->hash(sk);

		if (inet_csk(sk)->icsk_ack.pending&ICSK_ACK_TIMER)
			sk_reset_timer(sk, &inet_csk(sk)->icsk_delack_timer, inet_csk(sk)->icsk_ack.timeout);
		if (inet_csk(sk)->icsk_pending && !skb_queue_empty(&sk->sk_write_queue))
			sk_reset_timer(sk, &inet_csk(sk)->icsk_retransmit_timer,
				       inet_csk(sk)->icsk_timeout);
		if (sock_flag(sk, SOCK_KEEPOPEN)) {
			unsigned long expires = jiffies_import(si->cpt_ka_timeout);
			if (time_after(jiffies, expires))
				expires = jiffies + HZ;
			sk_reset_timer(sk, &sk->sk_timer, expires);
		}
	}

	if (sk->sk_family == AF_INET6)
		sk->sk_gso_type = SKB_GSO_TCPV6;
	else
		sk->sk_gso_type = SKB_GSO_TCPV4;

	return 0;
}

static void rst_listen_socket_tcp(struct cpt_sock_image *si, struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tp->rcv_tstamp = tcp_jiffies_import(si->cpt_rcv_tstamp);
	tp->lsndtime = tcp_jiffies_import(si->cpt_lsndtime);
	tp->tcp_header_len = si->cpt_tcp_header_len;
	inet_csk(sk)->icsk_accept_queue.rskq_defer_accept = si->cpt_defer_accept;

	/* Next options are inherited by children */
	tp->mss_cache = si->cpt_mss_cache;
	inet_csk(sk)->icsk_ext_hdr_len = si->cpt_ext_header_len;
	tp->reordering = si->cpt_reordering;
	tp->nonagle = si->cpt_nonagle;
	tp->keepalive_probes = si->cpt_keepalive_probes;
	tp->rx_opt.user_mss = si->cpt_user_mss;
	inet_csk(sk)->icsk_syn_retries = si->cpt_syn_retries;
	tp->keepalive_time = si->cpt_keepalive_time;
	tp->keepalive_intvl = si->cpt_keepalive_intvl;
	tp->linger2 = si->cpt_linger2;
}

int rst_listen_socket_in( struct sock *sk, struct cpt_sock_image *si,
			  loff_t pos, struct cpt_context *ctx)
{
	struct inet_sock *inet = inet_sk(sk);

	lock_sock(sk);

	inet->uc_ttl = si->cpt_uc_ttl;
	inet->tos = si->cpt_tos;
	inet->cmsg_flags = si->cpt_cmsg_flags;
	inet->pmtudisc = si->cpt_pmtudisc;
	inet->recverr = si->cpt_recverr;
	inet->freebind = si->cpt_freebind;
	inet->id = si->cpt_idcounter;

	if (sk->sk_family == AF_INET6) {
		struct ipv6_pinfo *np = inet6_sk(sk);

		np->frag_size = si->cpt_frag_size6;
		np->hop_limit = si->cpt_hop_limit6;

		np->rxopt.all = si->cpt_rxopt6;
		np->mc_loop = si->cpt_mc_loop6;
		np->recverr = si->cpt_recverr6;
		np->pmtudisc = si->cpt_pmtudisc6;
		np->ipv6only = si->cpt_ipv6only6;
	}

	if (sk->sk_protocol == IPPROTO_TCP)
		rst_listen_socket_tcp(si, sk);

	release_sock(sk);
	return 0;
}

int rst_socket_in(struct cpt_sock_image *si, loff_t pos, struct sock *sk,
		  struct cpt_context *ctx)
{
	struct inet_sock *inet = inet_sk(sk);
	struct net *net = get_exec_env()->ve_ns->net_ns;
	int err, ret_err = 0;

	lock_sock(sk);

	sk->sk_state = si->cpt_state;

	inet->daddr = si->cpt_daddr;
	inet->dport = si->cpt_dport;
	inet->saddr = si->cpt_saddr;
	inet->rcv_saddr = si->cpt_rcv_saddr;
	inet->sport = si->cpt_sport;
	inet->uc_ttl = si->cpt_uc_ttl;
	inet->tos = si->cpt_tos;
	inet->cmsg_flags = si->cpt_cmsg_flags;
	inet->mc_index = si->cpt_mc_index;
	inet->mc_addr = si->cpt_mc_addr;
	inet->hdrincl = si->cpt_hdrincl;
	inet->mc_ttl = si->cpt_mc_ttl;
	inet->mc_loop = si->cpt_mc_loop;
	inet->pmtudisc = si->cpt_pmtudisc;
	inet->recverr = si->cpt_recverr;
	inet->freebind = si->cpt_freebind;
	inet->id = si->cpt_idcounter;

	inet->cork.flags = si->cpt_cork_flags;
	inet->cork.fragsize = si->cpt_cork_fragsize;
	inet->cork.length = si->cpt_cork_length;
	inet->cork.addr = si->cpt_cork_addr;
	inet->cork.fl.fl4_src = si->cpt_cork_saddr;
	inet->cork.fl.fl4_dst = si->cpt_cork_daddr;
	inet->cork.fl.oif = si->cpt_cork_oif;
	if (inet->cork.fragsize) {
		if (ip_route_output_key(net, (struct rtable **)&inet->cork.dst, &inet->cork.fl)) {
			eprintk_ctx("failed to restore cork route\n");
			inet->cork.fragsize = 0;
		}
	}

	if (sk->sk_type == SOCK_DGRAM && sk->sk_protocol == IPPROTO_UDP) {
		struct udp_sock *up = udp_sk(sk);
		up->pending = si->cpt_udp_pending;
		up->corkflag = si->cpt_udp_corkflag;
		up->encap_type = si->cpt_udp_encap;
		up->len = si->cpt_udp_len;
	}

	if (sk->sk_family == AF_INET6) {
		struct ipv6_pinfo *np = inet6_sk(sk);

		memcpy(&np->saddr, si->cpt_saddr6, 16);
		memcpy(&np->rcv_saddr, si->cpt_rcv_saddr6, 16);
		memcpy(&np->daddr, si->cpt_daddr6, 16);
		np->flow_label = si->cpt_flow_label6;
		np->frag_size = si->cpt_frag_size6;
		np->hop_limit = si->cpt_hop_limit6;
		np->mcast_hops = si->cpt_mcast_hops6;
		np->mcast_oif = si->cpt_mcast_oif6;
		np->rxopt.all = si->cpt_rxopt6;
		np->mc_loop = si->cpt_mc_loop6;
		np->recverr = si->cpt_recverr6;
		np->sndflow = si->cpt_sndflow6;
		np->pmtudisc = si->cpt_pmtudisc6;
		np->ipv6only = si->cpt_ipv6only6;

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		if (si->cpt_mapped) {
			extern struct inet_connection_sock_af_ops ipv6_mapped;
			if (sk->sk_type == SOCK_STREAM &&
			    sk->sk_protocol == IPPROTO_TCP) {
				inet_csk(sk)->icsk_af_ops = &ipv6_mapped;
				sk->sk_backlog_rcv = tcp_v4_do_rcv;
			}
		}
#endif
	}

	err = restore_queues(sk, si, pos, ctx);

	if (sk->sk_type == SOCK_STREAM && sk->sk_protocol == IPPROTO_TCP) {
		ret_err = err;
		rst_socket_tcp(si, pos, sk, ctx);
	}

	release_sock(sk);
	return ret_err;
}

static struct request_sock *rst_reqsk_alloc(unsigned short family)
{
	struct request_sock *req;

	if (family == AF_INET)
		req = inet_reqsk_alloc(&tcp_request_sock_ops);
	else
#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
		req = inet6_reqsk_alloc(&tcp6_request_sock_ops);
#else
		return ERR_PTR(-EINVAL);
#endif
#ifdef CONFIG_TCP_MD5SIG
	if (req) {
		if (family == AF_INET)
			tcp_rsk(req)->af_specific = &tcp_request_sock_ipv4_ops;
		else
			tcp_rsk(req)->af_specific = &tcp_request_sock_ipv6_ops;
	}
#endif
	return req;
}

int cpt_attach_accept(struct sock *lsk, struct sock *sk, cpt_context_t *ctx)
{
	struct request_sock *req;

	if (lsk->sk_state != TCP_LISTEN)
		return -EINVAL;
	req = rst_reqsk_alloc(sk->sk_family);
	if (IS_ERR(req))
		return PTR_ERR(req);
	if (!req)
		return -ENOMEM;

	sk->sk_socket = NULL;
	sk->sk_sleep = NULL;
	inet_csk_reqsk_queue_add(lsk, req, sk);
	return 0;
}

int rst_restore_synwait_queue(struct sock *sk, struct cpt_sock_image *si,
			      loff_t pos, struct cpt_context *ctx)
{
	int err;
	loff_t end = pos + si->cpt_next;

	pos += si->cpt_hdrlen;

	lock_sock(sk);
	while (pos < end) {
		struct cpt_openreq_image oi;

		err = rst_sock_attr(&pos, sk, ctx);
		if (!err)
			continue;
		if (err < 0)
			goto out;

		err = rst_get_object(CPT_OBJ_OPENREQ, pos, &oi, ctx);
		if (err)
			goto out;

		if (oi.cpt_object == CPT_OBJ_OPENREQ) {
			struct request_sock *req;

			if (oi.cpt_family == AF_INET6 &&
			    sk->sk_family != AF_INET6)
				/* related to non initialized cpt_family bug */
				goto next;
			req = rst_reqsk_alloc(oi.cpt_family);
			if (IS_ERR(req)) {
				release_sock(sk);
				return PTR_ERR(req);
			}

			if (req == NULL) {
				release_sock(sk);
				return -ENOMEM;
			}

			tcp_rsk(req)->rcv_isn = oi.cpt_rcv_isn;
			tcp_rsk(req)->snt_isn = oi.cpt_snt_isn;
			inet_rsk(req)->rmt_port = oi.cpt_rmt_port;
			req->mss = oi.cpt_mss;
			req->retrans = oi.cpt_retrans;
			inet_rsk(req)->snd_wscale = oi.cpt_snd_wscale;
			inet_rsk(req)->rcv_wscale = oi.cpt_rcv_wscale;
			inet_rsk(req)->tstamp_ok = oi.cpt_tstamp_ok;
			inet_rsk(req)->sack_ok = oi.cpt_sack_ok;
			inet_rsk(req)->wscale_ok = oi.cpt_wscale_ok;
			inet_rsk(req)->ecn_ok = oi.cpt_ecn_ok;
			inet_rsk(req)->acked = oi.cpt_acked;
			inet_rsk(req)->opt = NULL;
			req->window_clamp = oi.cpt_window_clamp;
			req->rcv_wnd = oi.cpt_rcv_wnd;
			req->ts_recent = oi.cpt_ts_recent;
			req->expires = jiffies_import(oi.cpt_expires);
			req->sk = NULL;
			req->secid = 0;
			req->peer_secid = 0;

			if (oi.cpt_family == AF_INET6) {
#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
				inet6_rsk(req)->pktopts = NULL;
				memcpy(&inet6_rsk(req)->loc_addr, oi.cpt_loc_addr, 16);
				memcpy(&inet6_rsk(req)->rmt_addr, oi.cpt_rmt_addr, 16);
				inet6_rsk(req)->iif = oi.cpt_iif;
				inet6_csk_reqsk_queue_hash_add(sk, req, TCP_TIMEOUT_INIT);
#endif
			} else {
				memcpy(&inet_rsk(req)->loc_addr, oi.cpt_loc_addr, 4);
				memcpy(&inet_rsk(req)->rmt_addr, oi.cpt_rmt_addr, 4);
				inet_csk_reqsk_queue_hash_add(sk, req, TCP_TIMEOUT_INIT);
			}
		}
next:
		pos += oi.cpt_next;
	}
	err = 0;
out:
	release_sock(sk);
	return err;
}

int rst_sk_mcfilter_in(struct sock *sk, struct cpt_sockmc_image *v,
		       loff_t pos, cpt_context_t *ctx)
{
	struct ip_mreqn imr;

	if (v->cpt_mode || v->cpt_next != v->cpt_hdrlen) {
		eprintk_ctx("IGMPv3 is still not supported\n");
		return -EINVAL;
	}

	memset(&imr, 0, sizeof(imr));
	imr.imr_ifindex = v->cpt_ifindex;
	imr.imr_multiaddr.s_addr = v->cpt_mcaddr[0];
	return ip_mc_join_group(sk, &imr);
}

#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
int rst_sk_mcfilter_in6(struct sock *sk, struct cpt_sockmc_image *v,
			loff_t pos, cpt_context_t *ctx)
{

	if (v->cpt_mode || v->cpt_next != v->cpt_hdrlen) {
		eprintk_ctx("IGMPv3 is still not supported\n");
		return -EINVAL;
	}

	return ipv6_sock_mc_join(sk, v->cpt_ifindex,
				 (struct in6_addr*)v->cpt_mcaddr);
}
#endif
