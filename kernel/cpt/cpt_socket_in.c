/*
 *
 *  kernel/cpt/cpt_socket_in.c
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
#include <net/sock.h>
#include <net/tcp.h>
#include <net/if_inet6.h>
#include <linux/igmp.h>
#include <linux/ipv6.h>

#include <linux/cpt_obj.h>
#include <linux/cpt_context.h>
#include "cpt_mm.h"
#include "cpt_socket.h"
#include "cpt_kernel.h"

static inline __u32 jiffies_export(unsigned long tmo)
{
	__s32 delta = (long)(tmo - jiffies);
	return delta;
}

static inline __u32 tcp_jiffies_export(__u32 tmo)
{
	__s32 delta = tmo - tcp_time_stamp;
	return delta;
}

int cpt_dump_ofo_queue(int idx, struct sock *sk, struct cpt_context *ctx)
{
	struct rb_node *p;
	struct tcp_sock *tp;

	if (sk->sk_type != SOCK_STREAM || sk->sk_protocol != IPPROTO_TCP)
		return 0;

	tp = tcp_sk(sk);

	p = rb_first(&tp->out_of_order_queue);
	while (p) {
		int err;
		struct sk_buff *skb = rb_to_skb(p);

		p = rb_next(p);

		err = cpt_dump_skb(CPT_SKB_OFOQ, idx, skb, sk, ctx);
		if (err)
			return err;

	}
	return 0;
}

static inline int sk_ipv6_mapped(struct sock *sk)
{
	const struct inet_connection_sock_af_ops *ops;

	ops = inet_csk(sk)->icsk_af_ops;

	BUILD_BUG_ON(sizeof(struct iphdr) == sizeof(struct ipv6hdr));
	BUILD_BUG_ON(sizeof(struct sockaddr_in) == sizeof(struct sockaddr_in6));

	return sk->sk_family == AF_INET6 &&
		ops->net_header_len == sizeof(struct iphdr) &&
		ops->sockaddr_len == sizeof(struct sockaddr_in6);
}

static int cpt_dump_socket_tcp(struct cpt_sock_image *si, struct sock *sk,
			       struct cpt_context *ctx)
{
	struct tcp_sock *tp = tcp_sk(sk);

	si->cpt_pred_flags = tp->pred_flags;
	si->cpt_rcv_nxt = tp->rcv_nxt;
	si->cpt_snd_nxt = tp->snd_nxt;
	si->cpt_snd_una = tp->snd_una;
	si->cpt_snd_sml = tp->snd_sml;
	si->cpt_rcv_tstamp = tcp_jiffies_export(tp->rcv_tstamp);
	si->cpt_lsndtime = tcp_jiffies_export(tp->lsndtime);
	si->cpt_tcp_header_len = tp->tcp_header_len;
	si->cpt_ack_pending = inet_csk(sk)->icsk_ack.pending;
	si->cpt_quick = inet_csk(sk)->icsk_ack.quick;
	si->cpt_pingpong = inet_csk(sk)->icsk_ack.pingpong;
	si->cpt_blocked = inet_csk(sk)->icsk_ack.blocked;
	si->cpt_ato = inet_csk(sk)->icsk_ack.ato;
	si->cpt_ack_timeout = jiffies_export(inet_csk(sk)->icsk_ack.timeout);
	si->cpt_lrcvtime = tcp_jiffies_export(inet_csk(sk)->icsk_ack.lrcvtime);
	si->cpt_last_seg_size = inet_csk(sk)->icsk_ack.last_seg_size;
	si->cpt_rcv_mss = inet_csk(sk)->icsk_ack.rcv_mss;
	si->cpt_snd_wl1 = tp->snd_wl1;
	si->cpt_snd_wnd = tp->snd_wnd;
	si->cpt_max_window = tp->max_window;
	si->cpt_pmtu_cookie = inet_csk(sk)->icsk_pmtu_cookie;
	si->cpt_mss_cache = tp->mss_cache;
	si->cpt_mss_cache_std = tp->mss_cache; /* FIXMW was tp->mss_cache_std */
	si->cpt_mss_clamp = tp->rx_opt.mss_clamp;
	si->cpt_ext_header_len = inet_csk(sk)->icsk_ext_hdr_len;
	si->cpt_ext2_header_len = 0;
	si->cpt_ca_state = inet_csk(sk)->icsk_ca_state;
	si->cpt_retransmits = inet_csk(sk)->icsk_retransmits;
	si->cpt_reordering = tp->reordering;
	si->cpt_frto_counter = tp->frto_counter;
	si->cpt_frto_highmark = tp->frto_highmark;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,9)
	// // si->cpt_adv_cong = tp->adv_cong;
#endif
	si->cpt_defer_accept = inet_csk(sk)->icsk_accept_queue.rskq_defer_accept;
	si->cpt_backoff = inet_csk(sk)->icsk_backoff;
	si->cpt_srtt = tp->srtt;
	si->cpt_mdev = tp->mdev;
	si->cpt_mdev_max = tp->mdev_max;
	si->cpt_rttvar = tp->rttvar;
	si->cpt_rtt_seq = tp->rtt_seq;
	si->cpt_rto = inet_csk(sk)->icsk_rto;
	si->cpt_packets_out = tp->packets_out;
	si->cpt_left_out = tp->sacked_out + tp->lost_out;
	si->cpt_retrans_out = tp->retrans_out;
	si->cpt_lost_out = tp->lost_out;
	si->cpt_sacked_out = tp->sacked_out;
	si->cpt_fackets_out = tp->fackets_out;
	si->cpt_snd_ssthresh = tp->snd_ssthresh;
	si->cpt_snd_cwnd = tp->snd_cwnd;
	si->cpt_snd_cwnd_cnt = tp->snd_cwnd_cnt;
	si->cpt_snd_cwnd_clamp = tp->snd_cwnd_clamp;
	si->cpt_snd_cwnd_used = tp->snd_cwnd_used;
	si->cpt_snd_cwnd_stamp = tcp_jiffies_export(tp->snd_cwnd_stamp);
	si->cpt_timeout = jiffies_export(inet_csk(sk)->icsk_timeout);
	si->cpt_ka_timeout = 0;
	si->cpt_rcv_wnd = tp->rcv_wnd;
	si->cpt_rcv_wup = tp->rcv_wup;
	si->cpt_write_seq = tp->write_seq;
	si->cpt_pushed_seq = tp->pushed_seq;
	si->cpt_copied_seq = tp->copied_seq;
	si->cpt_tstamp_ok = tp->rx_opt.tstamp_ok;
	si->cpt_wscale_ok = tp->rx_opt.wscale_ok;
	si->cpt_sack_ok = tp->rx_opt.sack_ok;
	si->cpt_saw_tstamp = tp->rx_opt.saw_tstamp;
	si->cpt_snd_wscale = tp->rx_opt.snd_wscale;
	si->cpt_rcv_wscale = tp->rx_opt.rcv_wscale;
	si->cpt_nonagle = tp->nonagle;
	si->cpt_keepalive_probes = tp->keepalive_probes;
	si->cpt_rcv_tsval = tp->rx_opt.rcv_tsval;
	si->cpt_rcv_tsecr = tp->rx_opt.rcv_tsecr;
	si->cpt_ts_recent = tp->rx_opt.ts_recent;
	si->cpt_ts_recent_stamp = tp->rx_opt.ts_recent_stamp;
	si->cpt_user_mss = tp->rx_opt.user_mss;
	si->cpt_dsack = tp->rx_opt.dsack;
	si->cpt_sack_array[0] = tp->duplicate_sack[0].start_seq;
	si->cpt_sack_array[1] = tp->duplicate_sack[0].end_seq;
	si->cpt_sack_array[2] = tp->selective_acks[0].start_seq;
	si->cpt_sack_array[3] = tp->selective_acks[0].end_seq;
	si->cpt_sack_array[4] = tp->selective_acks[1].start_seq;
	si->cpt_sack_array[5] = tp->selective_acks[1].end_seq;
	si->cpt_sack_array[6] = tp->selective_acks[2].start_seq;
	si->cpt_sack_array[7] = tp->selective_acks[2].end_seq;
	si->cpt_sack_array[8] = tp->selective_acks[3].start_seq;
	si->cpt_sack_array[9] = tp->selective_acks[3].end_seq;
	si->cpt_window_clamp = tp->window_clamp;
	si->cpt_rcv_ssthresh = tp->rcv_ssthresh;
	si->cpt_probes_out = inet_csk(sk)->icsk_probes_out;
	si->cpt_num_sacks = tp->rx_opt.num_sacks;
	si->cpt_advmss = tp->advmss;
	si->cpt_syn_retries = inet_csk(sk)->icsk_syn_retries;
	si->cpt_ecn_flags = tp->ecn_flags;
	si->cpt_prior_ssthresh = tp->prior_ssthresh;
	si->cpt_high_seq = tp->high_seq;
	si->cpt_retrans_stamp = tp->retrans_stamp;
	si->cpt_undo_marker = tp->undo_marker;
	si->cpt_undo_retrans = tp->undo_retrans;
	si->cpt_urg_seq = tp->urg_seq;
	si->cpt_urg_data = tp->urg_data;
	si->cpt_pending = inet_csk(sk)->icsk_pending;
	si->cpt_snd_up = tp->snd_up;
	si->cpt_keepalive_time = tp->keepalive_time;
	si->cpt_keepalive_intvl = tp->keepalive_intvl;
	si->cpt_linger2 = tp->linger2;

	if (sk->sk_state != TCP_LISTEN &&
	    sk->sk_state != TCP_CLOSE &&
	    sock_flag(sk, SOCK_KEEPOPEN)) {
		si->cpt_ka_timeout = jiffies_export(sk->sk_timer.expires);
	}

	if (sk_ipv6_mapped(sk))
		si->cpt_mapped = 1;
	return 0;
}


int cpt_dump_socket_in(struct cpt_sock_image *si, struct sock *sk,
		       struct cpt_context *ctx)
{
	struct inet_sock *inet = inet_sk(sk);
	struct ipv6_pinfo *np = inet6_sk(sk);

	if (sk->sk_family == AF_INET) {
		struct sockaddr_in *sin = ((struct sockaddr_in*)si->cpt_laddr);
		sin->sin_family = AF_INET;
		sin->sin_port = inet->sport;
		sin->sin_addr.s_addr = inet->rcv_saddr;
		si->cpt_laddrlen = sizeof(*sin);
	} else if (sk->sk_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = ((struct sockaddr_in6*)si->cpt_laddr);
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = inet->sport;
		memcpy(&sin6->sin6_addr, &np->rcv_saddr, 16);
		si->cpt_laddrlen = sizeof(*sin6);
	}
	if (!inet->num)
		si->cpt_laddrlen = 0;

	si->cpt_daddr = inet->daddr;
	si->cpt_dport = inet->dport;
	si->cpt_saddr = inet->saddr;
	si->cpt_rcv_saddr = inet->rcv_saddr;
	si->cpt_sport = inet->sport;
	si->cpt_uc_ttl = inet->uc_ttl;
	si->cpt_tos = inet->tos;
	si->cpt_cmsg_flags = inet->cmsg_flags;
	si->cpt_mc_index = inet->mc_index;
	si->cpt_mc_addr = inet->mc_addr;
	si->cpt_hdrincl = inet->hdrincl;
	si->cpt_mc_ttl = inet->mc_ttl;
	si->cpt_mc_loop = inet->mc_loop;
	si->cpt_pmtudisc = inet->pmtudisc;
	si->cpt_recverr = inet->recverr;
	si->cpt_freebind = inet->freebind;
	si->cpt_idcounter = inet->id;

	si->cpt_cork_flags = inet->cork.flags;
	si->cpt_cork_fragsize = 0;
	si->cpt_cork_length = inet->cork.length;
	si->cpt_cork_addr = inet->cork.addr;
	si->cpt_cork_saddr = inet->cork.fl.fl4_src;
	si->cpt_cork_daddr = inet->cork.fl.fl4_dst;
	si->cpt_cork_oif = inet->cork.fl.oif;
	if (inet->cork.dst) {
		struct rtable *rt = (struct rtable *)inet->cork.dst;
		si->cpt_cork_fragsize = inet->cork.fragsize;
		si->cpt_cork_saddr = rt->fl.fl4_src;
		si->cpt_cork_daddr = rt->fl.fl4_dst;
		si->cpt_cork_oif = rt->fl.oif;
	}

	if (sk->sk_type == SOCK_DGRAM && sk->sk_protocol == IPPROTO_UDP) {
		struct udp_sock *up = udp_sk(sk);
		si->cpt_udp_pending  = up->pending;
		si->cpt_udp_corkflag  = up->corkflag;
		si->cpt_udp_encap  = up->encap_type;
		si->cpt_udp_len  = up->len;
	}

	if (sk->sk_family == AF_INET6) {
		memcpy(si->cpt_saddr6, &np->saddr, 16);
		memcpy(si->cpt_rcv_saddr6, &np->rcv_saddr, 16);
		memcpy(si->cpt_daddr6, &np->daddr, 16);
		si->cpt_flow_label6 = np->flow_label;
		si->cpt_frag_size6 = np->frag_size;
		si->cpt_hop_limit6 = np->hop_limit;
		si->cpt_mcast_hops6 = np->mcast_hops;
		si->cpt_mcast_oif6 = np->mcast_oif;
		si->cpt_rxopt6 = np->rxopt.all;
		si->cpt_mc_loop6 = np->mc_loop;
		si->cpt_recverr6 = np->recverr;
		si->cpt_sndflow6 = np->sndflow;
		si->cpt_pmtudisc6 = np->pmtudisc;
		si->cpt_ipv6only6 = np->ipv6only;
		si->cpt_mapped = 0;
	}

	if (sk->sk_type == SOCK_STREAM && sk->sk_protocol == IPPROTO_TCP)
		cpt_dump_socket_tcp(si, sk, ctx);

	return 0;
}

int cpt_dump_accept_queue(struct sock *sk, int index, struct cpt_context *ctx)
{
	struct request_sock *req;

	for (req=inet_csk(sk)->icsk_accept_queue.rskq_accept_head; req; req=req->dl_next) {
		int err = cpt_dump_socket(NULL, req->sk, -1, index, ctx);
		if (err)
			return err;
	}
	return 0;
}


static int dump_openreq(struct request_sock *req, struct sock *sk, int index,
			struct cpt_context *ctx)
{
	struct cpt_openreq_image *v = cpt_get_buf(ctx);

	cpt_open_object(NULL, ctx);

	v->cpt_next = CPT_NULL;
	v->cpt_object = CPT_OBJ_OPENREQ;
	v->cpt_hdrlen = sizeof(*v);
	v->cpt_content = CPT_CONTENT_VOID;

	v->cpt_rcv_isn = tcp_rsk(req)->rcv_isn;
	v->cpt_snt_isn = tcp_rsk(req)->snt_isn;
	v->cpt_rmt_port = inet_rsk(req)->rmt_port;
	v->cpt_mss = req->mss;
	v->cpt_family = req->rsk_ops->family;
	v->cpt_retrans = req->retrans;
	v->cpt_snd_wscale = inet_rsk(req)->snd_wscale;
	v->cpt_rcv_wscale = inet_rsk(req)->rcv_wscale;
	v->cpt_tstamp_ok = inet_rsk(req)->tstamp_ok;
	v->cpt_sack_ok = inet_rsk(req)->sack_ok;
	v->cpt_wscale_ok = inet_rsk(req)->wscale_ok;
	v->cpt_ecn_ok = inet_rsk(req)->ecn_ok;
	v->cpt_acked = inet_rsk(req)->acked;
	v->cpt_window_clamp = req->window_clamp;
	v->cpt_rcv_wnd = req->rcv_wnd;
	v->cpt_ts_recent = req->ts_recent;
	v->cpt_expires = jiffies_export(req->expires);

	if (v->cpt_family == AF_INET) {
		memcpy(v->cpt_loc_addr, &inet_rsk(req)->loc_addr, 4);
		memcpy(v->cpt_rmt_addr, &inet_rsk(req)->rmt_addr, 4);
	} else {
#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
		memcpy(v->cpt_loc_addr, &inet6_rsk(req)->loc_addr, 16);
		memcpy(v->cpt_rmt_addr, &inet6_rsk(req)->rmt_addr, 16);
		v->cpt_iif = inet6_rsk(req)->iif;
#endif
	}

	ctx->write(v, sizeof(*v), ctx);
	cpt_release_buf(ctx);

	cpt_close_object(ctx);
	return 0;
}

int cpt_dump_synwait_queue(struct sock *sk, int index, struct cpt_context *ctx)
{
	struct inet_connection_sock *icsk;
	struct listen_sock *lopt;
	struct request_sock *req;
	int nr_entries;
	int i;

	icsk = inet_csk(sk);
	lopt = icsk->icsk_accept_queue.listen_opt;
	nr_entries = icsk->icsk_accept_queue.listen_opt->nr_table_entries;

	for (i=0; i < nr_entries; i++) {
		for (req=lopt->syn_table[i]; req; req=req->dl_next) {
			loff_t saved_obj;
			cpt_push_object(&saved_obj, ctx);
			dump_openreq(req, sk, index, ctx);
			cpt_pop_object(&saved_obj, ctx);
		}
	}
	return 0;
}


int cpt_kill_socket(struct sock *sk, cpt_context_t * ctx)
{
	if (sk->sk_state != TCP_CLOSE &&
	    (sk->sk_family == AF_INET || sk->sk_family == AF_INET6) &&
	    sk->sk_protocol == IPPROTO_TCP) {
		if (sk->sk_state != TCP_LISTEN)
			tcp_set_state(sk, TCP_CLOSE);
		else
			sk->sk_prot->disconnect(sk, 0);
	}
	return 0;
}

int cpt_dump_mcfilter(struct sock *sk, cpt_context_t *ctx)
{
	struct inet_sock *inet = inet_sk(sk);
	struct ip_mc_socklist *iml;

	for (iml = inet->mc_list; iml; iml = iml->next) {
		struct cpt_sockmc_image smi;
		int scnt = 0;
		int i;

		if (iml->sflist)
			scnt = iml->sflist->sl_count*16;

		smi.cpt_next = sizeof(smi) + scnt;
		smi.cpt_object = CPT_OBJ_SOCK_MCADDR;
		smi.cpt_hdrlen = sizeof(smi);
		smi.cpt_content = CPT_CONTENT_DATA;

		smi.cpt_family = AF_INET;
		smi.cpt_mode = iml->sfmode;
		smi.cpt_ifindex = iml->multi.imr_ifindex;
		memset(&smi.cpt_mcaddr, 0, sizeof(smi.cpt_mcaddr));
		smi.cpt_mcaddr[0] = iml->multi.imr_multiaddr.s_addr;

		ctx->write(&smi, sizeof(smi), ctx);

		for (i = 0; i < scnt; i++) {
			u32 addr[4];
			memset(&addr, 0, sizeof(addr));
			addr[0] = iml->sflist->sl_addr[i];
			ctx->write(&addr, sizeof(addr), ctx);
		}
	}

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	if (sk->sk_family == AF_INET6) {
		struct ipv6_mc_socklist *mcl;
		struct ipv6_pinfo *np = inet6_sk(sk);

		for (mcl = np->ipv6_mc_list; mcl; mcl = mcl->next) {
			struct cpt_sockmc_image smi;
			int scnt = 0;
			int i;

			if (mcl->sflist)
				scnt = mcl->sflist->sl_count*16;

			smi.cpt_next = sizeof(smi) + scnt;
			smi.cpt_object = CPT_OBJ_SOCK_MCADDR;
			smi.cpt_hdrlen = sizeof(smi);
			smi.cpt_content = CPT_CONTENT_DATA;

			smi.cpt_family = AF_INET6;
			smi.cpt_mode = mcl->sfmode;
			smi.cpt_ifindex = mcl->ifindex;
			memcpy(&smi.cpt_mcaddr, &mcl->addr, sizeof(smi.cpt_mcaddr));

			ctx->write(&smi, sizeof(smi), ctx);
			for (i = 0; i < scnt; i++)
				ctx->write(&mcl->sflist->sl_addr[i], 16, ctx);
		}
	}
#endif
	return 0;
}
