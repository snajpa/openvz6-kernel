/*
 *
 *  kernel/cpt/cpt_socket.c
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
#include <linux/un.h>
#include <linux/tcp.h>
#include <linux/mount.h>
#include <net/sock.h>
#include <net/scm.h>
#include <net/af_unix.h>
#include <net/tcp.h>
#include <net/netlink_sock.h>

#include <linux/cpt_obj.h>
#include <linux/cpt_context.h>
#include "cpt_mm.h"
#include "cpt_socket.h"
#include "cpt_files.h"
#include "cpt_kernel.h"
#include "cpt_fsmagic.h"
#include "cpt_process.h"

static int dump_rqueue(int owner, struct sock *sk, struct cpt_context *ctx);


/* Sockets are quite different of another kinds of files.
 * There is one simplification: only one struct file can refer to a socket,
 * so we could store information about socket directly in section FILES as
 * a description of a file and append f.e. array of not-yet-accepted
 * connections of listening socket as array of auxiliary data.
 *
 * Complications are:
 * 1. TCP sockets can be orphans. We have to relocate orphans as well,
 *    so we have to create special section for orphans.
 * 2. AF_UNIX sockets are distinguished objects: set of links between
 *    AF_UNIX sockets is quite arbitrary.
 *    A. Each socket can refers to many of files due to FD passing.
 *    B. Each socket except for connected ones can have in queue skbs
 *       sent by any of sockets.
 *
 *    2A is relatively easy: after our tasks are frozen we make an additional
 *    recursive pass throgh set of collected files and get referenced to
 *    FD passed files. After end of recursion, all the files are treated
 *    in the same way. All they will be stored in section FILES.
 *
 *    2B. We have to resolve all those references at some point.
 *    It is the place where pipe-like approach to image fails.
 *
 * All this makes socket checkpointing quite chumbersome.
 * Right now we collect all the sockets and assign some numeric index value
 * to each of them. The socket section is separate and put after section FILES,
 * so section FILES refers to sockets by index, section SOCKET refers to FILES
 * as usual by position in image. All the refs inside socket section are
 * by index. When restoring we read socket section, create objects to hold
 * mappings index <-> pos. At the second pass we open sockets (simultaneosly
 * with their pairs) and create FILE objects.
 */ 


/* ====== FD passing ====== */

/* Almost nobody does FD passing via AF_UNIX sockets, nevertheless we
 * have to implement this. A problem is that in general case we receive
 * skbs from an unknown context, so new files can arrive to checkpointed
 * set of processes even after they are stopped. Well, we are going just
 * to ignore unknown fds while doing real checkpointing. It is fair because
 * links outside checkpointed set are going to fail anyway.
 *
 * ATTN: the procedure is recursive. We linearize the recursion adding
 * newly found files to the end of file list, so they will be analyzed
 * in the same loop.
 */

static int collect_one_passedfd(struct file *file, cpt_context_t * ctx)
{
	struct inode *inode = file->f_dentry->d_inode;
	struct socket *sock;
	struct sock *sk;
	struct sk_buff *skb;

	if (!S_ISSOCK(inode->i_mode))
		return -ENOTSOCK;

	sock = &container_of(inode, struct socket_alloc, vfs_inode)->socket;

	if (sock->ops->family != AF_UNIX)
		return 0;

	sk = sock->sk;

	/* Subtle locking issue. skbs cannot be removed while
	 * we are scanning, because all the processes are stopped.
	 * They still can be added to tail of queue. Locking while
	 * we dereference skb->next is enough to resolve this.
	 * See above about collision with skbs added after we started
	 * checkpointing.
	 */

	skb = skb_peek(&sk->sk_receive_queue);
	while (skb && skb != (struct sk_buff*)&sk->sk_receive_queue) {
		if (UNIXCB(skb).fp && skb->sk &&
		    (!sock_flag(skb->sk, SOCK_DEAD) || unix_peer(sk) == skb->sk)) {
			struct scm_fp_list *fpl = UNIXCB(skb).fp;
			int i;

			for (i = fpl->count-1; i >= 0; i--) {
				if (cpt_object_add(CPT_OBJ_FILE, fpl->fp[i], ctx) == NULL)
					return -ENOMEM;
			}
		}

		spin_lock_irq(&sk->sk_receive_queue.lock);
		skb = skb->next;
		spin_unlock_irq(&sk->sk_receive_queue.lock);
	}

	return 0;
}

int cpt_collect_passedfds(cpt_context_t * ctx)
{
	cpt_object_t *obj;

	for_each_object(obj, CPT_OBJ_FILE) {
		struct file *file = obj->o_obj;

		if (S_ISSOCK(file->f_dentry->d_inode->i_mode)) {
			int err;

			if ((err = collect_one_passedfd(file, ctx)) < 0)
				return err;
		}
	}

	return 0;
}

/* ====== End of FD passing ====== */

/* Must be called under bh_lock_sock() */

void clear_backlog(struct sock *sk)
{
	struct sk_buff *skb = sk->sk_backlog.head;

	sk->sk_backlog.head = sk->sk_backlog.tail = NULL;
	while (skb) {
		struct sk_buff *next = skb->next;

		skb->next = NULL;
		kfree_skb(skb);
		skb = next;
	}
}

void release_sock_nobacklog(struct sock *sk)
{
	spin_lock_bh(&(sk->sk_lock.slock));
	clear_backlog(sk);
	sk->sk_lock.owned = 0;
        if (waitqueue_active(&(sk->sk_lock.wq)))
		wake_up(&(sk->sk_lock.wq));
	spin_unlock_bh(&(sk->sk_lock.slock));
}

static void generic_dump_skb_cb(struct cpt_skb_image *v, struct sk_buff *skb)
{
	memcpy(v->cpt_cb, skb->cb, sizeof(v->cpt_cb));
}

static void dump_skb_tcp_cb(struct cpt_skb_image *v, struct sk_buff *skb)
{
	memcpy(v->cpt_tcp_cb, skb->cb, sizeof(v->cpt_tcp_cb));
}

static void dump_inet_skb_cb(struct cpt_skb_image *v, struct sk_buff *skb,
			     struct sock *sk, struct cpt_context *ctx)
{
	/*
	 * IPv6 enabled 'tcp_skb_cb' does not fit into 'cpt_skb_image.cb'.
	 * 'ack_seq' is missing, but hopefully it is not needed while
	 * skb is in queue.
	 * BUILD_BUG_ON(sizeof(v->cpt_cb) < sizeof(skb->cb));
	 */
	BUILD_BUG_ON(sizeof(v->cpt_cb) != 40);
	BUILD_BUG_ON(sizeof(struct inet_skb_parm) != 16);
	BUILD_BUG_ON(sizeof(struct inet6_skb_parm) != 24);
	BUILD_BUG_ON(sizeof(*TCP_SKB_CB(skb)) -
		     sizeof(TCP_SKB_CB(skb)->header) != 20);
#if !defined(CONFIG_IPV6) && !defined(CONFIG_IPV6_MODULE)
	if (sk->sk_protocol == IPPROTO_TCP) {
		/* Save control block according to tcp_skb_cb with IPv6 */

		/*
		 * IPv6 enabled 'tcp_skb_cb' does not fit into 'cpt_skb_image.cb'.
		 * BUILD_BUG_ON(sizeof(v->cpt_cb) - sizeof(struct inet6_skb_parm) <
		 *	sizeof(struct tcp_skb_cb) - sizeof(struct inet_skb_parm));
		 */
		memcpy(v->cpt_cb, skb->cb, sizeof(struct inet_skb_parm));
		memcpy((void *)v->cpt_cb + sizeof(struct inet6_skb_parm),
		       skb->cb + sizeof(struct inet_skb_parm),
		       min(sizeof(v->cpt_cb) - sizeof(struct inet6_skb_parm),
			   sizeof(struct tcp_skb_cb) - sizeof(struct inet_skb_parm)));
	} else
#endif
		generic_dump_skb_cb(v, skb);
}

static void dump_unix_skb_cb(struct cpt_skb_image *v, struct sk_buff *skb,
			     struct sock *sk, struct cpt_context *ctx)
{
	/*
	 * UNIXCB keeps pointers to pid and cred. Convert them to
	 * numbers.
	 */
	struct ucred *ucred = (struct ucred *)v->cpt_cb;

	BUILD_BUG_ON(sizeof(*ucred) > sizeof(v->cpt_cb));
	ucred->pid = cpt_pid_nr(UNIXCB(skb).pid);
	ucred->uid = UNIXCB(skb).cred ? UNIXCB(skb).cred->uid : -1;
	ucred->gid = UNIXCB(skb).cred ? UNIXCB(skb).cred->gid : -1;
}

int cpt_dump_skb(int type, int owner, struct sk_buff *skb,
		 struct sock *sk, struct cpt_context *ctx)
{
	struct cpt_skb_image *v = cpt_get_buf(ctx);
	loff_t saved_obj;
	struct timeval tmptv;
	int tcp = 0;
	int ret = 0;

	cpt_push_object(&saved_obj, ctx);
	cpt_open_object(NULL, ctx);

	v->cpt_next = CPT_NULL;
	v->cpt_object = CPT_OBJ_SKB;
	v->cpt_hdrlen = sizeof(*v);
	v->cpt_content = CPT_CONTENT_ARRAY;

	v->cpt_owner = owner;
	v->cpt_queue = type;
	skb_get_timestamp(skb, &tmptv);
	v->cpt_stamp = cpt_timeval_export(&tmptv);
	v->cpt_hspace = skb->data - skb->head;
	v->cpt_tspace = skb->end - skb->tail;
	v->cpt_h = skb_transport_header(skb) - skb->head;
	v->cpt_nh = skb_network_header(skb) - skb->head;
	v->cpt_mac = skb_mac_header(skb) - skb->head;
	memset(v->cpt_cb, 0, sizeof(v->cpt_cb));

	switch (sk->sk_family) {
	case AF_INET:
		if (sk->sk_protocol == IPPROTO_TCP)
			tcp = 1;
		dump_inet_skb_cb(v, skb, sk, ctx);
		break;
	case AF_UNIX:
		dump_unix_skb_cb(v, skb, sk, ctx);
		break;
	case AF_INET6:
		if (sk->sk_protocol == IPPROTO_TCP)
			tcp = 1;
	default:
		generic_dump_skb_cb(v, skb);
		break;
	}

	if ((tcp) && (type == CPT_SKB_RQ || type == CPT_SKB_OFOQ)) {
		/* In 2.6.32-504.16.2.el6 tcp_skb_cb was modified,
		 * old [36] .flags was splitted to 2 separate fields:
		 * [36] .tcp_flags and [38] .ip_dsfield
		 * For compatibility data should be dumped to in old format:
		 * for RQ and OFOQ .ip_dsfield should be saved to cb36
		 *
		 *  old kernels  vs  2.6.32-504.16.2.el6 aka 042stab108.1
		 *	   struct tcp_skb_cb {
		 *		    ...
		 *		[32] __u32 when;
		 *  [36] __u8 flags;		[36] __u8 tcp_flags;
		 *		[37] __u8 sacked;
		 *  ---				[38] __u8 ip_dsfield;
		 *		[40] __u32 ack_seq;
		 *	   }
		 *	   SIZE: 44
		 */
		struct tcp_skb_cb *pcb = (struct tcp_skb_cb *)&v->cpt_cb;

		pcb->tcp_flags = pcb->ip_dsfield;
	}
	if (tcp)
		dump_skb_tcp_cb(v, skb);

	v->cpt_len = skb->len;
	v->cpt_mac_len = skb->mac_len;
	v->cpt_csum = skb->csum;
	v->cpt_local_df = skb->local_df;
	v->cpt_pkt_type = skb->pkt_type;
	v->cpt_ip_summed = skb->ip_summed;
	v->cpt_priority = skb->priority;
	v->cpt_protocol = skb->protocol;
	v->cpt_security = 0;
	v->cpt_gso_segs = skb_shinfo(skb)->gso_segs;
	v->cpt_gso_size = skb_shinfo(skb)->gso_size;
	v->cpt_gso_type = skb_shinfo(skb)->gso_type;
	if (skb_shinfo(skb)->gso_type & SKB_GSO_UDP) {
		eprintk_ctx("skb ufo is not supported\n");
		cpt_release_buf(ctx);
		ret = -EINVAL;
		goto out;
	}

	ctx->write(v, sizeof(*v), ctx);
	cpt_release_buf(ctx);

	if (skb->len + (skb->data - skb->head) > 0) {
		struct cpt_obj_bits ob;
		loff_t saved_obj2;

		cpt_push_object(&saved_obj2, ctx);
		cpt_open_object(NULL, ctx);
		ob.cpt_next = CPT_NULL;
		ob.cpt_object = CPT_OBJ_BITS;
		ob.cpt_hdrlen = sizeof(ob);
		ob.cpt_content = CPT_CONTENT_DATA;
		ob.cpt_size = skb->len + v->cpt_hspace;

		ctx->write(&ob, sizeof(ob), ctx);

		ctx->write(skb->head, (skb->data-skb->head) + (skb->len-skb->data_len), ctx);
		if (skb->data_len) {
			int offset = skb->len - skb->data_len;
			while (offset < skb->len) {
				int copy = skb->len - offset;
				if (copy > PAGE_SIZE)
					copy = PAGE_SIZE;
				(void)cpt_get_buf(ctx);
				if (skb_copy_bits(skb, offset, ctx->tmpbuf, copy))
					BUG();
				ctx->write(ctx->tmpbuf, copy, ctx);
				__cpt_release_buf(ctx);
				offset += copy;
			}
		}

		ctx->align(ctx);
		cpt_close_object(ctx);
		cpt_pop_object(&saved_obj2, ctx);
	}

	if (skb->sk && skb->sk->sk_family == AF_UNIX) {
		struct scm_fp_list *fpl = UNIXCB(skb).fp;

		if (fpl) {
			int i;

			for (i = 0; i < fpl->count; i++) {
				struct cpt_fd_image v;
				cpt_object_t *obj;
				loff_t saved_obj2;

				obj = lookup_cpt_object(CPT_OBJ_FILE, fpl->fp[i], ctx);

				if (!obj) {
					eprintk_ctx("lost passed FD\n");
					ret = -EINVAL;
					goto out;
				}

				cpt_push_object(&saved_obj2, ctx);
				cpt_open_object(NULL, ctx);
				v.cpt_next = CPT_NULL;
				v.cpt_object = CPT_OBJ_FILEDESC;
				v.cpt_hdrlen = sizeof(v);
				v.cpt_content = CPT_CONTENT_VOID;

				v.cpt_fd = i;
				v.cpt_file = obj->o_pos;
				v.cpt_flags = 0;
				v.cpt_uid = fpl->user->uid;
				ctx->write(&v, sizeof(v), ctx);
				cpt_close_object(ctx);
				cpt_pop_object(&saved_obj2, ctx);
			}
		}
	}

out:
	cpt_close_object(ctx);
	cpt_pop_object(&saved_obj, ctx);
	return ret;
}

static int dump_rqueue(int idx, struct sock *sk, struct cpt_context *ctx)
{
	struct sk_buff *skb;
	struct sock *sk_cache = NULL;

	skb = skb_peek(&sk->sk_receive_queue);
	while (skb && skb != (struct sk_buff*)&sk->sk_receive_queue) {
		int err;

		if (sk->sk_family == AF_UNIX) {
			cpt_object_t *obj;
			if (skb->sk != sk_cache) {
				idx = -1;
				sk_cache = NULL;
				obj = lookup_cpt_object(CPT_OBJ_SOCKET, skb->sk, ctx);
				if (obj) {
					idx = obj->o_index;
					sk_cache = skb->sk;
				} else if (unix_peer(sk) != skb->sk)
					goto next_skb;
			}
		}

		err = cpt_dump_skb(CPT_SKB_RQ, idx, skb, sk, ctx);
		if (err)
			return err;

next_skb:
		spin_lock_irq(&sk->sk_receive_queue.lock);
		skb = skb->next;
		spin_unlock_irq(&sk->sk_receive_queue.lock);
	}
	return 0;
}

static int dump_wqueue(int idx, struct sock *sk, struct cpt_context *ctx)
{
	struct sk_buff *skb;

	skb = skb_peek(&sk->sk_write_queue);
	while (skb && skb != (struct sk_buff*)&sk->sk_write_queue) {
		int err = cpt_dump_skb(CPT_SKB_WQ, idx, skb, sk, ctx);
		if (err)
			return err;

		spin_lock_irq(&sk->sk_write_queue.lock);
		skb = skb->next;
		spin_unlock_irq(&sk->sk_write_queue.lock);
	}
	return 0;
}

static void cpt_dump_sock_packet_mclist(struct sock *sk,
					struct cpt_context *ctx)
{
	struct cpt_sock_packet_mc_image mi;
	loff_t saved_obj;
	void *iter = NULL;

	cpt_push_object(&saved_obj, ctx);
	while ((iter = sock_packet_cpt_one_mc(sk, &mi, iter)) != NULL) {
		cpt_open_object(NULL, ctx);
		mi.cpt_next = CPT_NULL;
		mi.cpt_object = CPT_OBJ_SOCK_PACKET_MC;
		mi.cpt_hdrlen = sizeof(mi);
		mi.cpt_content = CPT_CONTENT_VOID;
		ctx->write(&mi, sizeof(mi), ctx);
		cpt_close_object(ctx);
	}
	cpt_pop_object(&saved_obj, ctx);
}

void cpt_dump_sock_attr(struct sock *sk, cpt_context_t *ctx)
{
	loff_t saved_obj;
	if (sk->sk_filter) {
		struct cpt_obj_bits v;

		cpt_push_object(&saved_obj, ctx);
		cpt_open_object(NULL, ctx);

		v.cpt_next = CPT_NULL;
		v.cpt_object = CPT_OBJ_SKFILTER;
		v.cpt_hdrlen = sizeof(v);
		v.cpt_content = CPT_CONTENT_DATA;
		v.cpt_size = sk->sk_filter->len*sizeof(struct sock_filter);

		ctx->write(&v, sizeof(v), ctx);
		ctx->write(sk->sk_filter->insns, v.cpt_size, ctx);
		cpt_close_object(ctx);
		cpt_pop_object(&saved_obj, ctx);
	}
	if (sk->sk_family == AF_INET || sk->sk_family == AF_INET6) {
		cpt_push_object(&saved_obj, ctx);
		cpt_dump_mcfilter(sk, ctx);
		cpt_pop_object(&saved_obj, ctx);
	}
	if (sk->sk_family == AF_PACKET) {
		struct cpt_sock_packet_image v;

		memset(&v, 0, sizeof(v));

		cpt_push_object(&saved_obj, ctx);
		cpt_open_object(NULL, ctx);

		v.cpt_next = CPT_NULL;
		v.cpt_object = CPT_OBJ_SOCK_PACKET;
		v.cpt_hdrlen = sizeof(v);
		v.cpt_content = CPT_CONTENT_ARRAY;
		sock_packet_cpt_attr(sk, &v);

		ctx->write(&v, sizeof(v), ctx);
		cpt_dump_sock_packet_mclist(sk, ctx);

		cpt_close_object(ctx);
		cpt_pop_object(&saved_obj, ctx);
	}
}

static int cpt_dump_unix_mount(struct sock *sk, struct cpt_sock_image *v,
		cpt_context_t *ctx)
{
	cpt_object_t *mntobj;

	mntobj = cpt_lookup_vfsmount_obj(unix_sk(sk)->mnt, ctx);
	if (mntobj == NULL) {
		eprintk_ctx("can't get unix vfsmount\n");
		return -EINVAL;
	}

	v->cpt_vfsmount_ref = mntobj->o_pos;
	return 0;
}

static int cpt_dump_unix_socket(struct sock *sk, struct cpt_sock_image *v, cpt_context_t *ctx)
{
	v->cpt_vfsmount_ref = CPT_NULL;
	v->cpt_i_uid = -1;
	v->cpt_i_gid = -1;

	if (unix_sk(sk)->dentry) {
		struct dentry *d = unix_sk(sk)->dentry;
		unsigned long pg = __get_free_page(GFP_KERNEL);
		struct path p;
		char *path, *cpt_path;
		int err = 0;
		__u32 *path_len;
		int max_plen = 0;
		int offset = 0;

		if (!pg)
			return -ENOMEM;

		v->cpt_i_uid = d->d_inode->i_uid;
		v->cpt_i_gid = d->d_inode->i_gid;

		if (IS_ROOT(d) || !d_unhashed(d)) {
			p.dentry = dget(d);
			offset = sizeof(short);
			cpt_path = ((char*)v->cpt_laddr) + offset;
			path_len = &v->cpt_laddrlen;
			max_plen = sizeof(v->cpt_laddr) - offset;
		} else {
			v->cpt_sockflags |= CPT_SOCK_DELETED;
			v->cpt_d_aliaslen = 0;
			p.dentry = NULL;

			if (d->d_inode->i_nlink != 0) {
				p.dentry = get_linked_dentry(d, unix_sk(sk)->mnt, ctx);
				cpt_path = (char *)v->cpt_d_alias;
				path_len = &v->cpt_d_aliaslen;
				max_plen = sizeof(v->cpt_d_alias);
			}
		}

		if (!IS_ERR_OR_NULL(p.dentry)) {
			p.mnt = unix_sk(sk)->mnt;

			path = d_path(&p, (char *)pg, PAGE_SIZE);

			if (!IS_ERR(path)) {
				int len = strlen(path);
				if (len < max_plen) {
					strcpy(cpt_path, path);
					*path_len = len + 1 + offset;
				} else
					wprintk_ctx("af_unix path is too long: %s (%s)\n", path, cpt_path);

				if (cpt_need_delayfs(unix_sk(sk)->mnt))
					v->cpt_sockflags |= CPT_SOCK_DELAYED;

				v->cpt_i_mode = d->d_inode->i_mode & S_IALLUGO;

				err = cpt_dump_unix_mount(sk, v, ctx);
			} else {
				eprintk_ctx("cannot get path of an af_unix socket\n");
				err = PTR_ERR(path);
			}
			dput(p.dentry);
		}

		free_page(pg);
		if (err)
			return err;
	}

	/* If the socket is connected, find its peer. If peer is not
	 * in our table, the socket is connected to external process
	 * and we consider it disconnected.
	 */
	if (unix_peer(sk)) {
		cpt_object_t *pobj;
		pobj = lookup_cpt_object(CPT_OBJ_SOCKET, unix_peer(sk), ctx);
		if (pobj)
			v->cpt_peer = pobj->o_index;
		else
			v->cpt_shutdown = SHUTDOWN_MASK;

		/*
		 * There could be a situation, then socket is connected to
		 * itself. Stupid, but valid.
		 * Let's don't mix it with socket pairs...
		 */
		if (unix_peer(sk) != sk && unix_peer(unix_peer(sk)) == sk)
			v->cpt_socketpair = 1;
	}

	/* If the socket shares address with another socket it is
	 * child of some listening socket. Find and record it. */
	if (unix_sk(sk)->addr &&
			atomic_read(&unix_sk(sk)->addr->refcnt) > 1 &&
			sk->sk_state != TCP_LISTEN) {
		cpt_object_t *pobj;
		for_each_object(pobj, CPT_OBJ_SOCKET) {
			struct sock *psk = pobj->o_obj;
			if (psk->sk_family == AF_UNIX &&
					psk->sk_state == TCP_LISTEN &&
					unix_sk(psk)->addr == unix_sk(sk)->addr) {
				v->cpt_parent = pobj->o_index;
				break;
			}
		}
	}

	return 0;
}

/* Dump socket content */

int cpt_dump_socket(cpt_object_t *obj, struct sock *sk, int index, int parent, struct cpt_context *ctx)
{
	struct cpt_sock_image *v = cpt_get_buf(ctx);
	struct socket *sock;
	struct timeval tmptv;

	cpt_open_object(obj, ctx);

	v->cpt_next = CPT_NULL;
	v->cpt_object = CPT_OBJ_SOCKET;
	v->cpt_hdrlen = sizeof(*v);
	v->cpt_content = CPT_CONTENT_ARRAY;

	v->cpt_file = CPT_NULL;
	sock = sk->sk_socket;
	if (sock && sock->file) {
		cpt_object_t *tobj;
		tobj = lookup_cpt_object(CPT_OBJ_FILE, sock->file, ctx);
		if (tobj)
			v->cpt_file = tobj->o_pos;
	}
	v->cpt_index = index;
	v->cpt_parent = parent;

	if (sk->sk_family == AF_INET || sk->sk_family == AF_INET6) {
		if (sock && !obj->o_lock) {
			lockdep_off();
			lock_sock(sk);
			lockdep_on();
			obj->o_lock = 1;
		}
	}

	/* Some bits stored in inode */
	v->cpt_ssflags = sock ? sock->flags : 0;
	v->cpt_sstate = sock ? sock->state : 0;
	v->cpt_passcred = sock ? test_bit(SOCK_PASSCRED, &sock->flags) : 0;

	/* Common data */
	v->cpt_family = sk->sk_family;
	v->cpt_type = sk->sk_type;
	v->cpt_state = sk->sk_state;
	v->cpt_reuse = sk->sk_reuse;
	v->cpt_zapped = sock_flag(sk, SOCK_ZAPPED);
	v->cpt_shutdown = sk->sk_shutdown;
	v->cpt_userlocks = sk->sk_userlocks;
	v->cpt_no_check = sk->sk_no_check;
	v->cpt_zapped = sock_flag(sk, SOCK_DBG);
	v->cpt_rcvtstamp = sock_flag(sk, SOCK_RCVTSTAMP);
	v->cpt_localroute = sock_flag(sk, SOCK_LOCALROUTE);
	v->cpt_protocol = sk->sk_protocol;
	v->cpt_err = sk->sk_err;
	v->cpt_err_soft = sk->sk_err_soft;
	v->cpt_max_ack_backlog = sk->sk_max_ack_backlog;
	v->cpt_priority = sk->sk_priority;
	v->cpt_rcvlowat = sk->sk_rcvlowat;
	v->cpt_rcvtimeo = CPT_NULL;
	if (sk->sk_rcvtimeo != MAX_SCHEDULE_TIMEOUT)
		v->cpt_rcvtimeo = sk->sk_rcvtimeo > INT_MAX ? INT_MAX : sk->sk_rcvtimeo;
	v->cpt_sndtimeo = CPT_NULL;
	if (sk->sk_sndtimeo != MAX_SCHEDULE_TIMEOUT)
		v->cpt_sndtimeo = sk->sk_sndtimeo > INT_MAX ? INT_MAX : sk->sk_sndtimeo;
	v->cpt_rcvbuf = sk->sk_rcvbuf;
	v->cpt_sndbuf = sk->sk_sndbuf;
	v->cpt_bound_dev_if = sk->sk_bound_dev_if;
	v->cpt_flags = sk->sk_flags;
	v->cpt_lingertime = CPT_NULL;
	if (sk->sk_lingertime != MAX_SCHEDULE_TIMEOUT)
		v->cpt_lingertime = sk->sk_lingertime > INT_MAX ? INT_MAX : sk->sk_lingertime;
	v->cpt_peer_pid = cpt_pid_nr(sk_extended(sk)->sk_peer_pid);
	v->cpt_peer_uid = sk_extended(sk)->sk_peer_cred ? sk_extended(sk)->sk_peer_cred->euid : -1;
	v->cpt_peer_gid = sk_extended(sk)->sk_peer_cred ? sk_extended(sk)->sk_peer_cred->egid : -1;
	tmptv = ktime_to_timeval(sk->sk_stamp);
	v->cpt_stamp = cpt_timeval_export(&tmptv);

	v->cpt_peer = -1;
	v->cpt_socketpair = 0;
	v->cpt_sockflags = 0;

	v->cpt_laddrlen = 0;
	if (sock) {
		int alen = sizeof(v->cpt_laddr);
		int err = sock->ops->getname(sock, (struct sockaddr*)&v->cpt_laddr, &alen, 0);
		if (err) {
			cpt_release_buf(ctx);
			return err;
		}
		v->cpt_laddrlen = alen;
	}
	v->cpt_raddrlen = 0;
	if (sock) {
		int alen = sizeof(v->cpt_raddr);
		int err = sock->ops->getname(sock, (struct sockaddr*)&v->cpt_raddr, &alen, 2);
		if (!err)
			v->cpt_raddrlen = alen;
	}

	if (sk->sk_family == AF_UNIX) {
		int err;
		
		err = cpt_dump_unix_socket(sk, v, ctx);
		if (err) {
			cpt_release_buf(ctx);
			return err;
		}
	}

	if (sk->sk_family == AF_INET || sk->sk_family == AF_INET6)
		cpt_dump_socket_in(v, sk, ctx);

	ctx->write(v, sizeof(*v), ctx);
	cpt_release_buf(ctx);

	cpt_dump_sock_attr(sk, ctx);

	dump_rqueue(index, sk, ctx);
	if (sk->sk_family == AF_INET || sk->sk_family == AF_INET6) {
		dump_wqueue(index, sk, ctx);
		cpt_dump_ofo_queue(index, sk, ctx);
	}

	if ((sk->sk_family == AF_INET || sk->sk_family == AF_INET6)
	    && sk->sk_state == TCP_LISTEN)
		cpt_dump_synwait_queue(sk, index, ctx);

	cpt_close_object(ctx);

	if ((sk->sk_family == AF_INET || sk->sk_family == AF_INET6)
	    && sk->sk_state == TCP_LISTEN) {
		int err = cpt_dump_accept_queue(sk, index, ctx);
		if (err)
			return err;
	}
	return 0;
}

int cpt_dump_orphaned_sockets(struct cpt_context *ctx)
{
	int i, err = 0;

	cpt_open_section(ctx, CPT_SECT_ORPHANS);

	for (i = 0; i < tcp_hashinfo.ehash_size; i++) {
		struct sock *sk;
		struct hlist_nulls_node *node;
		spinlock_t *lock = inet_ehash_lockp(&tcp_hashinfo, i);
retry:
		spin_lock_bh(lock);
		sk_nulls_for_each(sk, node, &tcp_hashinfo.ehash[i].chain) {

			if (sk->owner_env != get_exec_env())
				continue;
			if (sk->sk_socket)
				continue;
			if (!sock_flag(sk, SOCK_DEAD))
				continue;
			if (lookup_cpt_object(CPT_OBJ_SOCKET, sk, ctx))
				continue;
			sock_hold(sk);
			spin_unlock_bh(lock);

			local_bh_disable();
			bh_lock_sock(sk);
			if (sock_owned_by_user(sk))
				eprintk_ctx("BUG: sk locked by whom?\n");
			sk->sk_lock.owned = 1;
			bh_unlock_sock(sk);
			local_bh_enable();

			err = cpt_dump_socket(NULL, sk, -1, -1, ctx);

			local_bh_disable();
			bh_lock_sock(sk);
			sk->sk_lock.owned = 0;
			clear_backlog(sk);
			tcp_done(sk);
			bh_unlock_sock(sk);
			local_bh_enable();
			sock_put(sk);

			if (err)
				return err;

			goto retry;
		}
		spin_unlock_bh(lock);
	}
	cpt_close_section(ctx);
	return err;
}

static int can_dump(struct sock *sk, cpt_context_t *ctx)
{
	switch (sk->sk_family) {
	case AF_NETLINK:
		if (((struct netlink_sock *)sk)->cb) {
			eprintk_ctx("netlink socket has active callback\n");
			return 0;
		}
		break;
	}
	return 1;
}

/* We are not going to block suspend when we have external AF_UNIX connections.
 * But we cannot stop feed of new packets/connections to our environment
 * from outside. Taking into account that it is intrincically unreliable,
 * we collect some amount of data, but when checkpointing/restoring we
 * are going to drop everything, which does not make sense: skbs sent
 * by outside processes, connections from outside etc. etc.
 */

/* The first pass. When we see socket referenced by a file, we just
 * add it to socket table */
int cpt_collect_socket(struct file *file, cpt_context_t * ctx)
{
	cpt_object_t *obj;
	struct socket *sock;
	struct sock *sk;

	if (!S_ISSOCK(file->f_dentry->d_inode->i_mode))
		return -ENOTSOCK;
	sock = &container_of(file->f_dentry->d_inode, struct socket_alloc, vfs_inode)->socket;
	sk = sock->sk;
	if (!can_dump(sk, ctx))
		return -EAGAIN;
	if ((obj = cpt_object_add(CPT_OBJ_SOCKET, sk, ctx)) == NULL)
		return -ENOMEM;
	obj->o_parent = file;

	return 0;
}

/*
 * We should end with table containing:
 *  * all sockets opened by our processes in the table.
 *  * all the sockets queued in listening queues on _our_ listening sockets,
 *    which are connected to our opened sockets.
 */

static int collect_one_unix_listening_sock(cpt_object_t *obj, cpt_context_t * ctx)
{
	struct sock *sk = obj->o_obj;
	cpt_object_t *cobj;
	struct sk_buff *skb;

	skb = skb_peek(&sk->sk_receive_queue);
	while (skb && skb != (struct sk_buff*)&sk->sk_receive_queue) {
		struct sock *lsk = skb->sk;
		if (unix_peer(lsk) &&
		    lookup_cpt_object(CPT_OBJ_SOCKET, unix_peer(lsk), ctx)) {
			if ((cobj = cpt_object_add(CPT_OBJ_SOCKET, lsk, ctx)) == NULL)
				return -ENOMEM;
			cobj->o_parent = obj->o_parent;
		}
		spin_lock_irq(&sk->sk_receive_queue.lock);
		skb = skb->next;
		spin_unlock_irq(&sk->sk_receive_queue.lock);
	}

	return 0;
}

int cpt_index_sockets(cpt_context_t * ctx)
{
	cpt_object_t *obj;
	unsigned long index = 0;

	/* Collect not-yet-accepted children of listening sockets. */
	for_each_object(obj, CPT_OBJ_SOCKET) {
		struct sock *sk = obj->o_obj;

		if (sk->sk_state != TCP_LISTEN)
			continue;

		if (sk->sk_family == AF_UNIX)
			collect_one_unix_listening_sock(obj, ctx);
	}

	/* Assign indices to all the sockets. */
	for_each_object(obj, CPT_OBJ_SOCKET) {
		struct sock *sk = obj->o_obj;
		cpt_obj_setindex(obj, index++, ctx);

		if (sk->sk_socket && sk->sk_socket->file) {
			cpt_object_t *tobj;
			tobj = lookup_cpt_object(CPT_OBJ_FILE, sk->sk_socket->file, ctx);
			if (tobj)
				cpt_obj_setindex(tobj, obj->o_index, ctx);
		}
	}

	return 0;
}

void cpt_unlock_sockets(cpt_context_t * ctx)
{
	cpt_object_t *obj;

	lockdep_off();
	for_each_object(obj, CPT_OBJ_SOCKET) {
		struct sock *sk = obj->o_obj;
		if (sk && obj->o_lock) {
			if (sk->sk_socket)
				release_sock(sk);
		}
	}
	lockdep_on();
}

void cpt_kill_sockets(cpt_context_t * ctx)
{
	cpt_object_t *obj;

	for_each_object(obj, CPT_OBJ_SOCKET) {
		struct sock *sk = obj->o_obj;
		if (sk && obj->o_lock) {
			struct ve_struct *old_env;
			old_env = set_exec_env(sk->owner_env);
			cpt_kill_socket(sk, ctx);
			if (sk->sk_socket)
				release_sock_nobacklog(sk);
			set_exec_env(old_env);
		}
	}
}

__u32 cpt_socket_fasync(struct file *file, struct cpt_context *ctx)
{
	struct fasync_struct *fa;
	struct inode *inode = file->f_dentry->d_inode;
	struct socket *sock;

	sock = &container_of(inode, struct socket_alloc, vfs_inode)->socket;

	for (fa = sock->fasync_list; fa; fa = fa->fa_next) {
		if (fa->fa_file == file)
			return fa->fa_fd;
	}
	return -1;
}
