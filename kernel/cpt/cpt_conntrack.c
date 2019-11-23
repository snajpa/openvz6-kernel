/*
 *
 *  kernel/cpt/cpt_conntrack.c
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
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/rtnetlink.h>
#include <linux/unistd.h>
#include <linux/ve.h>
#include <linux/vzcalluser.h>
#include <linux/cpt_image.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/rculist_nulls.h>

#if defined(CONFIG_VE_IPTABLES) && \
    (defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE))

#include <linux/netfilter.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_conntrack_tuple.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_core.h>

#include <linux/cpt_obj.h>
#include <linux/cpt_context.h>


/* How does it work?
 *
 * Network is disabled, so new conntrack entries will not appear.
 * However, some of them can disappear because of timeouts.
 *
 * So, we take read_lock, collect all required information atomically,
 * essentially, creating parallel "refcount" structures holding pointers.
 * We delete conntrack timers as well, so the structures cannot disappear
 * after releasing the lock. Now, after releasing lock we can dump everything
 * safely. And on exit we restore timers to their original values.
 *
 * Note, this approach is not going to work in VE0.
 */

struct ct_holder
{
	struct ct_holder *next;
	struct nf_conntrack_tuple_hash *cth;
	int index;
};

static void encode_tuple(struct cpt_ipct_tuple *v, struct nf_conntrack_tuple *tuple)
{
	v->cpt_dst = tuple->dst.u3.ip;
	v->cpt_l3num = tuple->src.l3num;
	v->cpt_dstport = tuple->dst.u.all;
	v->cpt_protonum = tuple->dst.protonum;
	v->cpt_dir = tuple->dst.dir;

	v->cpt_src = tuple->src.u3.ip;
	v->cpt_srcport = tuple->src.u.all;
}

static void encode_tuple_mask(struct cpt_ipct_tuple *v, struct nf_conntrack_tuple_mask *tuple)
{
	v->cpt_src = tuple->src.u3.ip;
	v->cpt_srcport = tuple->src.u.all;
}

static int dump_one_expect(struct cpt_ip_connexpect_image *v,
			   struct nf_conntrack_expect *exp,
			   int sibling, cpt_context_t *ctx)
{
	int err = 0;

	v->cpt_next = sizeof(*v);
	v->cpt_object = CPT_OBJ_NET_CONNTRACK_EXPECT;
	v->cpt_hdrlen = sizeof(*v);
	v->cpt_content = CPT_CONTENT_VOID;

	encode_tuple(&v->cpt_tuple, &exp->tuple);
	encode_tuple_mask(&v->cpt_mask, &exp->mask);
	v->cpt_sibling_conntrack = sibling;
	v->cpt_flags = exp->flags;
	v->cpt_dir = 0;
#ifdef CONFIG_IP_NF_NAT_NEEDED
	v->cpt_manip_proto = exp->saved_proto.all;
	v->cpt_dir = exp->dir;
#endif
	v->cpt_timeout = exp->timeout.expires - jiffies;
	v->cpt_class = exp->class;
	return err;
}

/* NOTE. We use one page to dump list of expectations. This may be not enough
 * in theory. In practice there is only one expectation per conntrack record.
 * Moreover, taking into account that _ALL_ of expecations are saved in one
 * global list, which is looked up each incoming/outpging packet, the system
 * would be severely dead when even one conntrack would have so much of
 * expectations. Shortly, I am not going to repair this.
 */

static int dump_expect_list(struct nf_conn *ct, struct ct_holder *list,
			    cpt_context_t *ctx)
{
	int err = 0;
	unsigned long pg;
	struct cpt_ip_connexpect_image *v;
	struct nf_conntrack_expect *exp;
	struct nf_conn_help *help = nfct_help(ct);
	struct hlist_node *next;
	int expecting = 0, i;

	if (!help)
		return 0;

	for (i = 0; i < NF_CT_MAX_EXPECT_CLASSES; i++)
		expecting += help->expecting[i];

	if (expecting == 0)
		return err;
	if (expecting*sizeof(struct cpt_ip_connexpect_image) > PAGE_SIZE)
		return -ENOBUFS;

	pg = __get_free_page(GFP_KERNEL);
	if (!pg)
		return -ENOMEM;
	v = (struct cpt_ip_connexpect_image *)pg;

	spin_lock_bh(&nf_conntrack_lock);
	hlist_for_each_entry(exp, next, &help->expectations, lnode) {
		int sibling;

		if (exp->master != ct)
			continue;

		if (help->helper == NULL) {
			eprintk_ctx("conntrack: no helper and non-trivial expectation\n");
			err = -EINVAL;
			break;
		}

		sibling = 0;
#if 0
		/* That's all? No need to calculate sibling? */
		if (exp->sibling) {
			struct ct_holder *c;
			for (c = list; c; c = c->next) {
				if (tuplehash_to_ctrack(c->cth) == exp->sibling) {
					sibling = c->index;
					break;
				}
			}
			/* NOTE: exp->sibling could be not "confirmed" and, hence,
			 * out of hash table. We should just ignore such a sibling,
			 * the connection is going to be retried, the packet
			 * apparently was lost somewhere.
			 */
			if (sibling == 0)
				dprintk_ctx("sibling conntrack is not found\n");
		}
#endif

		/* If the expectation still does not have exp->sibling
		 * and timer is not running, it is about to die on another
		 * cpu. Skip it. */
		if (!del_timer(&exp->timeout)) {
			dprintk_ctx("conntrack: expectation: no timer\n");
			continue;
		}

		err = dump_one_expect(v, exp, sibling, ctx);

		add_timer(&exp->timeout);

		if (err)
			break;

		v++;
	}
	spin_unlock_bh(&nf_conntrack_lock);

	if (err == 0 && (unsigned long)v != pg)
		ctx->write((void*)pg, (unsigned long)v - pg, ctx);

	free_page(pg);
	return err;
}

static int dump_one_ct(struct ct_holder *c, struct ct_holder *list,
		       cpt_context_t *ctx)
{
	struct nf_conntrack_tuple_hash *h = c->cth;
	struct nf_conn *ct = nf_ct_tuplehash_to_ctrack(h);
	struct nf_conn_nat *nat = nfct_nat(ct);
	struct cpt_ip_conntrack_image v;
	const struct nf_conn_help *help;
	int err = 0;

	BUILD_BUG_ON(sizeof(v.cpt_proto_data) < sizeof(ct->proto));
	BUILD_BUG_ON(sizeof(v.cpt_help_data) < sizeof(union nf_conntrack_help));

	rcu_read_lock_bh();
	help = nfct_help(ct);
	if (help) {
		const struct nf_conntrack_helper *helper;

		helper = rcu_dereference(help->helper);
		if (helper && !strcmp(helper->name, "pptp")) {
			eprintk_ctx("conntrack: PPTP isn't supported\n");
			err = -EBUSY;
		}
	}
	rcu_read_unlock_bh();

	if (err)
		return err;

	cpt_open_object(NULL, ctx);

	v.cpt_next = CPT_NULL;
	v.cpt_object = CPT_OBJ_NET_CONNTRACK;
	v.cpt_hdrlen = sizeof(v);
	v.cpt_content = CPT_CONTENT_ARRAY;

	rcu_read_lock_bh();
	v.cpt_status = ct->status;
	v.cpt_timeout = ct->timeout.expires - jiffies;
	v.cpt_ct_helper = (nfct_help(ct) != NULL);
	v.cpt_index = c->index;
	v.cpt_mark = 0;
#if defined(CONFIG_NF_CONNTRACK_MARK)
	v.cpt_mark = ct->mark;
#endif
	encode_tuple(&v.cpt_tuple[0], &ct->tuplehash[0].tuple);
	encode_tuple(&v.cpt_tuple[1], &ct->tuplehash[1].tuple);
	memcpy(&v.cpt_proto_data, &ct->proto, sizeof(v.cpt_proto_data));
	if (nfct_help(ct))
		memcpy(&v.cpt_help_data, &nfct_help(ct)->help, sizeof(v.cpt_help_data));

	v.cpt_masq_index = 0;
	v.cpt_nat_helper = 0;
	if (nat) {
#ifdef CONFIG_NF_NAT_NEEDED
#if defined(CONFIG_IP_NF_TARGET_MASQUERADE) || \
	defined(CONFIG_IP_NF_TARGET_MASQUERADE_MODULE)
		v.cpt_masq_index = nat->masq_index;
#endif
	/* "help" data is used by pptp, difficult to support */
		v.cpt_nat_seq[0].cpt_correction_pos = nat->seq[0].correction_pos;
		v.cpt_nat_seq[0].cpt_offset_before = nat->seq[0].offset_before;
		v.cpt_nat_seq[0].cpt_offset_after = nat->seq[0].offset_after;
		v.cpt_nat_seq[1].cpt_correction_pos = nat->seq[1].correction_pos;
		v.cpt_nat_seq[1].cpt_offset_before = nat->seq[1].offset_before;
		v.cpt_nat_seq[1].cpt_offset_after = nat->seq[1].offset_after;
#endif
	}
	rcu_read_unlock_bh();

	ctx->write(&v, sizeof(v), ctx);

	err = dump_expect_list(ct, list, ctx);

	cpt_close_object(ctx);
	return err;
}

int cpt_dump_ip_conntrack(cpt_context_t * ctx)
{
	struct ct_holder *ct_list = NULL;
	struct ct_holder *c, **cp;
	struct nf_conn *ct;
	int err = 0;
	int index = 0;
	int idx;
	struct net *net = get_exec_env()->ve_netns;
	struct hlist_nulls_node *n;

	for (idx = atomic_read(&(net->ct.count)); idx >= 0; idx--) {
		c = kmalloc(sizeof(struct ct_holder), GFP_KERNEL);
		if (c == NULL) {
			err = -ENOMEM;
			goto done;
		}
		memset(c, 0, sizeof(struct ct_holder));
		c->next = ct_list;
		ct_list = c;
	}

	c = ct_list;

	rcu_read_lock_bh();
	for (idx = 0; idx < net->ct.htable_size; idx++) {
		struct nf_conntrack_tuple_hash *h;
                hlist_nulls_for_each_entry_rcu(h, n, &net->ct.hash[idx], hnnode) {
			/* Skip reply tuples, they are covered by original
			 * direction. */
			if (NF_CT_DIRECTION(h))
				continue;

			/* Oops, we have not enough of holders...
			 * It is impossible. */
			if (unlikely(c == NULL)) {
				rcu_read_unlock_bh();
				eprintk_ctx("unexpected conntrack appeared\n");
				err = -ENOMEM;
				goto done;
			}

			/* If timer is not running, it means that it
			 * has just been scheduled on another cpu.
			 * We should skip this conntrack, it is about to be
			 * destroyed. */
			if (!del_timer(&nf_ct_tuplehash_to_ctrack(h)->timeout)) {
				dprintk_ctx("conntrack: no timer\n");
				continue;
			}

			/* Timer is deleted. refcnt is _not_ decreased.
			 * We are going to restore the timer on exit
			 * from this function. */
			c->cth = h;
			ct = nf_ct_tuplehash_to_ctrack(h);
			nf_conntrack_get(&ct->ct_general);
			c->index = ++index;
			c = c->next;
		}
	}
	rcu_read_unlock_bh();

	/* No conntracks? Good. */
	if (index == 0)
		goto done;

	/* Comb the list a little. */
	cp = &ct_list;
	while ((c = *cp) != NULL) {
		/* Discard unused entries; they can appear, if some
		 * entries were timed out since we preallocated the list.
		 */
		if (c->cth == NULL) {
			*cp = c->next;
			kfree(c);
			continue;
		}

		/* Move conntracks attached to expectations to the beginning
		 * of the list. */
		if (nf_ct_tuplehash_to_ctrack(c->cth)->master && c != ct_list) {
			*cp = c->next;
			c->next = ct_list;
			ct_list = c;
			dprintk_ctx("conntrack: %d moved in list\n", c->index);
			continue;
		}
		cp = &c->next;
	}

	cpt_open_section(ctx, CPT_SECT_NET_CONNTRACK);

	for (c = ct_list; c; c = c->next) {
		err = dump_one_ct(c, ct_list, ctx);
		if (err)
			goto done;
	}

	cpt_close_section(ctx);

done:
	while ((c = ct_list) != NULL) {
		ct_list = c->next;
		if (c->cth) {
			ct = nf_ct_tuplehash_to_ctrack(c->cth);
			nf_conntrack_put(&ct->ct_general);
			/* Restore timer. refcnt is preserved. */
			add_timer(&nf_ct_tuplehash_to_ctrack(c->cth)->timeout);
		}
		kfree(c);
	}
	return err;
}

#endif
