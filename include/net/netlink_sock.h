#ifndef __NET_NETLINK_SOCK_H
#define __NET_NETLINK_SOCK_H

struct netlink_sock {
	/* struct sock has to be the first member of netlink_sock */
	struct sock		sk;
	u32			pid;
	u32			dst_pid;
	u32			dst_group;
	u32			flags;
	u32			subscriptions;
	u32			ngroups;
	unsigned long		*groups;
	unsigned long		state;
	wait_queue_head_t	wait;
	struct netlink_callback	*cb;
	struct mutex		*cb_mutex;
	struct mutex		cb_def_mutex;
	void			(*netlink_rcv)(struct sk_buff *skb);
	struct module		*module;
};

#endif /* __NET_NETLINK_SOCK_H */
