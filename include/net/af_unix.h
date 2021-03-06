#ifndef __LINUX_NET_AFUNIX_H
#define __LINUX_NET_AFUNIX_H

#include <linux/socket.h>
#include <linux/un.h>
#include <linux/mutex.h>
#include <net/sock.h>

void unix_inflight(struct user_struct *user, struct file *fp);
void unix_notinflight(struct user_struct *user, struct file *fp);
extern void unix_gc(void);
extern void wait_for_unix_gc(void);
extern struct sock *unix_get_socket(struct file *filp);
extern void unix_destruct_scm(struct sk_buff *skb);

#define UNIX_HASH_SIZE	256

extern unsigned int unix_tot_inflight;

struct unix_address {
	atomic_t	refcnt;
	int		len;
	unsigned	hash;
	struct sockaddr_un name[0];
};

int unix_bind_path(struct sock *, struct dentry *, struct vfsmount *);
int unix_attach_addr(struct sock *, struct sockaddr_un *, int);

struct unix_skb_parms {
	struct pid		*pid;		/* Skb credentials	*/
	const struct cred	*cred;
	struct scm_fp_list	*fp;		/* Passed files		*/
#ifdef CONFIG_SECURITY_NETWORK
	u32			secid;		/* Security ID		*/
#endif
	u32			consumed;
};

#define UNIXCB(skb) 	(*(struct unix_skb_parms*)&((skb)->cb))
#define UNIXSID(skb)	(&UNIXCB((skb)).secid)

#define unix_state_lock(s)	spin_lock(&unix_sk(s)->lock)
#define unix_state_unlock(s)	spin_unlock(&unix_sk(s)->lock)
#define unix_state_lock_nested(s) \
				spin_lock_nested(&unix_sk(s)->lock, \
				SINGLE_DEPTH_NESTING)

#ifdef __KERNEL__
/* The AF_UNIX socket */
struct unix_sock {
	/* WARNING: sk has to be the first member */
	struct sock		sk;
        struct unix_address     *addr;
        struct dentry		*dentry;
        struct vfsmount		*mnt;
	struct mutex		readlock;
        struct sock		*peer;
        struct sock		*other;
	struct list_head	link;
        atomic_long_t           inflight;
        spinlock_t		lock;
	unsigned char		recursion_level;
	unsigned long		gc_flags;
#define UNIX_GC_CANDIDATE	0
#define UNIX_GC_MAYBE_CYCLE	1
        wait_queue_head_t       peer_wait;
	wait_queue_t		peer_wake;
};
#define unix_sk(__sk) ((struct unix_sock *)__sk)

#ifdef CONFIG_SYSCTL
extern int unix_sysctl_register(struct net *net);
extern void unix_sysctl_unregister(struct net *net);
#else
static inline int unix_sysctl_register(struct net *net) { return 0; }
static inline void unix_sysctl_unregister(struct net *net) {}
#endif
#endif
#endif
