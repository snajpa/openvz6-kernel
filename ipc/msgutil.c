/*
 * linux/ipc/msgutil.c
 * Copyright (C) 1999, 2004 Manfred Spraul
 *
 * This file is released under GNU General Public Licence version 2 or
 * (at your option) any later version.
 *
 * See the file COPYING for more details.
 */

#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/ipc.h>
#include <linux/ipc_namespace.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>

#include "util.h"

#include <bc/kmem.h>

DEFINE_SPINLOCK(mq_lock);

/*
 * The next 2 defines are here bc this is the only file
 * compiled when either CONFIG_SYSVIPC and CONFIG_POSIX_MQUEUE
 * and not CONFIG_IPC_NS.
 */
struct ipc_namespace init_ipc_ns = {
	.count		= ATOMIC_INIT(1),
#ifdef CONFIG_POSIX_MQUEUE
	.mq_queues_max   = DFLT_QUEUESMAX,
	.mq_msg_max      = DFLT_MSGMAX,
	.mq_msgsize_max  = DFLT_MSGSIZEMAX,
	.mq_msg_default	    = DFLT_MSG,
	.mq_msgsize_default = DFLT_MSGSIZE,
#endif
	.proc_inum = PROC_IPC_INIT_INO,
};

atomic_t nr_ipc_ns = ATOMIC_INIT(1);

struct msg_msgseg {
	struct msg_msgseg* next;
	/* the next part of the message follows immediately */
};

#define DATALEN_MSG	(PAGE_SIZE-sizeof(struct msg_msg))
#define DATALEN_SEG	(PAGE_SIZE-sizeof(struct msg_msgseg))

struct msg_msg *sysv_msg_load(int (*load)(void * dst, int len, int offset,
					  void * data), int len, void * data)
{
	struct msg_msg *msg;
	struct msg_msgseg **pseg;
	int err;
	int alen;
	int offset = 0;

	alen = len;
	if (alen > DATALEN_MSG)
		alen = DATALEN_MSG;

	msg = kmalloc(sizeof(*msg) + alen, GFP_KERNEL_UBC);
	if (msg == NULL)
		return ERR_PTR(-ENOMEM);

	msg->next = NULL;
	msg->security = NULL;

	if (load(msg + 1, alen, offset, data)) {
		err = -EFAULT;
		goto out_err;
	}

	len -= alen;
	offset += alen;
	pseg = &msg->next;
	while (len > 0) {
		struct msg_msgseg *seg;
		alen = len;
		if (alen > DATALEN_SEG)
			alen = DATALEN_SEG;
		seg = kmalloc(sizeof(*seg) + alen, GFP_KERNEL_UBC);
		if (seg == NULL) {
			err = -ENOMEM;
			goto out_err;
		}
		*pseg = seg;
		seg->next = NULL;
		if (load(seg + 1, alen, offset, data)) {
			err = -EFAULT;
			goto out_err;
		}
		pseg = &seg->next;
		len -= alen;
		offset += alen;
	}

	err = security_msg_msg_alloc(msg);
	if (err)
		goto out_err;

	return msg;

out_err:
	free_msg(msg);
	return ERR_PTR(err);
}
EXPORT_SYMBOL_GPL(sysv_msg_load);

static int do_load_msg(void * dst, int len, int offset, void * data)
{
	return copy_from_user(dst, data + offset, len);
}

struct msg_msg *load_msg(const void __user *src, int len)
{
	return sysv_msg_load(do_load_msg, len, (void*)src);
}

int sysv_msg_store(struct msg_msg *msg,
		   int (*store)(void * src, int len, int offset, void * data),
		   int len, void * data)
{
	int alen;
	int offset = 0;
	struct msg_msgseg *seg;
	
	alen = len;
	if (alen > DATALEN_MSG)
		alen = DATALEN_MSG;
	if (store(msg + 1, alen, offset, data))
		return -1;

	len -= alen;
	offset += alen;
	seg = msg->next;
	while (len > 0) {
		alen = len;
		if (alen > DATALEN_SEG)
			alen = DATALEN_SEG;
		if (store(seg + 1, alen, offset, data))
			return -1;
		len -= alen;
		offset += alen;
		seg = seg->next;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(sysv_msg_store);

static int do_store_msg(void * src, int len, int offset, void * data)
{
	return copy_to_user(data + offset, src, len);
}

int store_msg(void __user *dest, struct msg_msg *msg, int len)
{
	return sysv_msg_store(msg, do_store_msg, len, dest);
}

void free_msg(struct msg_msg *msg)
{
	struct msg_msgseg *seg;

	security_msg_msg_free(msg);

	seg = msg->next;
	kfree(msg);
	while (seg != NULL) {
		struct msg_msgseg *tmp = seg->next;
		kfree(seg);
		seg = tmp;
	}
}
