/*
 * Functions related to io context handling
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/bootmem.h>	/* for max_pfn/max_low_pfn */

#include "blk.h"

/*
 * For io context allocations
 */
static struct kmem_cache *iocontext_cachep;

static void cfq_dtor(struct io_context *ioc)
{
	if (!hlist_empty(&ioc->cic_list)) {
		struct cfq_io_context *cic;

		cic = list_entry(ioc->cic_list.first, struct cfq_io_context,
								cic_list);
		cic->dtor(ioc);
	}
}

/*
 * IO Context helper functions. put_io_context() returns 1 if there are no
 * more users of this io context, 0 otherwise.
 */
int put_io_context(struct io_context *ioc)
{
	if (ioc == NULL)
		return 1;

	BUG_ON(atomic_long_read(&ioc->refcount) == 0);

	if (atomic_long_dec_and_test(&ioc->refcount)) {
		rcu_read_lock();
		if (ioc->aic && ioc->aic->dtor)
			ioc->aic->dtor(ioc->aic);
		cfq_dtor(ioc);
		rcu_read_unlock();
#ifdef CONFIG_BEANCOUNTERS
		put_beancounter(ioc->ioc_ub);
#endif
		kmem_cache_free(iocontext_cachep, ioc);
		return 1;
	}
	return 0;
}
EXPORT_SYMBOL(put_io_context);

static void cfq_exit(struct io_context *ioc)
{
	rcu_read_lock();

	if (!hlist_empty(&ioc->cic_list)) {
		struct cfq_io_context *cic;

		cic = list_entry(ioc->cic_list.first, struct cfq_io_context,
								cic_list);
		cic->exit(ioc);
	}
	rcu_read_unlock();
}

/* Called by the exitting task */
void exit_io_context(struct task_struct *task)
{
	struct io_context *ioc;

	task_lock(task);
	ioc = task->io_context;
	task->io_context = NULL;
	task_unlock(task);

	ioc_task_unlink(ioc);
}
EXPORT_SYMBOL(exit_io_context);

void ioc_task_unlink(struct io_context *ioc)
{
	if (atomic_dec_and_test(&ioc->nr_tasks)) {
		if (ioc->aic && ioc->aic->exit)
			ioc->aic->exit(ioc->aic);
		cfq_exit(ioc);

	}
	put_io_context(ioc);
}
EXPORT_SYMBOL(ioc_task_unlink);

struct io_context *alloc_io_context(gfp_t gfp_flags, int node)
{
	struct io_context *ret;

	ret = kmem_cache_alloc_node(iocontext_cachep, gfp_flags, node);
	if (ret) {
		atomic_long_set(&ret->refcount, 1);
		atomic_set(&ret->nr_tasks, 1);
		spin_lock_init(&ret->lock);
		ret->ioprio = 0;
		ret->last_waited = jiffies; /* doesn't matter... */
		ret->nr_batch_requests = 0; /* because this is 0 */
		ret->aic = NULL;
		INIT_RADIX_TREE(&ret->radix_root, GFP_ATOMIC | __GFP_HIGH);
		INIT_HLIST_HEAD(&ret->cic_list);
		ret->ioc_data = NULL;
#ifdef CONFIG_BEANCOUNTERS
		ret->ioc_ub = get_beancounter(get_exec_ub_top());
#endif
	}

	return ret;
}

/*
 * If the current task has no IO context then create one and initialise it.
 * Otherwise, return its existing IO context.
 *
 * This returned IO context doesn't have a specifically elevated refcount,
 * but since the current task itself holds a reference, the context can be
 * used in general code, so long as it stays within `current` context.
 */
struct io_context *current_io_context(gfp_t gfp_flags, int node)
{
	struct task_struct *tsk = current;
	struct io_context *ret;

	ret = tsk->io_context;
	if (likely(ret))
		return ret;

	ret = alloc_io_context(gfp_flags, node);
	if (ret) {
		/* make sure set_task_ioprio() sees the settings above */
		smp_wmb();
		tsk->io_context = ret;
	}

	return ret;
}
EXPORT_SYMBOL(current_io_context);

/*
 * If the current task has no IO context then create one and initialise it.
 * If it does have a context, take a ref on it.
 *
 * This is always called in the context of the task which submitted the I/O.
 */
struct io_context *get_io_context(gfp_t gfp_flags, int node)
{
	struct io_context *ret = NULL;

	/*
	 * Check for unlikely race with exiting task. ioc ref count is
	 * zero when ioc is being detached.
	 */
	do {
		ret = current_io_context(gfp_flags, node);
		if (unlikely(!ret))
			break;
	} while (!atomic_long_inc_not_zero(&ret->refcount));

	return ret;
}
EXPORT_SYMBOL(get_io_context);

void copy_io_context(struct io_context **pdst, struct io_context **psrc)
{
	struct io_context *src = *psrc;
	struct io_context *dst = *pdst;

	if (src) {
		BUG_ON(atomic_long_read(&src->refcount) == 0);
		atomic_long_inc(&src->refcount);
		put_io_context(dst);
		*pdst = src;
	}
}
EXPORT_SYMBOL(copy_io_context);

void ioc_set_changed(struct io_context *ioc, int which)
{
	struct cfq_io_context *cic;
	struct hlist_node *n;

	hlist_for_each_entry(cic, n, &ioc->cic_list, cic_list)
		set_bit(which, &cic->changed);
}

/**
 * ioc_ioprio_changed - notify ioprio change
 * @ioc: io_context of interest
 * @ioprio: new ioprio
 *
 * @ioc's ioprio has changed to @ioprio.  Set %CIC_IOPRIO_CHANGED for all
 * cic's.  iosched is responsible for checking the bit and applying it on
 * request issue path.
 */
void ioc_ioprio_changed(struct io_context *ioc, int ioprio)
{
	unsigned long flags;

	spin_lock_irqsave(&ioc->lock, flags);
	ioc->ioprio = ioprio;
	ioc_set_changed(ioc, CIC_IOPRIO_CHANGED);
	spin_unlock_irqrestore(&ioc->lock, flags);
}

/**
 * ioc_cgroup_changed - notify cgroup change
 * @ioc: io_context of interest
 *
 * @ioc's cgroup has changed.  Set %CIC_CGROUP_CHANGED for all cic's.
 * iosched is responsible for checking the bit and applying it on request
 * issue path.
 */
void ioc_cgroup_changed(struct io_context *ioc)
{
	unsigned long flags;

	spin_lock_irqsave(&ioc->lock, flags);
	ioc_set_changed(ioc, CIC_CGROUP_CHANGED);
	spin_unlock_irqrestore(&ioc->lock, flags);
}

static int __init blk_ioc_init(void)
{
	iocontext_cachep = kmem_cache_create("blkdev_ioc",
			sizeof(struct io_context), 0, SLAB_PANIC, NULL);
	return 0;
}
subsys_initcall(blk_ioc_init);
