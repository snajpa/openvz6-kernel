#undef TRACE_SYSTEM
#define TRACE_SYSTEM writeback

#if !defined(_TRACE_WRITEBACK_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_WRITEBACK_H

#include <linux/backing-dev.h>
#include <linux/device.h>
#include <linux/writeback.h>

struct wb_writeback_work;

#define show_inode_state(state)					\
	__print_flags(state, "|",				\
		      {I_DIRTY_SYNC,		"I_DIRTY_SYNC"},	\
		      {I_DIRTY_DATASYNC,	"I_DIRTY_DATASYNC"},	\
		      {I_DIRTY_PAGES,		"I_DIRTY_PAGES"},	\
		      {I_NEW,			"I_NEW"},		\
		      {I_WILL_FREE,		"I_WILL_FREE"},		\
		      {I_FREEING,		"I_FREEING"},		\
		      {I_CLEAR,		"I_CLEAR"},			\
		      {I_SYNC,		"I_SYNC"},			\
		      {I_DIRTY_TIME,		"I_DIRTY_TIME"},	\
		      {I_DIRTY_TIME_EXPIRED,	"I_DIRTY_TIME_EXPIRED"})

DECLARE_EVENT_CLASS(writeback_work_class,
	TP_PROTO(struct backing_dev_info *bdi, struct wb_writeback_work *work),
	TP_ARGS(bdi, work),
	TP_STRUCT__entry(
		__array(char, name, 32)
		__field(long, nr_pages)
		__field(dev_t, sb_dev)
		__field(int, sync_mode)
		__field(int, for_kupdate)
		__field(int, range_cyclic)
		__field(int, for_background)
	),
	TP_fast_assign(
		strncpy(__entry->name, dev_name(bdi->dev), 32);
		__entry->nr_pages = work->nr_pages;
		__entry->sb_dev = work->sb ? work->sb->s_dev : 0;
		__entry->sync_mode = work->sync_mode;
		__entry->for_kupdate = work->for_kupdate;
		__entry->range_cyclic = work->range_cyclic;
		__entry->for_background	= work->for_background;
	),
	TP_printk("bdi %s: sb_dev %d:%d nr_pages=%ld sync_mode=%d "
		  "kupdate=%d range_cyclic=%d background=%d",
		  __entry->name,
		  MAJOR(__entry->sb_dev), MINOR(__entry->sb_dev),
		  __entry->nr_pages,
		  __entry->sync_mode,
		  __entry->for_kupdate,
		  __entry->range_cyclic,
		  __entry->for_background
	)
);
#define DEFINE_WRITEBACK_WORK_EVENT(name) \
DEFINE_EVENT(writeback_work_class, name, \
	TP_PROTO(struct backing_dev_info *bdi, struct wb_writeback_work *work), \
	TP_ARGS(bdi, work))
DEFINE_WRITEBACK_WORK_EVENT(writeback_nothread);
DEFINE_WRITEBACK_WORK_EVENT(writeback_queue);
DEFINE_WRITEBACK_WORK_EVENT(writeback_exec);

TRACE_EVENT(writeback_pages_written,
	TP_PROTO(long pages_written),
	TP_ARGS(pages_written),
	TP_STRUCT__entry(
		__field(long,		pages)
	),
	TP_fast_assign(
		__entry->pages		= pages_written;
	),
	TP_printk("%ld", __entry->pages)
);

DECLARE_EVENT_CLASS(writeback_class,
	TP_PROTO(struct backing_dev_info *bdi),
	TP_ARGS(bdi),
	TP_STRUCT__entry(
		__array(char, name, 32)
	),
	TP_fast_assign(
		strncpy(__entry->name, dev_name(bdi->dev), 32);
	),
	TP_printk("bdi %s",
		  __entry->name
	)
);
#define DEFINE_WRITEBACK_EVENT(name) \
DEFINE_EVENT(writeback_class, name, \
	TP_PROTO(struct backing_dev_info *bdi), \
	TP_ARGS(bdi))

DEFINE_WRITEBACK_EVENT(writeback_nowork);
DEFINE_WRITEBACK_EVENT(writeback_bdi_register);
DEFINE_WRITEBACK_EVENT(writeback_bdi_unregister);
DEFINE_WRITEBACK_EVENT(writeback_task_start);
DEFINE_WRITEBACK_EVENT(writeback_task_stop);

DECLARE_EVENT_CLASS(wbc_class,
	TP_PROTO(struct writeback_control *wbc, struct backing_dev_info *bdi),
	TP_ARGS(wbc, bdi),
	TP_STRUCT__entry(
		__array(char, name, 32)
		__field(long, nr_to_write)
		__field(long, pages_skipped)
		__field(int, sync_mode)
		__field(int, nonblocking)
		__field(int, encountered_congestion)
		__field(int, for_kupdate)
		__field(int, for_background)
		__field(int, for_reclaim)
		__field(int, range_cyclic)
		__field(int, more_io)
		__field(unsigned long, older_than_this)
		__field(long, range_start)
		__field(long, range_end)
	),

	TP_fast_assign(
		strncpy(__entry->name, dev_name(bdi->dev), 32);
		__entry->nr_to_write	= wbc->nr_to_write;
		__entry->pages_skipped	= wbc->pages_skipped;
		__entry->sync_mode	= wbc->sync_mode;
		__entry->for_kupdate	= wbc->for_kupdate;
		__entry->for_background	= wbc->for_background;
		__entry->for_reclaim	= wbc->for_reclaim;
		__entry->range_cyclic	= wbc->range_cyclic;
		__entry->more_io	= wbc->more_io;
		__entry->older_than_this = wbc->older_than_this ?
						*wbc->older_than_this : 0;
		__entry->range_start	= (long)wbc->range_start;
		__entry->range_end	= (long)wbc->range_end;
	),

	TP_printk("bdi %s: towrt=%ld skip=%ld mode=%d kupd=%d "
		"bgrd=%d reclm=%d cyclic=%d more=%d older=0x%lx "
		"start=0x%lx end=0x%lx",
		__entry->name,
		__entry->nr_to_write,
		__entry->pages_skipped,
		__entry->sync_mode,
		__entry->for_kupdate,
		__entry->for_background,
		__entry->for_reclaim,
		__entry->range_cyclic,
		__entry->more_io,
		__entry->older_than_this,
		__entry->range_start,
		__entry->range_end)
)

#define DEFINE_WBC_EVENT(name) \
DEFINE_EVENT(wbc_class, name, \
	TP_PROTO(struct writeback_control *wbc, struct backing_dev_info *bdi), \
	TP_ARGS(wbc, bdi))
DEFINE_WBC_EVENT(wbc_writeback_start);
DEFINE_WBC_EVENT(wbc_writeback_written);
DEFINE_WBC_EVENT(wbc_writeback_wait);
DEFINE_WBC_EVENT(wbc_balance_dirty_start);
DEFINE_WBC_EVENT(wbc_balance_dirty_written);
DEFINE_WBC_EVENT(wbc_balance_dirty_wait);
DEFINE_WBC_EVENT(wbc_writepage);


DECLARE_EVENT_CLASS(writeback_dirty_inode_template,
	TP_PROTO(struct inode *inode, int flags),
	TP_ARGS(inode, flags),
	TP_STRUCT__entry (
		__array(char, name, 32)
		__field(unsigned long, ino)
		__field(unsigned long, state)
		__field(unsigned long, flags)
	),

	TP_fast_assign(
		struct backing_dev_info *bdi = inode->i_mapping->backing_dev_info;

		/* may be called for files on pseudo FSes w/ unregistered bdi */
		strncpy(__entry->name,
			bdi->dev ? dev_name(bdi->dev) : "(unknown)", 32);
		__entry->ino		= inode->i_ino;
		__entry->state		= inode->i_state;
		__entry->flags		= flags;
	),

	TP_printk("bdi %s: ino=%lu state=%s flags=%s",
		__entry->name,
		__entry->ino,
		show_inode_state(__entry->state),
		show_inode_state(__entry->flags)
	)
);

DEFINE_EVENT(writeback_dirty_inode_template, writeback_mark_inode_dirty,

	TP_PROTO(struct inode *inode, int flags),

	TP_ARGS(inode, flags)
);

DEFINE_EVENT(writeback_dirty_inode_template, writeback_dirty_inode_start,

	TP_PROTO(struct inode *inode, int flags),

	TP_ARGS(inode, flags)
);

DEFINE_EVENT(writeback_dirty_inode_template, writeback_dirty_inode,

	TP_PROTO(struct inode *inode, int flags),

	TP_ARGS(inode, flags)
);

DECLARE_EVENT_CLASS(writeback_lazytime_template,
	TP_PROTO(struct inode *inode),
	TP_ARGS(inode),
	TP_STRUCT__entry(
		__field(	dev_t,	dev			)
		__field(unsigned long,	ino			)
		__field(unsigned long,	state			)
		__field(	__u16, mode			)
		__field(unsigned long, dirtied_when		)
	),

	TP_fast_assign(
		__entry->dev	= inode->i_sb->s_dev;
		__entry->ino	= inode->i_ino;
		__entry->state	= inode->i_state;
		__entry->mode	= inode->i_mode;
		__entry->dirtied_when = inode->dirtied_when;
	),

	TP_printk("dev %d,%d ino %lu dirtied %lu state %s mode 0%o",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __entry->ino, __entry->dirtied_when,
		  show_inode_state(__entry->state), __entry->mode)
);

DEFINE_EVENT(writeback_lazytime_template, writeback_lazytime,
	TP_PROTO(struct inode *inode),

	TP_ARGS(inode)
);

DEFINE_EVENT(writeback_lazytime_template, writeback_lazytime_iput,
	TP_PROTO(struct inode *inode),

	TP_ARGS(inode)
);

DEFINE_EVENT(writeback_lazytime_template, writeback_dirty_inode_enqueue,

	TP_PROTO(struct inode *inode),

	TP_ARGS(inode)
);


#endif /* _TRACE_WRITEBACK_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
