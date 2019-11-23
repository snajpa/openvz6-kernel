#if !defined(_TRACE_EVENTS_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_EVENTS_H

#undef TRACE_SYSTEM
#define TRACE_SYSTEM ploop

#include <linux/sched.h>
#include <linux/tracepoint.h>

#include <linux/ploop/ploop.h>

#define PRINT_BI_RW(rw)	__print_flags(rw, "|",		\
			{ 1 << BIO_RW,				"W"},	\
			{ 1 << BIO_RW_FAILFAST_DEV,		"FD"},	\
			{ 1 << BIO_RW_FAILFAST_TRANSPORT,	"FT"},	\
			{ 1 << BIO_RW_FAILFAST_DRIVER,		"FDRV"},\
			{ 1 << BIO_RW_AHEAD,			"A"},	\
			{ 1 << BIO_RW_BARRIER,			"B"},	\
			{ 1 << BIO_RW_SYNCIO,			"S"},	\
			{ 1 << BIO_RW_UNPLUG,			"U"},	\
			{ 1 << BIO_RW_META,			"M"},	\
			{ 1 << BIO_RW_DISCARD,			"D"},	\
			{ 1 << BIO_RW_NOIDLE,			"N"},	\
			{ 1 << BIO_RW_FLUSH,			"F"},	\
			{ 1 << BIO_RW_FUA,			"FUA"},	\
			{ 1 << BIO_RW_THROTTLED,		"T"})

#define PRINT_PREQ_STATE(state)					\
			__print_flags(state, "|",		\
			{ 1 << PLOOP_REQ_LOCKOUT,	"L"},	\
			{ 1 << PLOOP_REQ_SYNC,		"S"},	\
			{ 1 << PLOOP_REQ_BARRIER,	"B"},	\
			{ 1 << PLOOP_REQ_UNSTABLE,	"U"},	\
			{ 1 << PLOOP_REQ_TRACK,		"TRACK"},\
			{ 1 << PLOOP_REQ_SORTED,	"SORT"},\
			{ 1 << PLOOP_REQ_TRANS,		"T"},	\
			{ 1 << PLOOP_REQ_MERGE,		"M"},	\
			{ 1 << PLOOP_REQ_RELOC_A,	"RA"},	\
			{ 1 << PLOOP_REQ_RELOC_S,	"RS"},	\
			{ 1 << PLOOP_REQ_RELOC_N,	"RN"},	\
			{ 1 << PLOOP_REQ_ZERO,		"Z"},	\
			{ 1 << PLOOP_REQ_DISCARD,	"D"})

#define PREQ_FORMAT "preq=0x%p cluster=0x%x iblock=0x%x size=0x%x eng_state=0x%lx state=%s rw=%s"

#define PREQ_ARGS	__entry->preq,				\
			__entry->clu,				\
			__entry->iblk,				\
			__entry->size,				\
			__entry->eng_state,			\
			PRINT_PREQ_STATE(__entry->state),	\
			PRINT_BI_RW(__entry->rw)

DECLARE_EVENT_CLASS(preq_template,
	TP_PROTO(struct ploop_request *preq),

	TP_ARGS(preq),

	TP_STRUCT__entry(
		__field(void *,		preq)
		__field(cluster_t,	clu)
		__field(iblock_t,	iblk)
		__field(unsigned int,	size)
		__field(unsigned long,	eng_state)
		__field(unsigned long,	state)
		__field(unsigned int,	rw)
	),

	TP_fast_assign(
		__entry->preq		= preq;
		__entry->clu		= preq->req_cluster;
		__entry->iblk		= preq->iblock;
		__entry->size		= preq->req_size;
		__entry->eng_state	= preq->eng_state;
		__entry->state		= preq->state;
		__entry->rw		= preq->req_rw;
	),

	TP_printk(PREQ_FORMAT, PREQ_ARGS)
);

DECLARE_EVENT_CLASS(bio_template,
	TP_PROTO(struct bio *bio),

	TP_ARGS(bio),

	TP_STRUCT__entry(
		__field(void *,		bio)
		__field(sector_t,	sector)
		__field(unsigned int,	size)
		__field(unsigned long,	rw)
	),

	TP_fast_assign(
		__entry->bio		= bio;
		__entry->sector		= bio->bi_sector;
		__entry->size		= bio->bi_size;
		__entry->rw		= bio->bi_rw;
	),

	TP_printk("bio=0x%p sector=0x%lx size=0x%x rw=%s",
			__entry->bio,
			__entry->sector,
			__entry->size,
			PRINT_BI_RW(__entry->rw)
			)
);

#endif /* _TRACE_PLOOP_H */
