#ifndef _LINUX_PRAM_H
#define _LINUX_PRAM_H
/*
 * Persistent RAM provides a kernel interface to save data so that it can be
 * loaded and used after a kexec.
 *
 * Usage:
 * 
 * * To save data to a PRAM storage:
 *   pram_open(name, PRAM_WRITE, stream);
 *   pram_push_page(stream, page, &pfn); // and/or ...
 *   pram_write(stream, buf, count);
 *   pram_close(stream, 0); // to save the storage or ...
 *   pram_close(stream, -1); // to discard data written and destroy the storage
 *
 * * To load data from a PRAM storage:
 *   pram_open(name, PRAM_READ, stream);
 *   page = pram_pop_page(stream); // and/or ...
 *   pram_read(stream, buf, count);
 *   pram_close(stream, 0);
 *
 * For PRAM to be restored after a kexec, the PRAM pfn has to be passed to the
 * kernel at boot time in the 'pram' parameter. The PRAM pfn can be read from
 * /sys/kernel/pram.
 */

#include <linux/gfp.h>
#include <linux/types.h>
#include <linux/mm_types.h>
#include <linux/mm.h>

struct pram_chain;
struct pram_link;

struct pram_stream {
	struct pram_chain *chain;
	struct pram_link *link;
	unsigned long offset;
	struct page *data_page;
	unsigned long data_offset;
	gfp_t gfp_mask;
};

#define PRAM_WRITE	1
#define PRAM_READ	2

extern int __pram_open(const char *name, int mode, gfp_t gfp_mask,
		       struct pram_stream *stream);
#define pram_open(name, mode, stream) \
	__pram_open(name, mode, GFP_KERNEL | __GFP_HIGHMEM, stream)
extern int pram_push_page(struct pram_stream *stream, struct page *page,
			  unsigned long *ppfn);
extern struct page *pram_pop_page(struct pram_stream *stream);
extern int pram_del_page(struct pram_stream *stream, struct page *page);
extern ssize_t pram_write(struct pram_stream *stream,
			  const void *buf, size_t count);
extern ssize_t pram_read(struct pram_stream *stream,
			 void *buf, size_t count);
extern void pram_close(struct pram_stream *stream, int how);
extern int pram_destroy(const char *name);

extern int __pram_prealloc(gfp_t gfp_mask, int n, ...);
#define pram_prealloc(gfp, sz) \
	__pram_prealloc(gfp, 1, (size_t)(sz))
#define pram_prealloc2(gfp, sz1, sz2) \
	__pram_prealloc(gfp, 2, (size_t)(sz1), (size_t)(sz2))
extern void pram_prealloc_end(void);

extern int pram_for_each_page(struct pram_stream *stream,
		int (*fn)(struct page *page, void *data), void *data);
extern int pram_del_from_lru(struct pram_stream *stream, int wait);

extern int pram_dirty(struct pram_stream *stream);

#define PRAM_DEL_FROM_LRU_OBSOLETE

#ifdef CONFIG_PRAM
/*
 * This function can be used to check if a page extracted from pram is dirty
 * i.e.  it was not relocated on push and the system has not been rebooted
 * since it was added to pram.
 *
 * To mark page dirty, use PAGE_MAPPING_ANON bit of its mapping. It should not
 * conflict with memory reclaimer because page_mapping won't return the actual
 * mapping value then. Neither should it cause any troubles freeing such pages
 * (see free_hot_cold_page).
 */
static inline bool pram_page_dirty(struct page *page)
{
	return ((unsigned long)page->mapping & PAGE_MAPPING_ANON) != 0;
}
extern unsigned long long pram_low;
extern unsigned long pram_reserved_pages;
extern void pram_reserve(void);
extern void pram_init(void);
extern void pram_ban_region(unsigned long start, unsigned long end);
extern void pram_show_banned(void);
#else
static inline bool pram_page_dirty(struct page *page) { return false; };
#define pram_low 0ULL
#define pram_reserved_pages 0UL
static inline void pram_reserve(void) { }
static inline void pram_init(void) { }
static inline void pram_ban_region(unsigned long start, unsigned long end) { }
static inline void pram_show_banned(void) { }
#endif

#endif /* _LINUX_PRAM_H */
