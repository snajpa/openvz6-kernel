#include <linux/bootmem.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/crc32.h>
#include <linux/crc32c.h>
#include <linux/err.h>
#include <linux/gfp.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/memcontrol.h>
#include <linux/mm.h>
#include <linux/mm_inline.h>
#include <linux/mmgang.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/page-flags.h>
#include <linux/percpu.h>
#include <linux/pfn.h>
#include <linux/pram.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/types.h>
#include <asm/cpufeature.h>

#define PRAM_MAGIC		0x7072616D
#define PRAM_MAGIC_INCOMPLETE	(PRAM_MAGIC+1)
#define PRAM_MAGIC_V2		(PRAM_MAGIC+2)

#define PRAM_MAGIC_OK(magic) \
	((magic) == PRAM_MAGIC || \
	 (magic) == PRAM_MAGIC_V2)

#define PRAM_NAME_MAX		512	/* including nul */

/*
 * Since currently we support only x86_64, don't worry
 * about endianness as well as highmem.
 */
struct pram_chain {
	__u32			magic;
	__u32			csum;
	__u64			chain_pfn;
	__u64			link_pfn;
	__u32			last_link_sz;
	__u32			last_page_sz;
	__u8			name[PRAM_NAME_MAX];

	/* v2 fields */
	__u32			csum_mode;
};

typedef __u32 (*csum_func_t)(const void *);

struct pram_csum_mode {
	int id;
	char *name;
	csum_func_t func;
};

#define PRAM_CSUM_NAME_MAX	16

static const struct pram_csum_mode csum_mode_none;
static const struct pram_csum_mode csum_mode_crc32c;
static const struct pram_csum_mode csum_mode_xor;

static const struct pram_csum_mode * const csum_mode_list[] = {
#define PRAM_CSUM_NONE		0
	&csum_mode_none,
#define PRAM_CSUM_CRC32C	1
	&csum_mode_crc32c,
#define PRAM_CSUM_XOR		2
	&csum_mode_xor,
#define NR_PRAM_CSUM_MODES	3
	NULL,
};

static const struct pram_csum_mode *csum_mode;

#define PRAM_STATE_SAVE		1
#define PRAM_STATE_LOAD		2

#define PRAM_CHAIN_STATE(chain) \
	page_private(virt_to_page(chain))
#define PRAM_SET_CHAIN_STATE(chain, state) \
	set_page_private(virt_to_page(chain), state)
#define PRAM_CHAIN_BUSY(chain) \
	(PRAM_CHAIN_STATE(chain) != 0)

struct pram_page {
	__u32			csum;
	__u64			pfn;
};

struct pram_link {
	__u32			magic;
	__u32			csum;
	__u64			link_pfn;
	struct pram_page	page[0];
};

#define PRAM_LINK_CAPACITY \
	((PAGE_SIZE - sizeof(struct pram_link)) / sizeof(struct pram_page))

static int pram_reservation;
unsigned long pram_reserved_pages;

#define DEFAULT_PRAM_LOW	(16UL << 20) /* 16Mb */
unsigned long long pram_low = DEFAULT_PRAM_LOW;

struct banned_region {
	unsigned long start, end;
};

#define MAX_NR_BANNED		(32 + MAX_NUMNODES * 2)

static int nr_banned = 1;
static struct banned_region banned[MAX_NR_BANNED] = {
	{ .start = 0, .end = PFN_UP(DEFAULT_PRAM_LOW) - 1 },
};

static unsigned long total_banned;

/* list of allocated pages that can't be used as pram;
 * shrinked when memory is low */
static unsigned long nr_banned_pages;
static LIST_HEAD(banned_pages);
static DEFINE_SPINLOCK(banned_pages_lock);

/* pool of free pages available for pram;
 * allocated by sysctl pram_prealloc */
static unsigned long page_pool_size;
static LIST_HEAD(page_pool);
static DEFINE_SPINLOCK(page_pool_lock);

struct pram_prealloc_struct {
	int nr_pages;
	struct list_head pages;
};
static DEFINE_PER_CPU(struct pram_prealloc_struct, pram_preallocs);

#define MAX_PREALLOC_SIZE	4

static unsigned long pram_pfn;	/* points to first pram chain */
static LIST_HEAD(pram_list);	/* list of chains linked through page->lru */

static DEFINE_MUTEX(pram_mutex);

static int __init parse_pram(char *arg)
{
	if (!arg)
		return 0;
	return strict_strtoul(arg, 16, &pram_pfn);
}
early_param("pram", parse_pram);

static int __init parse_pram_low(char *arg)
{
	char *endptr;
	unsigned long long val;

	if (!arg)
		return 0;
	val = memparse(arg, &endptr);
	if (*endptr != '\0')
		return -EINVAL;
	if (val > 0) {
		pram_low = val;
		banned[0].end = PFN_UP(val) - 1;
	}
	return 0;
}
early_param("pram_low", parse_pram_low);

static __u32 csum_none_func(const void *p)
{
	return 0;
}

static const struct pram_csum_mode csum_mode_none = {
	.id = PRAM_CSUM_NONE,
	.name = "none",
	.func = csum_none_func,
};

static __u32 csum_crc32c_func(const void *p)
{
	return crc32c(~0, p, PAGE_SIZE);
}

static const struct pram_csum_mode csum_mode_crc32c = {
	.id = PRAM_CSUM_CRC32C,
	.name = "crc32c",
	.func = csum_crc32c_func,
};

static __u32 csum_xor_func(const void *p)
{
	int idx = PAGE_SIZE / 4;
	const __u32 *cur = p;
	__u32 sum = 0;

	while (idx--)
		sum ^= *cur++;
	return sum;
}

static const struct pram_csum_mode csum_mode_xor = {
	.id = PRAM_CSUM_XOR,
	.name = "xor",
	.func = csum_xor_func,
};

static inline const struct pram_csum_mode *pram_get_csum_mode(void)
{
	return csum_mode;
}

static void pram_set_csum_mode(const struct pram_csum_mode *m)
{
	if (csum_mode != m) {
		csum_mode = m;
		printk(KERN_INFO "PRAM: selected csum mode: %s\n", m->name);
	}
}

static void __init pram_select_csum_mode(void)
{
	const struct pram_csum_mode *m;

	if (cpu_has_xmm4_2)
		m = &csum_mode_crc32c;
	else
		m = &csum_mode_xor;
	pram_set_csum_mode(m);
}

/* SSE-4.2 crc32c faster than crc32, but not avaliable at early boot */
static inline __u32 pram_meta_csum(const void *p)
{
	/* skip magic and csum fields */
	return crc32(~0, (char *)p + 8, PAGE_SIZE - 8);
}

static void pram_list_add(struct pram_chain *chain)
{
	struct page *page, *head_page;
	struct pram_chain *head;

	BUG_ON(!pram_pfn);
	head_page = pfn_to_page(pram_pfn);
	head = page_address(head_page);

	page = virt_to_page(chain);
	BUG_ON(page == head_page);

	chain->chain_pfn = head->chain_pfn;
	head->chain_pfn = page_to_pfn(page);
	head->csum = pram_meta_csum(head);
	list_add(&page->lru, &pram_list);
}

static void pram_list_del(struct pram_chain *chain)
{
	struct page *page, *prev_page;
	struct pram_chain *prev;

	BUG_ON(!pram_pfn);

	page = virt_to_page(chain);
	BUG_ON(pram_pfn == page_to_pfn(page));

	prev_page = page->lru.prev == &pram_list ?
		pfn_to_page(pram_pfn) :
		list_entry(page->lru.prev, struct page, lru);
	prev = page_address(prev_page);

	BUG_ON(prev->chain_pfn != page_to_pfn(page));
	prev->chain_pfn = chain->chain_pfn;
	if (PRAM_CHAIN_STATE(prev) != PRAM_STATE_SAVE)
		prev->csum = pram_meta_csum(prev);
	list_del_init(&page->lru);
}

static void pram_init_list_head(void)
{
	struct pram_chain *head;

	BUG_ON(!pram_pfn);
	head = pfn_to_kaddr(pram_pfn);

	memset(head, 0, PAGE_SIZE);
	head->magic = PRAM_MAGIC_V2;
	head->csum = pram_meta_csum(head);
}

static struct page *pram_alloc_page(gfp_t gfpmask);
static void __banned_pages_shrink(int nr_to_scan);

static __init int pram_build_list(void)
{
	unsigned long pfn;
	struct page *page;
	struct pram_chain *chain;

	if (!pram_pfn) {
		/* allocate pram list head */
		page = pram_alloc_page(GFP_KERNEL);
		if (!page) {
			__banned_pages_shrink(INT_MAX);
			return -ENOMEM;
		}
		pram_pfn = page_to_pfn(page);
		pram_init_list_head();
	}

	for (pfn = pram_pfn; pfn; pfn = chain->chain_pfn) {
		page = pfn_to_page(pfn);
		chain = page_address(page);
		if (pfn != pram_pfn)
			list_add_tail(&page->lru, &pram_list);
	}

	return 0;
}

static struct pram_chain *pram_find_chain(const char *name)
{
	struct page *page;
	struct pram_chain *chain;

	if (strlen(name) >= PRAM_NAME_MAX)
		return NULL;

	list_for_each_entry(page, &pram_list, lru) {
		chain = page_address(page);
		if (strcmp(chain->name, name) == 0)
			return chain;
	}
	return NULL;
}

static __init int pram_check_reserve(unsigned long pfn)
{
	if (pfn > max_pfn) {
		printk(KERN_ERR "  pfn:%lx invalid\n", pfn);
		return 0;
	}
	if (reserve_bootmem(PFN_PHYS(pfn), PAGE_SIZE, BOOTMEM_EXCLUSIVE) != 0) {
		printk(KERN_ERR "  pfn:%lx busy\n", pfn);
		return 0;
	}
	return 1;
}

static __init void pram_free_reserved(unsigned long pfn)
{
	free_bootmem(PFN_PHYS(pfn), PAGE_SIZE);
}

static __init int pram_check_meta(unsigned long pfn)
{
	__u32 *map = pfn_to_kaddr(pfn);

	if (!PRAM_MAGIC_OK(map[0])) {
		printk(KERN_ERR "  pfn:%lx corrupted: wrong magic%s\n", pfn,
		       map[0] == PRAM_MAGIC_INCOMPLETE ?
		       " (stream was not closed?)" : "");
		return 0;
	}
	if (map[1] != pram_meta_csum(map)) {
		printk(KERN_ERR "  pfn:%lx corrupted: wrong checksum\n", pfn);
		return 0;
	}
	return 1;
}

static __init void pram_version_fixup(struct pram_chain *chain)
{
	if (chain->magic == PRAM_MAGIC)
		chain->csum_mode = PRAM_CSUM_CRC32C;
}

void __init pram_reserve(void)
{
	int i;
	unsigned long chain_pfn, link_pfn;
	__u64 first_chain_pfn, *chain_ppfn, *link_ppfn;
	struct pram_chain *chain;
	struct pram_link *link;
	long nr_bad, nr_reserved;

	if (!pram_pfn)
		return;

	printk(KERN_INFO "PRAM: examine persistent memory...\n");

	pram_reservation = 1;
	nr_bad = nr_reserved = 0;
	first_chain_pfn = pram_pfn;
	for (chain_ppfn = &first_chain_pfn;
	     *chain_ppfn; chain_ppfn = &chain->chain_pfn) {
		chain_pfn = *chain_ppfn;
		chain = pfn_to_kaddr(chain_pfn);

		if (!pram_check_reserve(chain_pfn))
			goto bad_chain;
		if (!pram_check_meta(chain_pfn)) {
			pram_free_reserved(chain_pfn);
			goto bad_chain;
		}
		nr_reserved++;

		pram_version_fixup(chain);

		for (link_ppfn = &chain->link_pfn;
		     *link_ppfn; link_ppfn = &link->link_pfn) {
			link_pfn = *link_ppfn;
			if (!pram_check_reserve(link_pfn))
				goto bad_link;
			if (!pram_check_meta(link_pfn)) {
				pram_free_reserved(link_pfn);
				goto bad_link;
			}
			nr_reserved++;

			link = pfn_to_kaddr(link_pfn);
			for (i = 0; i < PRAM_LINK_CAPACITY &&
			     link->page[i].pfn; i++) {
				if (!pram_check_reserve(link->page[i].pfn)) {
					link->page[i].pfn = 0;
					nr_bad++;
					continue;
				}
				nr_reserved++;
			}
			continue;
bad_link:
			*link_ppfn = 0;
			nr_bad++;
			break;
		}
		continue;
bad_chain:
		*chain_ppfn = 0;
		nr_bad++;
		printk("  chain \"%.64s\" corrupted\n", chain->name);
		break;
	}
	pram_pfn = first_chain_pfn;
	pram_reservation = 0;

	if (!nr_bad) {
		printk(KERN_INFO "PRAM: %ld pages reserved\n", nr_reserved);
		pram_reserved_pages = nr_reserved;
		return;
	}

	printk(KERN_ERR "PRAM: reservation FAILED: %ld pages corrupted\n",
	       nr_bad);

	for (chain_pfn = pram_pfn; chain_pfn; chain_pfn = chain->chain_pfn) {
		chain = pfn_to_kaddr(chain_pfn);
		for (link_pfn = chain->link_pfn;
		     link_pfn; link_pfn = link->link_pfn) {
			link = pfn_to_kaddr(link_pfn);
			for (i = 0; i < PRAM_LINK_CAPACITY; i++) {
				if (link->page[i].pfn)
					pram_free_reserved(link->page[i].pfn);
			}
			pram_free_reserved(link_pfn);
		}
		pram_free_reserved(chain_pfn);
	}
	pram_pfn = 0;
}

void __init pram_ban_region(unsigned long start, unsigned long end)
{
	int i;

	if (pram_reservation)
		return;

	for (i = nr_banned - 1; i >= 0 && start <= banned[i].end + 1; i--) {
		if (end + 1 >= banned[i].start) {
			banned[i].start = min(banned[i].start, start);
			banned[i].end = max(banned[i].end, end);
			return;
		}
	}

	if (nr_banned == MAX_NR_BANNED) {
		printk(KERN_WARNING "PRAM: too many banned regions!\n");
		return;
	}

	i++;
	memmove(banned + i + 1, banned + i,
		sizeof(struct banned_region) * (nr_banned - i));
	banned[i].start = start;
	banned[i].end = end;
	nr_banned++;
}

void __init pram_show_banned(void)
{
	int i;
	unsigned long n;

	printk("PRAM: banned regions:\n");
	for (i = 0; i < nr_banned; i++) {
		n = banned[i].end - banned[i].start + 1;
		printk("%4d: [%08lx - %08lx] %ld pages\n",
		       i, banned[i].start, banned[i].end, n);
		total_banned += n;
	}
	printk("Total banned: %ld pages in %d regions\n",
	       total_banned, nr_banned);
}

static int page_banned(struct page *page)
{
	unsigned long pfn = page_to_pfn(page);
	int l = 0, r = nr_banned - 1, m;

	while (l <= r) {
		m = (l + r) / 2;
		if (pfn < banned[m].start)
			r = m - 1;
		else if (pfn > banned[m].end)
			l = m + 1;
		else
			return 1;
	}
	return 0;
}

static struct page *__pram_alloc_new_page(gfp_t gfpmask)
{
	struct page *page;
	int page_list_len = 0;
	LIST_HEAD(page_list);

	/*
	 * For the subsequent boot to be successful, we should not use pages
	 * that have ever been reserved. So just put them to the banned list to
	 * be freed later.
	 */

	page = alloc_page(gfpmask);
	while (page && page_banned(page)) {
		page_list_len++;
		list_add(&page->lru, &page_list);
		page = alloc_page(gfpmask | __GFP_COLD);
	}

	if (page_list_len > 0) {
		spin_lock(&banned_pages_lock);
		nr_banned_pages += page_list_len;
		list_splice(&page_list, &banned_pages);
		spin_unlock(&banned_pages_lock);
	}

	return page;
}

static struct page *__pram_alloc_page(gfp_t gfpmask)
{
	struct page *page = NULL;

	if (page_pool_size) {
		spin_lock(&page_pool_lock);
		if (page_pool_size) {
			BUG_ON(list_empty(&page_pool));
			page = list_entry(page_pool.next, struct page, lru);
			list_del_init(&page->lru);
			page_pool_size--;
		}
		spin_unlock(&page_pool_lock);

		if (page && (gfpmask & __GFP_ZERO))
			clear_highpage(page);
	}

	if (!page)
		page = __pram_alloc_new_page(gfpmask);

	return page;
}

static struct page *pram_alloc_page(gfp_t gfpmask)
{
	struct page *page = NULL;

	if (!(gfpmask & __GFP_WAIT)) {
		struct pram_prealloc_struct *p;

		p = &get_cpu_var(pram_preallocs);
		if (p->nr_pages > 0) {
			BUG_ON(list_empty(&p->pages));
			page = list_entry(p->pages.next, struct page, lru);
			list_del_init(&page->lru);
			p->nr_pages--;
		}
		put_cpu_var(pram_preallocs);

		if (page && (gfpmask & __GFP_ZERO))
			clear_highpage(page);
	}

	if (!page)
		page = __pram_alloc_page(gfpmask);

	return page;
}

static void __init pram_init_preallocs(void)
{
	int cpu;
	struct pram_prealloc_struct *p;

	for_each_possible_cpu(cpu) {
		p = &per_cpu(pram_preallocs, cpu);
		p->nr_pages = 0;
		INIT_LIST_HEAD(&p->pages);
	}
}

static inline int pram_prealloc_size(size_t size)
{
	int nr_pages;

	if (!size)
		return 0;

	nr_pages = DIV_ROUND_UP(size, PAGE_SIZE);
	nr_pages += DIV_ROUND_UP(nr_pages, PRAM_LINK_CAPACITY);

	return nr_pages;
}

/**
 * __pram_prealloc - preallocate pages to ensure that subsequent writes to
 * persistent memory will not fail due to lack of memory
 * @gfp_mask: GFP flags to use for page allocations
 * @n: number of streams that will be written to
 * @...: @n constants of type size_t containing number of bytes that will be
 * written to each of @n streams
 *
 * On success, returns 0 with preemption disabled. On failure, returns -ENOMEM
 * with preemption not disabled.
 *
 * To make use of this facility, persistent memory streams must be opened for
 * writing without __GFP_WAIT being passed to __pram_open().
 */
int __pram_prealloc(gfp_t gfp_mask, int n, ...)
{
	int nr_pages = 0;
	struct page *page;
	struct pram_prealloc_struct *p;
	LIST_HEAD(pages);
	va_list ap;

	va_start(ap, n);
	while (n--)
		nr_pages += pram_prealloc_size(va_arg(ap, size_t));
	va_end(ap);

	preempt_disable();
	p = &__get_cpu_var(pram_preallocs);

	if (p->nr_pages >= nr_pages)
		return 0;

	preempt_enable();

	for (n = 0; n < nr_pages; n++) {
		page = __pram_alloc_page(gfp_mask);
		if (!page)
			break;
		list_add(&page->lru, &pages);
	}

	if (n < nr_pages) {
		while (!list_empty(&pages)) {
			page = list_entry(pages.next, struct page, lru);
			list_del_init(&page->lru);
			__free_page(page);
		}
		return -ENOMEM;
	}

	preempt_disable();
	p = &__get_cpu_var(pram_preallocs);

	p->nr_pages += nr_pages;
	list_splice(&pages, &p->pages);

	return 0;
}

void pram_prealloc_end(void)
{
	struct page *page;
	struct pram_prealloc_struct *p;

	p = &__get_cpu_var(pram_preallocs);
	while (p->nr_pages > MAX_PREALLOC_SIZE) {
		BUG_ON(list_empty(&p->pages));
		page = list_entry(p->pages.next, struct page, lru);
		list_del_init(&page->lru);
		__free_page(page);
		p->nr_pages--;
	}
	preempt_enable();
}

static int __pram_del_page(struct pram_chain *chain, struct page *page);

static unsigned long pram_drain(struct pram_chain *chain)
{
	int i;
	unsigned long link_pfn;
	struct pram_link *link;
	struct page *page;
	unsigned long freed = 0;

	link_pfn = chain->link_pfn;
	while (link_pfn) {
		link = pfn_to_kaddr(link_pfn);
		for (i = 0; i < PRAM_LINK_CAPACITY; i++) {
			if (!link->page[i].pfn)
				continue;
			page = pfn_to_page(link->page[i].pfn);

			if (PRAM_CHAIN_STATE(chain) == PRAM_STATE_LOAD) {
				if (__pram_del_page(chain, page))
					/* already removed */
					continue;
			}

			ClearPageReserved(page);
			put_page(page);
			freed++;
		}
		page = pfn_to_page(link_pfn);
		link_pfn = link->link_pfn;
		ClearPageReserved(page);
		put_page(page);
		freed++;
	}

	return freed;
}

static unsigned long __pram_destroy(struct pram_chain *chain)
{
	struct page *page;
	unsigned long freed;

	freed = pram_drain(chain);
	page = virt_to_page(chain);
	ClearPageReserved(page);
	ClearPageDirty(page);
	put_page(page);
	freed++;
	return freed;
}

static void pram_destroy_all(void)
{
	struct page *page, *tmp;
	struct pram_chain *chain;
	LIST_HEAD(dispose);
	int nodes_discarded = 0;
	unsigned long pages_freed = 0;

	mutex_lock(&pram_mutex);
	list_for_each_entry_safe(page, tmp, &pram_list, lru) {
		chain = page_address(page);
		if (PRAM_CHAIN_BUSY(chain))
			continue;
		pram_list_del(chain);
		list_add(&page->lru, &dispose);
	}
	mutex_unlock(&pram_mutex);

	while (!list_empty(&dispose)) {
		page = list_entry(dispose.next, struct page, lru);
		list_del_init(&page->lru);
		chain = page_address(page);
		pages_freed += __pram_destroy(chain);
		nodes_discarded++;
	}

	if (nodes_discarded)
		printk(KERN_INFO "PRAM: %d nodes discarded (%lu pages freed)\n",
		       nodes_discarded, pages_freed);
}

static void pram_stream_init(struct pram_stream *stream,
			     struct pram_chain *chain, gfp_t gfp_mask)
{
	stream->chain = chain;
	stream->link = chain->link_pfn ?
		pfn_to_kaddr(chain->link_pfn) : NULL;
	stream->offset = 0;
	stream->data_page = NULL;
	stream->data_offset = 0;
	stream->gfp_mask = gfp_mask;
}

static int pram_create(const char *name, gfp_t gfp_mask,
		       struct pram_stream *stream)
{
	struct page *page;
	struct pram_chain *chain;
	int ret = 0;

	if (strlen(name) >= PRAM_NAME_MAX)
		return -EINVAL;

	mutex_lock(&pram_mutex);
	if (pram_find_chain(name)) {
		ret = -EEXIST;
		goto unlock;
	}

	page = pram_alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!page) {
		ret = -ENOMEM;
		goto unlock;
	}

	chain = page_address(page);
	strcpy(chain->name, name);
	PRAM_SET_CHAIN_STATE(chain, PRAM_STATE_SAVE);

	chain->magic = PRAM_MAGIC_INCOMPLETE;

	pram_list_add(chain);
unlock:
	mutex_unlock(&pram_mutex);

	if (!ret)
		pram_stream_init(stream, chain, gfp_mask);
	return ret;
}

static int __pram_push_page(struct pram_stream *stream, struct page *page)
{
	struct pram_link *link = stream->link;
	unsigned long offset = stream->offset;

	if (!link || stream->offset >= PRAM_LINK_CAPACITY) {
		unsigned long link_pfn;
		struct page *link_page;

		link_page = pram_alloc_page(stream->gfp_mask | __GFP_ZERO);
		if (!link_page)
			return -ENOMEM;

		link_pfn = page_to_pfn(link_page);
		if (link)
			link->link_pfn = link_pfn;
		else
			stream->chain->link_pfn = link_pfn;

		stream->link = link = page_address(link_page);
		offset = 0;

		link->magic = PRAM_MAGIC_INCOMPLETE;
	}

	get_page(page);

	link->page[offset].pfn = page_to_pfn(page);
	offset++;

	stream->offset = offset;
	SetPageDirty(virt_to_page(stream->chain));
	return 0;
}

/**
 * pram_push_page - save page to persistent memory storage
 * @stream: storage stream
 * @page: page to save
 * @ppfn: if not NULL, saved page pfn is stored there
 *
 * Saving a page to a persistent memory storage usually is equivalent to
 * getting the page and requires no data copying unless the page resides in a
 * banned region. In the latter case, a new page is allocated and the content
 * of the page passed to the function is copied to the new page.
 *
 * The function may block iff __GFP_WAIT was passed to __pram_open().
 *
 * Returns 0 on success, -errno on failure.
 *
 * Error values:
 *    %-EINVAL: stream is not opened for writing
 *    %-EFAULT: page is compound
 *    %-ENOMEM: insufficient amount of memory available
 */
int pram_push_page(struct pram_stream *stream, struct page *page,
		   unsigned long *ppfn)
{
	int ret;
	struct page *new = NULL;

	if (PRAM_CHAIN_STATE(stream->chain) != PRAM_STATE_SAVE)
		return -EINVAL;

	if (PageCompound(page))
		return -EFAULT;

	if (page_banned(page)) {
		new = pram_alloc_page(stream->gfp_mask);
		if (!new)
			return -ENOMEM;
		copy_highpage(new, page);
		page = new;
	}

	ret = __pram_push_page(stream, page);
	if (!ret) {
		stream->data_page = NULL;
		if (ppfn)
			*ppfn = page_to_pfn(page);
		if (new)
			/* mark it clean (see __pram_pop_page) */
			SetPageReserved(new);
	}
	if (new)
		put_page(new);
	return ret;
}
EXPORT_SYMBOL(pram_push_page);

/**
 * pram_write - write data to persistent memory storage
 * @stream: storage stream
 * @buf: data to write
 * @count: data length
 *
 * The function may block iff __GFP_WAIT was passed to __pram_open().
 *
 * Returns the number of bytes written on success, -errno on failure.
 *
 * Error values:
 *    %-EINVAL: storage is not opened for writing
 *    %-ENOMEM: insufficient amount of memory available
 */
ssize_t pram_write(struct pram_stream *stream, const void *buf, size_t count)
{
	size_t copy_count, write_count = 0;
	char *data;

	if (PRAM_CHAIN_STATE(stream->chain) != PRAM_STATE_SAVE)
		return -EINVAL;

	while (count > 0) {
		if (!stream->data_page) {
			struct page *page;
			int ret = -ENOMEM;

			page = pram_alloc_page(stream->gfp_mask | __GFP_ZERO);
			if (page) {
				ret = __pram_push_page(stream, page);
				put_page(page);
			}
			if (ret)
				return ret;

			stream->data_page = page;
			stream->data_offset = 0;
		}

		copy_count = min_t(size_t, count,
				   PAGE_SIZE - stream->data_offset);
		data = page_address(stream->data_page);
		memcpy(data + stream->data_offset, buf, copy_count);

		buf = (char *)buf + copy_count;
		stream->data_offset += copy_count;
		if (stream->data_offset >= PAGE_SIZE)
			stream->data_page = NULL;

		write_count += copy_count;
		count -= copy_count;
	}
	return write_count;
}
EXPORT_SYMBOL(pram_write);

static inline void pram_csum_data(struct pram_page *p, csum_func_t csum_func)
{
	void *datap = pfn_to_kaddr(p->pfn);

	p->csum = csum_func(datap);
}

static inline int pram_check_data_csum(struct pram_chain *chain,
				       struct pram_page *p)
{
	void *datap = pfn_to_kaddr(p->pfn);
	__u32 csum;

	if (chain->csum_mode < NR_PRAM_CSUM_MODES)
		csum = csum_mode_list[chain->csum_mode]->func(datap);
	else
		csum = p->csum + 1;

	if (p->csum != csum) {
		if (printk_ratelimit())
			printk(KERN_WARNING "PRAM: pfn:%lx corrupted\n",
			       (unsigned long)p->pfn);
		return 0;
	}

	return 1;
}

static void pram_update_csum(struct pram_chain *chain)
{
	int i;
	unsigned long link_pfn;
	struct pram_link *link;
	struct pram_page *p;
	const struct pram_csum_mode *cur_csum_mode = pram_get_csum_mode();

	chain->csum_mode = cur_csum_mode->id;
	for (link_pfn = chain->link_pfn; link_pfn; link_pfn = link->link_pfn) {
		link = pfn_to_kaddr(link_pfn);
		for (i = 0; i < PRAM_LINK_CAPACITY; i++) {
			p = &link->page[i];
			if (!p->pfn)
				break;
			pram_csum_data(p, cur_csum_mode->func);
		}
		link->magic = PRAM_MAGIC_V2;
		link->csum = pram_meta_csum(link);
	}
}

static void pram_save(struct pram_stream *stream)
{
	struct pram_chain *chain = stream->chain;

	chain->last_link_sz = stream->offset;
	chain->last_page_sz =
		stream->data_page ? stream->data_offset : PAGE_SIZE;

	pram_update_csum(chain);

	mutex_lock(&pram_mutex);
	chain->magic = PRAM_MAGIC_V2;
	chain->csum = pram_meta_csum(chain);
	PRAM_SET_CHAIN_STATE(chain, 0);
	mutex_unlock(&pram_mutex);
}

static void pram_discard(struct pram_stream *stream)
{
	struct pram_chain *chain = stream->chain;

	mutex_lock(&pram_mutex);
	pram_list_del(chain);
	mutex_unlock(&pram_mutex);

	PRAM_SET_CHAIN_STATE(chain, 0);
	__pram_destroy(chain);
}

static void pram_prepare_data_load(struct pram_chain *chain)
{
	int i;
	unsigned long link_pfn;
	struct pram_link *link;
	struct pram_page *p;
	struct page *page;

	for (link_pfn = chain->link_pfn; link_pfn; link_pfn = link->link_pfn) {
		link = pfn_to_kaddr(link_pfn);
		for (i = 0; i < PRAM_LINK_CAPACITY; i++) {
			p = &link->page[i];
			if (!p->pfn)
				continue;
			page = pfn_to_page(p->pfn);
			if (!pram_check_data_csum(chain, p)) {
				ClearPageReserved(page);
				put_page(page);
				p->pfn = 0;
				continue;
			}

			VM_BUG_ON(page_mapped(page));
			VM_BUG_ON(!PageAnon(page) && page->mapping);
			page->mapping = (void *)chain + PAGE_MAPPING_ANON;
		}
		cond_resched();
	}
}

static int pram_load(const char *name, struct pram_stream *stream)
{
	struct pram_chain *chain;
	int ret = 0;

	mutex_lock(&pram_mutex);
	chain = pram_find_chain(name);
	if (!chain) {
		ret = -ENOENT;
		goto unlock;
	}

	if (PRAM_CHAIN_BUSY(chain)) {
		ret = -EBUSY;
		goto unlock;
	}
	pram_list_del(chain);
unlock:
	mutex_unlock(&pram_mutex);

	if (!ret) {
		PRAM_SET_CHAIN_STATE(chain, PRAM_STATE_LOAD);
		pram_prepare_data_load(chain);
		pram_stream_init(stream, chain, 0);
	}
	return ret;
}

static int __pram_del_page(struct pram_chain *chain, struct page *page)
{
	void *mapping = (void *)page->mapping - PAGE_MAPPING_ANON;

	if (mapping != chain)
		return -EINVAL;

	if (PageReserved(page)) {
		page->mapping = NULL;
		ClearPageReserved(page);
	} else {
		/* dirty mark; see pram_page_dirty */
		page->mapping = (void *)PAGE_MAPPING_ANON;
	}
	return 0;
}

/**
 * pram_del_page - mark page as not belonging to persistent memory storage
 * @stream: storage stream opened for reading
 * @page: page to remove
 *
 * On success, returns 0 and marks the page as not belonging to the storage, so
 * that it will not be touched by pram code any more. On failure, returns
 * -errno.
 *
 * The function never blocks.
 *
 * Error values:
 *    %-EINVAL: stream is not opened for reading or page does not belong to it
 */
int pram_del_page(struct pram_stream *stream, struct page *page)
{
	return __pram_del_page(stream->chain, page);
}
EXPORT_SYMBOL(pram_del_page);

static struct page *__pram_pop_page(struct pram_stream *stream)
{
	struct pram_link *link = stream->link;
	unsigned long offset = stream->offset;
	struct pram_page *p;
	struct page *page;

next:
	if (!link)
		return NULL;

	p = &link->page[offset];
	if (p->pfn) {
		page = pfn_to_page(p->pfn);
		if (__pram_del_page(stream->chain, page))
			/* already removed */
			page = NULL;
	} else
		page = ERR_PTR(-EIO);

	p->pfn = 0;
	offset++;

	if (offset >= (link->link_pfn ? PRAM_LINK_CAPACITY :
		       stream->chain->last_link_sz)) {
		unsigned long link_pfn = link->link_pfn;
		struct page *link_page;

		link_page = virt_to_page(link);
		ClearPageReserved(link_page);
		put_page(link_page);

		stream->chain->link_pfn = link_pfn;
		stream->link = link = link_pfn ? pfn_to_kaddr(link_pfn) : NULL;
		offset = 0;
	}

	stream->offset = offset;
	if (!page)
		goto next;

	return page;
}

/**
 * pram_pop_page - load page from persistent memory storage
 * @stream: storage stream
 *
 * On success, returns the page loaded or NULL if the storage is empty. On
 * failure, returns ERR_PTR(-errno).
 *
 * The function never blocks.
 *
 * Error values:
 *    %-EINVAL: stream is not opened for reading
 *    %-EIO: page has been corrupted
 */
struct page *pram_pop_page(struct pram_stream *stream)
{
	struct page *page;

	if (PRAM_CHAIN_STATE(stream->chain) != PRAM_STATE_LOAD)
		return ERR_PTR(-EINVAL);

	page = __pram_pop_page(stream);
	if (!IS_ERR(page) && stream->data_page) {
		put_page(stream->data_page);
		stream->data_page = NULL;
	}
	return page;
}
EXPORT_SYMBOL(pram_pop_page);

/**
 * pram_read - read data from persistent memory storage
 * @stream: storage stream
 * @buf: buffer to write data to
 * @count: buffer length
 *
 * On success, the number of bytes read is returned (zero indicates end of
 * stream), and the stream position is advanced by this number. On failure,
 * -errno is returned. In this case it is left unspecified whether the stream
 * position changes.
 *
 * The function never blocks.
 *
 * Error values:
 *    %-EINVAL: storage is not opened for reading
 *    %-EIO: data have been corrupted
 */
ssize_t pram_read(struct pram_stream *stream, void *buf, size_t count)
{
	size_t copy_count, read_count = 0;
	unsigned int data_size;
	char *data;

	if (PRAM_CHAIN_STATE(stream->chain) != PRAM_STATE_LOAD)
		return -EINVAL;

	while (count > 0) {
		if (!stream->data_page) {
			struct page *page;

			page = __pram_pop_page(stream);
			if (IS_ERR(page))
				return PTR_ERR(page);
			if (!page)
				break;

			stream->data_page = page;
			stream->data_offset = 0;
		}

		data_size = stream->link ? PAGE_SIZE :
			stream->chain->last_page_sz;

		copy_count = min_t(size_t, count,
				   data_size - stream->data_offset);
		data = page_address(stream->data_page);
		memcpy(buf, data + stream->data_offset, copy_count);

		buf = (char *)buf + copy_count;
		stream->data_offset += copy_count;
		if (stream->data_offset >= data_size) {
			put_page(stream->data_page);
			stream->data_page = NULL;
		}

		read_count += copy_count;
		count -= copy_count;
	}
	return read_count;
}
EXPORT_SYMBOL(pram_read);

static void pram_release(struct pram_stream *stream)
{
	if (stream->data_page)
		put_page(stream->data_page);
	__pram_destroy(stream->chain);
}

/**
 * pram_destroy - destroy persistent memory storage
 * @name: storage name
 *
 * Returns 0 on success, -errno on failure.
 *
 * Error values:
 *    %-ENOENT: storage does not exist
 *    %-EBUSY: storage is currently being written to
 */
int pram_destroy(const char *name)
{
	struct pram_chain *chain;
	int ret = 0;

	mutex_lock(&pram_mutex);
	chain = pram_find_chain(name);
	if (!chain) {
		ret = -ENOENT;
		goto unlock;
	}

	if (PRAM_CHAIN_BUSY(chain)) {
		ret = -EBUSY;
		goto unlock;
	}
	pram_list_del(chain);
unlock:
	mutex_unlock(&pram_mutex);

	if (!ret)
		__pram_destroy(chain);
	return ret;
}
EXPORT_SYMBOL(pram_destroy);

/**
 * __pram_open - open or create persistent memory storage
 * @name: storage name
 * @mode: specifies if storage is created or opened
 * @gfp_mask: GFP flags to use for page allocations when writing to storage
 * @stream: stream to be used for operating on storage
 *
 * Depending on the value of @mode, the function creates or opens a persistent
 * memory storage with the given name and associates @stream with it.
 *
 * Possible values for @mode:
 *    %PRAM_WRITE - create new storage and initialize stream for writing
 *    %PRAM_READ - open existing storage and initialize stream for reading
 *
 * Returns 0 on success, -errno on failure.
 *
 * Error values:
 *    %-EINVAL: storage name is too long or mode is invalid
 *    %-EEXIST: create failed because storage with given name already exists
 *    %-ENOENT: open failed because storage with given name does not exist
 *    %-EBUSY: open failed because storage is currently being written to
 *    %-ENOMEM: insufficient amount of memory available
 */
int __pram_open(const char *name, int mode, gfp_t gfp_mask,
		struct pram_stream *stream)
{
	int ret;

	if (!pram_pfn)
		return -ENODEV;

	switch (mode) {
	case PRAM_WRITE:
		ret = pram_create(name, gfp_mask, stream);
		break;
	case PRAM_READ:
		ret = pram_load(name, stream);
		break;
	default:
		ret = -EINVAL;
	}
	return ret;
}
EXPORT_SYMBOL(__pram_open);

/**
 * pram_close - close stream and save or destroy persistent memory storage
 * @stream: storage stream
 * @how: if < 0, destroy storage, else save storage
 *
 * If @stream is opened for writing, depending on @how, the function saves or
 * destroys the storage @stream is associated with. If @stream is opened for
 * reading, @how is ignored, and the function frees all data left unread in the
 * storage and releases all resources associated with it.
 */
void pram_close(struct pram_stream *stream, int how)
{
	switch (PRAM_CHAIN_STATE(stream->chain)) {
	case PRAM_STATE_SAVE:
		if (how < 0)
			pram_discard(stream);
		else
			pram_save(stream);
		break;
	case PRAM_STATE_LOAD:
		pram_release(stream);
		break;
	default:
		BUG();
	}
}
EXPORT_SYMBOL(pram_close);

int pram_for_each_page(struct pram_stream *stream,
		int (*fn)(struct page *page, void *data), void *data)
{
	struct pram_chain *chain;
	struct pram_link *link;
	unsigned long link_pfn, pfn;
	int i, err = 0;

	chain = stream->chain;
	for (link_pfn = chain->link_pfn; link_pfn; link_pfn = link->link_pfn) {
		link = pfn_to_kaddr(link_pfn);
		for (i = 0; i < PRAM_LINK_CAPACITY; i++) {
			pfn = link->page[i].pfn;
			if (!pfn)
				continue;
			err = fn(pfn_to_page(pfn), data);
			if (err)
				goto out;
		}
	}
out:
	return err;
}
EXPORT_SYMBOL(pram_for_each_page);

#define LRU_DEL_ATTEMPTS	3000

struct lru_del_state {
	int attempt;
	unsigned long nr_busy;
	struct lruvec *lruvec;
};

static int __pram_del_from_lru(struct page *page, void *data)
{
	struct lru_del_state *st = data;

	if (!page_gang(page))
		/* page does not belong to any gang
		 * so it is definitely not on lru */
		goto out;

	if (page_count(page) != 1)
		/* we are not the only page owner
		 * so it is unsafe to del it from lru now */
		goto out_busy;

	st->lruvec = relock_lruvec(st->lruvec, page_lruvec(page));
	if (unlikely(st->lruvec != __page_lruvec(page) ||
		     page_count(page) != 1))
		goto out_busy;
	if (PageLRU(page)) {
		ClearPageLRU(page);
		del_page_from_lru(st->lruvec, page);
		gang_del_user_page(page);
	}
	goto out;

out_busy:
	st->nr_busy++;
	if (st->attempt >= LRU_DEL_ATTEMPTS && printk_ratelimit()) {
		printk(KERN_WARNING "PRAM: failed to del page from lru: "
		       "page:%p flags:%p count:%d "
		       "mapcount:%d mapping:%p index:%lx\n",
		       page, (void *)page->flags, page_count(page),
		       page_mapcount(page), page->mapping, page->index);
	}
out:
	return 0;
}

int pram_del_from_lru(struct pram_stream *stream, int wait)
{
	unsigned long flags;
	struct lru_del_state st;

	memset(&st, 0, sizeof(st));
again:
	st.attempt++;
	st.nr_busy = 0;
	st.lruvec = NULL;

	local_irq_save(flags);
	pram_for_each_page(stream, __pram_del_from_lru, &st);
	unlock_lruvec(st.lruvec);
	local_irq_restore(flags);

	if (st.nr_busy && st.attempt < LRU_DEL_ATTEMPTS && wait) {
		schedule_timeout_uninterruptible(1);
		goto again;
	}

	if (st.nr_busy && !wait)
		return -EAGAIN;
	if (st.nr_busy) {
		printk(KERN_WARNING "PRAM: %s failed: %lu pages busy\n",
		       __func__, st.nr_busy);
		return -EBUSY;
	}
	return 0;
}
EXPORT_SYMBOL(pram_del_from_lru);

int pram_dirty(struct pram_stream *stream)
{
	return PageDirty(virt_to_page(stream->chain));
}
EXPORT_SYMBOL(pram_dirty);

static void __banned_pages_shrink(int nr_to_scan)
{
	struct page *page;

	if (nr_to_scan <= 0)
		return;

	while (!list_empty(&banned_pages)) {
		page = list_entry(banned_pages.next, struct page, lru);
		list_del_init(&page->lru);
		__free_page(page);
		BUG_ON(!nr_banned_pages);
		nr_banned_pages--;
		nr_to_scan--;
		if (!nr_to_scan)
			break;
	}
}

static int banned_pages_shrink(struct shrinker *shrink,
			       int nr_to_scan, gfp_t gfp_mask)
{
	int nr_left = nr_banned_pages;

	if (!nr_to_scan || !nr_left)
		return nr_left;

	spin_lock(&banned_pages_lock);
	__banned_pages_shrink(nr_to_scan);
	nr_left = nr_banned_pages;
	spin_unlock(&banned_pages_lock);

	return nr_left;
}

static struct shrinker banned_pages_shrinker = {
	.shrink = banned_pages_shrink,
	.seeks = DEFAULT_SEEKS,
};

static int pram_callback(struct notifier_block *nfb,
			 unsigned long action, void *hcpu)
{
	int cpu = (long)hcpu;
	struct page *page;
	struct pram_prealloc_struct *p;

	/* Free per-cpu pool of preallocated pages */
	if (action == CPU_DEAD || action == CPU_DEAD_FROZEN) {
		p = &per_cpu(pram_preallocs, cpu);
		p->nr_pages = 0;
		while (!list_empty(&p->pages)) {
			page = list_entry(p->pages.next, struct page, lru);
			list_del_init(&page->lru);
			__free_page(page);
		}
	}
	return NOTIFY_OK;
}

static ssize_t pram_show(struct kobject *kobj, struct kobj_attribute *attr,
			 char *buf)
{
	return sprintf(buf, "%lx\n", pram_pfn);
}

static ssize_t pram_store(struct kobject *kobj, struct kobj_attribute *attr,
			  const char *buf, size_t count)
{
	unsigned long val;

	if (strict_strtoul(buf, 16, &val) || val)
		return -EINVAL;
	pram_destroy_all();
	return count;
}

static struct kobj_attribute pram_attr =
	__ATTR(pram, 0644, pram_show, pram_store);

static ssize_t pram_low_show(struct kobject *kboj, struct kobj_attribute *attr,
			     char *buf)
{
	return sprintf(buf, "%llu\n", pram_low);
}

static struct kobj_attribute pram_low_attr = __ATTR_RO(pram_low);

static ssize_t pram_banned_show(struct kobject *kboj,
				struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%lu\n", total_banned);
}

static struct kobj_attribute pram_banned_attr = __ATTR_RO(pram_banned);

static int page_pool_grow(unsigned long target_size)
{
	struct page *page;
	LIST_HEAD(allocated);
	unsigned long nr_allocated = 0;
	int err = 0;

	while (nr_allocated + page_pool_size < target_size) {
		page = __pram_alloc_new_page(GFP_KERNEL);
		if (!page) {
			err = -ENOMEM;
			break;
		}
		list_add(&page->lru, &allocated);
		nr_allocated++;
	}

	spin_lock(&page_pool_lock);
	list_splice(&allocated, &page_pool);
	page_pool_size += nr_allocated;
	spin_unlock(&page_pool_lock);

	return err;
}

static void page_pool_shrink(unsigned long target_size)
{
	struct page *page, *tmp;
	LIST_HEAD(throw_away);

	spin_lock(&page_pool_lock);
	if (page_pool_size <= target_size) {
		spin_unlock(&page_pool_lock);
		return;
	}
	list_for_each_entry(page, &page_pool, lru)
		if (--page_pool_size <= target_size)
			break;
	list_cut_position(&throw_away, &page_pool, &page->lru);
	spin_unlock(&page_pool_lock);

	list_for_each_entry_safe(page, tmp, &throw_away, lru)
		__free_page(page);
}

static ssize_t pram_prealloc_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%lu\n", page_pool_size);
}

static ssize_t pram_prealloc_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	static DEFINE_MUTEX(mutex);
	unsigned long target_size;
	int err = 0;

	if (strict_strtoul(buf, 10, &target_size))
		return -EINVAL;

	mutex_lock(&mutex);
	if (page_pool_size > target_size)
		page_pool_shrink(target_size);
	else if (page_pool_size < target_size)
		err = page_pool_grow(target_size);
	mutex_unlock(&mutex);

	return err ? err : count;
}

static struct kobj_attribute pram_prealloc_attr =
	__ATTR(pram_prealloc, 0644, pram_prealloc_show, pram_prealloc_store);

static ssize_t pram_csum_mode_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	const struct pram_csum_mode *cur_csum_mode = pram_get_csum_mode();
	const struct pram_csum_mode * const *p, *m;
	int len = 0;

	for (p = csum_mode_list; (m = *p); p++) {
		if (!strcmp(cur_csum_mode->name, m->name))
			len += sprintf(buf + len, "[%s] ", m->name);
		else
			len += sprintf(buf + len, "%s ", m->name);
	}
	len += sprintf(buf + len, "\n");
	return len;
}

static ssize_t pram_csum_mode_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	char raw_name[PRAM_CSUM_NAME_MAX], *name;
	const struct pram_csum_mode * const *p, *m;

	strlcpy(raw_name, buf, sizeof(raw_name));
	name = strstrip(raw_name);

	for (p = csum_mode_list; (m = *p); p++) {
		if (!strcmp(name, m->name))
			break;
	}
	if (!m)
		return -EINVAL;
	pram_set_csum_mode(m);
	return count;
}

static struct kobj_attribute pram_csum_mode_attr = __ATTR(pram_csum_mode,
		0644, pram_csum_mode_show, pram_csum_mode_store);

static struct attribute *pram_attrs[] = {
	&pram_attr.attr,
	&pram_low_attr.attr,
	&pram_banned_attr.attr,
	&pram_prealloc_attr.attr,
	&pram_csum_mode_attr.attr,
	NULL,
};

static struct attribute_group pram_attr_group = {
	.attrs = pram_attrs,
};

void __init pram_init(void)
{
	int ret;

	pram_select_csum_mode();
	pram_init_preallocs();
	ret = pram_build_list();
	if (ret)
		printk(KERN_ERR "PRAM: failed to build list: %d\n", ret);
}

static int __init pram_init_late(void)
{
	hotcpu_notifier(pram_callback, 0);
	register_shrinker(&banned_pages_shrinker);
	sysfs_update_group(kernel_kobj, &pram_attr_group);
	return 0;
}
module_init(pram_init_late);
