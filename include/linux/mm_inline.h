#ifndef LINUX_MM_INLINE_H
#define LINUX_MM_INLINE_H

#include <linux/huge_mm.h>
#include <linux/rcupdate.h>

/**
 * page_is_file_cache - should the page be on a file LRU or anon LRU?
 * @page: the page to test
 *
 * Returns 1 if @page is page cache page backed by a regular filesystem,
 * or 0 if @page is anonymous, tmpfs or otherwise ram or swap backed.
 * Used by functions that manipulate the LRU lists, to sort a page
 * onto the right LRU list.
 *
 * We would like to get this info without a page flag, but the state
 * needs to survive until the page is last deleted from the LRU, which
 * could be as far down as __page_cache_release.
 */
static inline int page_is_file_cache(struct page *page)
{
	return !PageSwapBacked(page);
}

static struct zone *lruvec_zone(struct lruvec *lruvec)
{
	return lruvec->zone;
}

static inline struct lruvec *page_lruvec(struct page *page)
{
	return rcu_dereference(page->lruvec);
}

static inline struct lruvec *__page_lruvec(struct page *page)
{
	return rcu_access_pointer(page->lruvec);
}

static inline void set_page_lruvec(struct page *page, struct lruvec *lruvec)
{
	rcu_assign_pointer(page->lruvec, lruvec);
}

static inline struct lruvec *
relock_lruvec(struct lruvec *locked, struct lruvec *lruvec)
{
	if (unlikely(locked != lruvec)) {
		if (locked)
			spin_unlock(&locked->lru_lock);
		spin_lock(&lruvec->lru_lock);
	}
	return lruvec;
}

static inline void
unlock_lruvec(struct lruvec *lruvec)
{
	if (lruvec)
		spin_unlock(&lruvec->lru_lock);
}

static inline struct lruvec *lock_page_lru(struct page *page)
{
	struct lruvec *lruvec;

	rcu_read_lock();
	while (1) {
		lruvec = page_lruvec(page);
		spin_lock(&lruvec->lru_lock);
		if (likely(__page_lruvec(page) == lruvec))
			break;
		spin_unlock(&lruvec->lru_lock);
	}
	rcu_read_unlock();

	return lruvec;
}

static inline struct lruvec *
relock_page_lru(struct lruvec *locked, struct page *page)
{
	struct lruvec *lruvec = __page_lruvec(page);

	if (unlikely(locked != lruvec)) {
		if (locked)
			spin_unlock(&locked->lru_lock);
		lruvec = lock_page_lru(page);
	}
	return lruvec;
}

static inline bool
try_relock_page_lru(struct lruvec **locked, struct page *page)
{
	struct lruvec *lruvec;

	while (PageLRU(page)) {
		rcu_read_lock();
		lruvec = page_lruvec(page);
		if (lruvec) {
			*locked = relock_lruvec(*locked, lruvec);
			if (__page_lruvec(page) == lruvec) {
				rcu_read_unlock();
				return PageLRU(page);
			}
		}
		rcu_read_unlock();
	}

	return false;
}

static inline void
add_page_to_lru_list(struct lruvec *lruvec, struct page *page, enum lru_list l)
{
	struct zone *zone = lruvec_zone(lruvec);
	int numpages = hpage_nr_pages(page);

	list_add(&page->lru, &lruvec->lru_list[l]);
	lruvec->nr_pages[l] += numpages;
	__mod_zone_page_state(zone, NR_LRU_BASE + l, numpages);
}

static inline void
del_page_from_lru_list(struct lruvec *lruvec, struct page *page, enum lru_list l)
{
	struct zone *zone = lruvec_zone(lruvec);
	int numpages = hpage_nr_pages(page);

	list_del(&page->lru);
	lruvec->nr_pages[l] -= numpages;
	__mod_zone_page_state(zone, NR_LRU_BASE + l, -numpages);
}

/**
 * page_lru_base_type - which LRU list type should a page be on?
 * @page: the page to test
 *
 * Used for LRU list index arithmetic.
 *
 * Returns the base LRU type - file or anon - @page should be on.
 */
static inline enum lru_list page_lru_base_type(struct page *page)
{
	if (page_is_file_cache(page))
		return LRU_INACTIVE_FILE;
	return LRU_INACTIVE_ANON;
}

static inline void
del_page_from_lru(struct lruvec *lruvec, struct page *page)
{
	enum lru_list l;

	if (PageUnevictable(page)) {
		__ClearPageUnevictable(page);
		l = LRU_UNEVICTABLE;
	} else {
		l = page_lru_base_type(page);
		if (PageActive(page)) {
			__ClearPageActive(page);
			l += LRU_ACTIVE;
		}
	}
	del_page_from_lru_list(lruvec, page, l);
}

/**
 * page_lru - which LRU list should a page be on?
 * @page: the page to test
 *
 * Returns the LRU list a page should be on, as an index
 * into the array of LRU lists.
 */
static inline enum lru_list page_lru(struct page *page)
{
	enum lru_list lru;

	if (PageUnevictable(page))
		lru = LRU_UNEVICTABLE;
	else {
		lru = page_lru_base_type(page);
		if (PageActive(page))
			lru += LRU_ACTIVE;
	}

	return lru;
}

#endif
