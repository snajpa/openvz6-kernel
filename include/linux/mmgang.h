#ifndef _LINIX_MMGANG_H
#define _LINIX_MMGANG_H

#include <linux/mm.h>
#include <linux/mm_inline.h>
#include <linux/sched.h>
#include <bc/beancounter.h>
#include <bc/vmpages.h>

void setup_zone_gang(struct gang_set *gs, struct zone *zone, struct gang *gang);

#ifndef CONFIG_BC_RSS_ACCOUNTING

extern struct gang_set init_gang_set;

static inline struct gang_set *get_mapping_gang(struct address_space *mapping)
{
	return &init_gang_set;
}

static inline struct gang_set *get_mm_gang(struct mm_struct *mm)
{
	return &init_gang_set;
}

static inline struct gang_set *get_ub_gs(struct user_beancounter *ub)
{
	return &init_gang_set;
}

static inline struct user_beancounter *get_gangs_ub(struct gang_set *gs)
{
	return get_ub0();
}

static inline struct user_beancounter *get_gang_ub(struct gang *gang)
{
	return get_ub0();
}

#else /* CONFIG_BC_RSS_ACCOUNTING */

#define init_gang_set	(ub0.gang_set)

static inline struct gang_set *get_mapping_gang(struct address_space *mapping)
{
	return &get_exec_ub()->gang_set;
}

static inline struct gang_set *get_mm_gang(struct mm_struct *mm)
{
	return &mm_ub(mm)->gang_set;
}

static inline struct gang_set *get_ub_gs(struct user_beancounter *ub)
{
	return &ub->gang_set;
}

static inline struct user_beancounter *get_gangs_ub(struct gang_set *gs)
{
	return container_of(gs, struct user_beancounter, gang_set);
}

static inline struct user_beancounter *get_gang_ub(struct gang *gang)
{
	return get_gangs_ub(gang->set);
}

#endif /* CONFIG_BC_RSS_ACCOUNTING */

static inline struct gang *lruvec_gang(struct lruvec *lruvec)
{
	return container_of(lruvec, struct gang, lruvec);
}

#ifdef CONFIG_MEMORY_GANGS

static inline struct gang *page_gang(struct page *page)
{
	return container_of(rcu_dereference(page->lruvec), struct gang, lruvec);
}

static inline void set_page_gang(struct page *page, struct gang *gang)
{
	set_page_lruvec(page, &gang->lruvec);
}

static inline struct gang *mem_zone_gang(struct gang_set *gs, struct zone *zone)
{
	return &gs->gangs[zone_to_nid(zone)][zone_idx(zone)];
}

static inline struct gang *mem_page_gang(struct gang_set *gs, struct page *page)
{
	return &gs->gangs[page_to_nid(page)][page_zonenum(page)];
}

static inline bool gang_in_shadow(struct gang *gang)
{
	return test_bit(GANG_IN_SHADOW, &gang->flags);
}

static inline bool gang_of_junk(struct gang *gang)
{
	return test_bit(GANG_OF_JUNK, &gang->flags);
}

static inline struct gang *gang_to_shadow_gang(struct gang *gang)
{
	return gang->shadow;
}

static inline bool page_in_gang(struct page *page, struct gang_set *gs)
{
	struct gang *gang;
	bool ret;

	rcu_read_lock();
	gang = page_gang(page);
	ret = (gang->set == gs) && !gang_in_shadow(gang);
	rcu_read_unlock();

	return ret;
}

void add_zone_gang(struct zone *zone, struct gang *gang);
void set_gang_priority(struct gang *gang, int priority);
void update_vmscan_priority(struct gang *gang);
void set_gang_limits(struct gang_set *gs, unsigned long *limit, nodemask_t *nodemask);
static inline int get_zone_nr_gangs(struct zone *zone) { return zone->nr_gangs; }
int alloc_mem_gangs(struct gang_set *gs);
void free_mem_gangs(struct gang_set *gs);
void add_mem_gangs(struct gang_set *gs);
void del_mem_gangs(struct gang_set *gs);
void junk_mem_gangs(struct gang_set *gs);
#define for_each_gang(gang, zone)			\
	list_for_each_entry_rcu(gang, &zone->gangs, list)
static inline int pin_mem_gang(struct gang *gang)
{
	struct user_beancounter *ub = get_gang_ub(gang);
	if (!get_beancounter_rcu(ub))
		return -EBUSY;
	ub_percpu_inc(ub, pincount);
	return 0;
}
static inline void unpin_mem_gang(struct gang *gang)
{
	struct user_beancounter *ub = get_gang_ub(gang);
	ub_percpu_dec(ub, pincount);
	put_beancounter(ub);
}

static inline void gang_add_free_page(struct page *page)
{
	set_page_gang(page, NULL);
}
static inline int gang_add_user_page(struct page *page,
		struct gang_set *gs, gfp_t gfp_mask)
{
	VM_BUG_ON(page->lruvec);
	if (ub_phys_charge(get_gangs_ub(gs), hpage_nr_pages(page), gfp_mask))
		return -ENOMEM;
	set_page_gang(page, mem_page_gang(gs, page));
	return 0;
}
static inline int gang_mod_user_page(struct page *page,
		struct gang_set *gs, gfp_t gfp_mask)
{
	int numpages = hpage_nr_pages(page);
	struct gang *gang = page_gang(page);
	struct user_beancounter *ub = get_gang_ub(gang);

	if (ub_phys_charge(get_gangs_ub(gs), numpages,
				gfp_mask|__GFP_NORETRY))
		return -ENOMEM;
	if (!gang_in_shadow(gang)) {
		ub_phys_uncharge(ub, numpages);
	} else {
		uncharge_beancounter_fast(ub, UB_SHADOWPAGES, numpages);
		if (PageSwapBacked(page))
			uncharge_beancounter_fast(ub, UB_SWAPPAGES, numpages);
	}

	VM_BUG_ON(PageLRU(page));
	spin_lock_irq(&gang->lruvec.lru_lock);
	set_page_gang(page, mem_page_gang(gs, page));
	spin_unlock_irq(&gang->lruvec.lru_lock);
	return 0;
}
static inline int gang_mod_shadow_page(struct page *page)
{
	int numpages = hpage_nr_pages(page);
	struct gang *gang = page_gang(page);
	struct user_beancounter *ub = get_gang_ub(gang);

	VM_BUG_ON(gang_in_shadow(gang));
	VM_BUG_ON(PageLRU(page));

	if (PageSwapBacked(page)) {
		if (charge_beancounter_fast(ub, UB_SWAPPAGES,
					    numpages, UB_SOFT | UB_TEST))
			return -ENOMEM;
	}

	ub_phys_uncharge(ub, numpages);
	charge_beancounter_fast(ub, UB_SHADOWPAGES, numpages, UB_FORCE);
	spin_lock_irq(&gang->lruvec.lru_lock);
	set_page_gang(page, gang_to_shadow_gang(gang));
	spin_unlock_irq(&gang->lruvec.lru_lock);
	return 0;
}
static inline void gang_del_user_page(struct page *page)
{
	struct gang *gang = page_gang(page);
	int numpages = hpage_nr_pages(page);
	struct user_beancounter *ub = get_gang_ub(gang);

	if (!gang_in_shadow(gang)) {
		ub_phys_uncharge(ub, numpages);
	} else {
		uncharge_beancounter_fast(ub, UB_SHADOWPAGES, numpages);
		if (PageSwapBacked(page))
			uncharge_beancounter_fast(ub, UB_SWAPPAGES, numpages);
	}
	set_page_gang(page, NULL);
}

static inline bool
is_lru_milestone(struct lruvec *lruvec, struct list_head *list)
{
	struct gang *gang = lruvec_gang(lruvec);

	return list >= gang->milestones[0].lru &&
	       list < gang->milestones[NR_LRU_MILESTONES].lru;
}

extern bool insert_lru_milestone(struct gang *gang, unsigned long now,
				 unsigned long *eldest_milestone);
extern void remove_lru_milestone(struct lruvec *lruvec, enum lru_list lru);

extern struct gang *init_gang_array[];

extern unsigned long total_committed_pages;

#else /* CONFIG_MEMORY_GANGS */

static inline struct gang *page_gang(struct page *page)
{
       return zone_init_gang(page_zone(page));
}

static inline void set_page_gang(struct page *page, struct gang *gang)
{
}

static inline struct gang *mem_zone_gang(struct gang_set *gs, struct zone *zone)
{
	return &zone->init_gang;
}

static inline struct gang *mem_page_gang(struct gang_set *gs, struct page *page)
{
	return &page_zone(page)->init_gang;
}

static inline bool gang_in_shadow(struct gang *gang)
{
	return false;
}

static inline bool page_in_gang(struct page *page, struct gang_set *gs)
{
	return true;
}

static inline void add_zone_gang(struct zone *zone, struct gang *gang) { }
static inline void set_gang_priority(struct gang *gang, int priority) { }
static inline void update_vmscan_priority(struct gang *gang) { }
static inline void set_gang_limits(struct gang_set *gs,
		unsigned long *limit, nodemask_t *nodemask) { }
static inline int get_zone_nr_gangs(struct zone *zone) { return 1; }
static inline void free_mem_gangs(struct gang_set *gs) { }
static inline int alloc_mem_gangs(struct gang_set *gs) { return 0; }
static inline void add_mem_gangs(struct gang_set *gs) { }
static inline void del_mem_gangs(struct gang_set *gs) { }
static inline void junk_mem_gangs(struct gang_set *gs)  { }
#define for_each_gang(gang, zone)			\
	for ( gang = &(zone)->init_gang ; gang ; gang = NULL )
static inline int pin_mem_gang(struct gang *gang) { return 0; }
static inline void unpin_mem_gang(struct gang *gang) { }

static inline void gang_add_free_page(struct page *page) { }
static inline int gang_add_user_page(struct page *page,
		struct gang_set *gs, gfp_t gfp_mask) { return 0; }
static inline int gang_mod_user_page(struct page *page,
		struct gang_set *gs, gfp_t gfp_mask) { return 0; }
static inline int gang_mod_shadow_page(struct page *page) { return 0; }
static inline void gang_del_user_page(struct page *page) { }

static inline bool
is_lru_milestone(struct lruvec *lruvec, struct list_head *list)
{
	return false;
}
static inline bool insert_lru_milestone(struct lruvec *lruvec, unsigned long now,
					unsigned long *eldest_milestone)
{
	return false;
}
static inline void remove_lru_milestone(struct lruvec *lruvec, enum lru_list lru)
{
}

#endif /* CONFIG_MEMORY_GANGS */

#ifdef CONFIG_MEMORY_GANGS_MIGRATION
extern unsigned int gangs_migration_max_isolate;
extern unsigned int gangs_migration_min_batch;
extern unsigned int gangs_migration_max_batch;
extern unsigned int gangs_migration_interval;

extern int schedule_gangs_migration(struct gang_set *gs,
		const nodemask_t *src_nodes, const nodemask_t *dest_nodes);
extern int cancel_gangs_migration(struct gang_set *gs);
extern int gangs_migration_pending(struct gang_set *gs, nodemask_t *pending);

extern int gangs_migration_batch_sysctl_handler(struct ctl_table *table,
		int write, void __user *buffer, size_t *lenp, loff_t *ppos);
#else
static inline int schedule_gangs_migration(struct gang_set *gs,
		const nodemask_t *src_nodes, const nodemask_t *dest_nodes)
{
	return 1;
}
static inline int cancel_gangs_migration(struct gang_set *gs)
{
	return 0;
}
static inline int gangs_migration_pending(struct gang_set *gs,
					  nodemask_t *pending)
{
	if (pending)
		nodes_clear(*pending);
	return 0;
}
#endif

void gang_page_stat(struct gang_set *gs, bool acct_hier, nodemask_t *nodemask,
		    unsigned long *stat, unsigned long *shadow);
void gang_show_state(struct gang_set *gs);

#endif /* _LINIX_MMGANG_H */
