/*
 * linux/mm/mmzone.c
 *
 * management codes for pgdats and zones.
 */


#include <linux/stddef.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/mmgang.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/module.h>
#include <linux/mm_inline.h>
#include <linux/migrate.h>

#include "internal.h"

static DEFINE_MUTEX(gs_lock);

unsigned long total_committed_pages;

unsigned long commitment_for_unlimited_containers = 1ul << (30 - PAGE_SHIFT); /* 1Gb */

struct pglist_data *first_online_pgdat(void)
{
	return NODE_DATA(first_online_node);
}
EXPORT_SYMBOL(first_online_pgdat);

struct pglist_data *next_online_pgdat(struct pglist_data *pgdat)
{
	int nid = next_online_node(pgdat->node_id);

	if (nid == MAX_NUMNODES)
		return NULL;
	return NODE_DATA(nid);
}
EXPORT_SYMBOL(next_online_pgdat);

/*
 * next_zone - helper magic for for_each_zone()
 */
struct zone *next_zone(struct zone *zone)
{
	pg_data_t *pgdat = zone->zone_pgdat;

	if (zone < pgdat->node_zones + MAX_NR_ZONES - 1)
		zone++;
	else {
		pgdat = next_online_pgdat(pgdat);
		if (pgdat)
			zone = pgdat->node_zones;
		else
			zone = NULL;
	}
	return zone;
}

static inline int zref_in_nodemask(struct zoneref *zref, nodemask_t *nodes)
{
#ifdef CONFIG_NUMA
	return node_isset(zonelist_node_idx(zref), *nodes);
#else
	return 1;
#endif /* CONFIG_NUMA */
}

/* Returns the next zone at or below highest_zoneidx in a zonelist */
struct zoneref *next_zones_zonelist(struct zoneref *z,
					enum zone_type highest_zoneidx,
					nodemask_t *nodes,
					struct zone **zone)
{
	/*
	 * Find the next suitable zone to use for the allocation.
	 * Only filter based on nodemask if it's set
	 */
	if (likely(nodes == NULL))
		while (zonelist_zone_idx(z) > highest_zoneidx)
			z++;
	else
		while (zonelist_zone_idx(z) > highest_zoneidx ||
				(z->zone && !zref_in_nodemask(z, nodes)))
			z++;

	*zone = zonelist_zone(z);
	return z;
}

#ifdef CONFIG_ARCH_HAS_HOLES_MEMORYMODEL
int memmap_valid_within(unsigned long pfn,
					struct page *page, struct zone *zone)
{
	if (page_to_pfn(page) != pfn)
		return 0;

	if (page_zone(page) != zone)
		return 0;

	return 1;
}
#endif /* CONFIG_ARCH_HAS_HOLES_MEMORYMODEL */

void lruvec_init(struct lruvec *lruvec)
{
	enum lru_list lru;

	memset(lruvec, 0, sizeof(struct lruvec));

	spin_lock_init(&lruvec->lru_lock);
	for_each_lru(lru)
		INIT_LIST_HEAD(&lruvec->lru_list[lru]);
}

void setup_zone_gang(struct gang_set *gs, struct zone *zone, struct gang *gang)
{
	enum lru_list lru;
	int __maybe_unused i;

	lruvec_init(&gang->lruvec);
	gang->lruvec.zone = zone;
	gang->set = gs;

#ifdef CONFIG_MEMORY_GANGS
	gang->last_milestone = 0;
	for_each_evictable_lru(lru) {
		gang->timestamp[lru] = jiffies;
		for (i = 0; i < NR_LRU_MILESTONES; i++)
			INIT_LIST_HEAD(&gang->milestones[i].lru[lru]);
	}
	gang->lruvec.priority = DEF_PRIORITY;
#endif
}

#ifdef CONFIG_MEMORY_GANGS

void remove_lru_milestone(struct lruvec *lruvec, enum lru_list lru)
{
	struct gang *gang = lruvec_gang(lruvec);
	struct lru_milestone *ms;

	ms = container_of(lruvec->lru_list[lru].prev,
			struct lru_milestone, lru[lru]);
	list_del_init(&ms->lru[lru]);
	gang->timestamp[lru] = ms->timestamp;

	set_bit(GANG_NEED_RESCHED, &gang->flags);
}

bool insert_lru_milestone(struct gang *gang, unsigned long now,
			  unsigned long *eldest_milestone)
{
	bool reused = false;
	struct lru_milestone *ms;
	enum lru_list lru;

	*eldest_milestone = now;
	gang->last_milestone = (gang->last_milestone + 1) % NR_LRU_MILESTONES;
	ms = gang->milestones + gang->last_milestone;
	for_each_evictable_lru(lru) {
		if (!list_empty(&ms->lru[lru])) {
			list_del(&ms->lru[lru]);
			if (is_file_lru(lru) || get_nr_swap_pages() > 0) {
				reused = true;
				if (time_before(ms->timestamp, *eldest_milestone))
					*eldest_milestone = ms->timestamp;
			}
		} else {
			if ((is_file_lru(lru) || get_nr_swap_pages() > 0) &&
			    time_before(gang->timestamp[lru], *eldest_milestone))
				*eldest_milestone = gang->timestamp[lru];
		}
		list_add(&ms->lru[lru], &gang->lruvec.lru_list[lru]);
	}
	ms->timestamp = now;
	return reused;
}

static void splice_timed_pages(struct gang *gang, enum lru_list lru,
		struct list_head *pages, unsigned long timestamp)
{
	struct list_head *head = &gang->lruvec.lru_list[lru];
	struct lru_milestone *ms;
	int i;

	if (is_unevictable_lru(lru)) {
		list_splice_tail(pages, head);
		return;
	}

	for (i = 0; i < NR_LRU_MILESTONES; i++) {
		ms = gang->milestones + (gang->last_milestone +
				NR_LRU_MILESTONES - i) % NR_LRU_MILESTONES;
		if (list_empty(ms->lru + lru)) {
			list_add_tail(ms->lru + lru,
					&gang->lruvec.lru_list[lru]);
			gang->timestamp[lru] = ms->timestamp;
		}
		if (time_after_eq(timestamp, ms->timestamp)) {
			head = ms->lru + lru;
			break;
		}
	}

	list_splice_tail(pages, head);
}

void add_zone_gang(struct zone *zone, struct gang *gang)
{
	unsigned long flags;

	spin_lock_irqsave(&zone->gangs_lock, flags);
	list_add_tail_rcu(&gang->list, &zone->gangs);
	zone->nr_gangs++;
	list_add_rcu(&gang->vmscan_list, zone->vmscan_prio + gang->lruvec.priority);
	__set_bit(gang->lruvec.priority, zone->vmscan_mask);
	spin_unlock_irqrestore(&zone->gangs_lock, flags);
}

static void del_zone_gang(struct zone *zone, struct gang *gang)
{
	struct lruvec *lruvec = &gang->lruvec;
	unsigned long flags;
	enum lru_list lru;
	int i;

	spin_lock_irqsave(&zone->gangs_lock, flags);
	set_bit(GANG_UNHASHED, &gang->flags);
	list_del_rcu(&gang->list);
	list_del_rcu(&gang->vmscan_list);
	if (list_empty(zone->vmscan_prio + lruvec->priority))
		__clear_bit(lruvec->priority, zone->vmscan_mask);
	for (i = 0; i < NR_VMSCAN_PRIORITIES; i++)
		(void)cmpxchg(zone->vmscan_iter + i, &gang->vmscan_list,
			      gang->vmscan_list.next);
	zone->nr_gangs--;
	spin_unlock_irqrestore(&zone->gangs_lock, flags);

	BUG_ON(gang->committed);

	spin_lock_irqsave(&lruvec->lru_lock, flags);
	for_each_evictable_lru(lru) {
		while (is_lru_milestone(lruvec, lruvec->lru_list[lru].prev))
			remove_lru_milestone(lruvec, lru);
	}

	for_each_lru(lru) {
		if (lruvec->nr_pages[lru] ||
		    !list_empty(&lruvec->lru_list[lru])) {
			printk(KERN_EMERG "gang leak:%ld lru:%d gang:%p\n",
					lruvec->nr_pages[lru], lru, gang);
			add_taint(TAINT_CRAP);
		}
	}
	spin_unlock_irqrestore(&lruvec->lru_lock, flags);
}

void set_gang_priority(struct gang *gang, int priority)
{
	struct lruvec *lruvec = &gang->lruvec;
	struct zone *zone = gang_zone(gang);
	int i;

	VM_BUG_ON(priority < 0 || priority > MAX_VMSCAN_PRIORITY);

	spin_lock_irq(&zone->gangs_lock);
	if (lruvec->priority == priority ||
	    test_bit(GANG_UNHASHED, &gang->flags))
		goto out;
	list_del_rcu(&gang->vmscan_list);
	if (list_empty(zone->vmscan_prio + lruvec->priority))
		__clear_bit(lruvec->priority, zone->vmscan_mask);
	for (i = 0; i <= lruvec->priority; i++)
		(void)cmpxchg(zone->vmscan_iter + i, &gang->vmscan_list,
				gang->vmscan_list.next);
	lruvec->priority = priority;
	list_add_rcu(&gang->vmscan_list, zone->vmscan_prio + priority);
	__set_bit(priority, zone->vmscan_mask);
out:
	spin_unlock_irq(&zone->gangs_lock);
}

void set_gang_limits(struct gang_set *gs,
		     unsigned long *newlimit, nodemask_t *newmask)
{
	unsigned long limit, available, committed, portion;
	unsigned long max_committed, zone_committed, gang_committed;
	nodemask_t nodemask;
	struct zone *zone;
	struct gang *gang;
	int nid;

	/* sub-beancounters do not contribute to global commitment */
	if (get_gangs_ub(gs)->parent)
		return;

	mutex_lock(&gs_lock);

	if (gs->memory_limit > totalram_pages) {
		for_each_zone(zone)
			if (node_isset(zone_to_nid(zone), gs->nodemask))
				zone->nr_unlimited_gangs--;
	}

	if (newlimit)
		gs->memory_limit = *newlimit;
	if (newmask)
		gs->nodemask = *newmask;
	limit = gs->memory_limit;
	nodemask = gs->nodemask;

#ifdef CONFIG_MEMORY_GANGS_MIGRATION
	/* include migration source nodes into coverage */
	nodes_or(nodemask, nodemask, gs->migration_work.src_nodes);
#endif

	available = 0;
	for_each_zone(zone) {
		if (node_isset(zone_to_nid(zone), nodemask)) {
			available += zone->present_pages;
			if (limit > totalram_pages)
				zone->nr_unlimited_gangs++;
		}
	}
	gs->memory_available = available;

	committed = min(limit, available);

	/* limit commitment for unlimited containers */
	if (limit > totalram_pages)
		committed = min(committed, commitment_for_unlimited_containers);

	total_committed_pages += committed - gs->memory_committed;
	gs->memory_committed = committed;

	for_each_zone(zone) {
		nid = zone_to_nid(zone);
		gang = mem_zone_gang(gs, zone);
		if (!gang->committed && !node_isset(nid, nodemask))
			continue;
		spin_lock_irq(&zone->gangs_lock);
		zone->committed -= gang->committed;
		if (node_isset(nid, nodemask) && available)
			gang->committed = committed * zone->present_pages
						    / available;
		else
			gang->committed = 0;
		zone->committed += gang->committed;

		/* get maximum memory commitment among limited containers */
		max_committed = 0;
		for_each_gang(gang, zone) {
			if (gang->set->memory_limit <= totalram_pages &&
			    gang->committed > max_committed)
				max_committed = gang->committed;
		}

		zone_committed = zone->committed +
			max_committed * zone->nr_unlimited_gangs;

		for_each_gang(gang, zone) {
			gang_committed = gang->committed;

			/*
			 * increase commitment of unlimited containers by
			 * maximum commitment among limited containers
			 */
			if (gang_committed &&
			    gang->set->memory_limit > totalram_pages)
				gang_committed += max_committed;

			if (zone_committed > zone->present_pages) {
				portion = zone->present_pages
						* gang_committed
						/ zone_committed;
			} else {
				portion = gang_committed;
				/* divide remains between unlimited containers */
				if (gang_committed &&
				    gang->set->memory_limit > totalram_pages)
					portion += (zone->present_pages -
							zone_committed) /
							zone->nr_unlimited_gangs;
			}
			gang->set->memory_portion += portion - gang->portion;
			gang->portion = portion;
		}
		spin_unlock_irq(&zone->gangs_lock);
	}

	mutex_unlock(&gs_lock);
}

int commitment_for_unlimited_containers_handler(struct ctl_table *table,
		int write, void __user *buffer, size_t *lenp, loff_t *ppos)
{
	struct user_beancounter *ub;
	int err;

	err = proc_doulongvec_minmax(table, write, buffer, lenp, ppos);
	if (!err && write) {
		rcu_read_lock();
		for_each_top_beancounter(ub) {
			if (get_beancounter_rcu(ub)) {
				rcu_read_unlock();
				set_gang_limits(get_ub_gs(ub), NULL, NULL);
				rcu_read_lock();
				put_beancounter(ub);
			}
		}
		rcu_read_unlock();
	}
	return err;
}

#ifdef CONFIG_MEMORY_GANGS_MIGRATION
static void init_gangs_migration_work(struct gang_set *gs);
#else
static inline void init_gangs_migration_work(struct gang_set *gs) { }
#endif

int alloc_mem_gangs(struct gang_set *gs)
{
	struct zone *zone;
	struct gang *gang;
	int node, zid;

	memset(gs, 0, sizeof(struct gang_set));

	gs->gangs = kzalloc(nr_node_ids * sizeof(struct gang *), GFP_KERNEL);
	if (!gs->gangs)
		goto noarr;

	/* decrease NR_LRU_MILESTONES if it doesn't fit */
	BUILD_BUG_ON(sizeof(struct gang) * MAX_NR_ZONES > (PAGE_SIZE << 2));

	for_each_node(node) {
		gs->gangs[node] = kzalloc_node(sizeof(struct gang)
				* MAX_NR_ZONES, GFP_KERNEL, node);
		if (!gs->gangs[node])
			goto nomem;
		for (zid = 0; zid < MAX_NR_ZONES; zid++) {
			gs->gangs[node][zid].shadow =
				kzalloc_node(sizeof(struct gang),
						GFP_KERNEL, node);
			if (!gs->gangs[node][zid].shadow)
				goto nomem;
		}
	}

	for_each_populated_zone(zone) {
		gang = mem_zone_gang(gs, zone);
		setup_zone_gang(gs, zone, gang);
		gang = gang_to_shadow_gang(gang);
		setup_zone_gang(gs, zone, gang);
		__set_bit(GANG_IN_SHADOW, &gang->flags);
	}

	init_gangs_migration_work(gs);

	return 0;

nomem:
	free_mem_gangs(gs);
noarr:
	return -ENOMEM;
}

void free_mem_gangs(struct gang_set *gs)
{
	int node, zid;

	for_each_node(node) {
		for (zid = 0; zid < MAX_NR_ZONES; zid++)
			kfree(gs->gangs[node][zid].shadow);
		kfree(gs->gangs[node]);
	}
	kfree(gs->gangs);
}

void add_mem_gangs(struct gang_set *gs)
{
	struct zone *zone;

	for_each_populated_zone(zone) {
		struct gang * gang = mem_zone_gang(gs, zone);

		add_zone_gang(zone, gang_to_shadow_gang(gang));
		add_zone_gang(zone, gang);
	}
}

#define MAX_MOVE_BATCH	256

static void move_gang_pages(struct gang *gang, struct gang *dst_gang)
{
	enum lru_list lru;
	int restart;
	struct user_beancounter *src_ub = get_gang_ub(gang);
	struct user_beancounter *dst_ub = get_gang_ub(dst_gang);
	LIST_HEAD(pages_to_wait);
	LIST_HEAD(pages_to_free);
	struct lruvec *lruvec;

again:
	restart = 0;
	for_each_lru(lru) {
		struct page *page, *next;
		LIST_HEAD(list);
		unsigned long nr_pages = 0;
		unsigned long uninitialized_var(timestamp);
		unsigned batch = 0;

		lruvec = &gang->lruvec;
		spin_lock_irq(&lruvec->lru_lock);
		list_for_each_entry_safe_reverse(page, next,
				&lruvec->lru_list[lru], lru) {
			int numpages;

			if (is_lru_milestone(lruvec, &page->lru)) {
				remove_lru_milestone(lruvec, lru);
				continue;
			}

			numpages = hpage_nr_pages(page);

			if (batch >= MAX_MOVE_BATCH) {
				restart = 1;
				break;
			}
			if (!get_page_unless_zero(page)) {
				list_move(&page->lru, &pages_to_wait);
				continue;
			}
			batch++;
			nr_pages += numpages;
			ClearPageLRU(page);
			set_page_gang(page, dst_gang);
			list_move(&page->lru, &list);
		}
		list_splice_init(&pages_to_wait, &lruvec->lru_list[lru]);
		lruvec->nr_pages[lru] -= nr_pages;
		if (!is_unevictable_lru(lru))
			timestamp = gang->timestamp[lru];
		spin_unlock_irq(&lruvec->lru_lock);

		if (!nr_pages)
			continue;

#ifdef CONFIG_BC_SWAP_ACCOUNTING
		if (!is_file_lru(lru) && !is_unevictable_lru(lru)) {
			list_for_each_entry(page, &list, lru) {
				if (PageSwapCache(page)) {
					lock_page(page);
					ub_unuse_swap_page(page);
					unlock_page(page);
				}
			}
		}
#endif

		if (!gang_in_shadow(gang)) {
			uncharge_beancounter_fast(src_ub,
					UB_PHYSPAGES, nr_pages);
		} else {
			uncharge_beancounter_fast(src_ub,
					UB_SHADOWPAGES, nr_pages);
			if (!is_file_lru(lru) && !is_unevictable_lru(lru))
				uncharge_beancounter_fast(src_ub, UB_SWAPPAGES,
							  nr_pages);
		}

		if (!gang_in_shadow(dst_gang)) {
			charge_beancounter_fast(dst_ub,
					UB_PHYSPAGES, nr_pages, UB_FORCE);
		} else {
			charge_beancounter_fast(dst_ub,
					UB_SHADOWPAGES, nr_pages, UB_FORCE);
			if (!is_file_lru(lru) && !is_unevictable_lru(lru))
				charge_beancounter_fast(dst_ub, UB_SWAPPAGES,
							nr_pages, UB_FORCE);
		}

		lruvec = &dst_gang->lruvec;
		spin_lock_irq(&lruvec->lru_lock);
		lruvec->nr_pages[lru] += nr_pages;
		list_for_each_entry_safe(page, next, &list, lru) {
			SetPageLRU(page);
			if (unlikely(put_page_testzero(page))) {
				__ClearPageLRU(page);
				del_page_from_lru(lruvec, page);
				gang_del_user_page(page);
				list_add(&page->lru, &pages_to_free);
			}
		}
		splice_timed_pages(dst_gang, lru, &list, timestamp);
		spin_unlock_irq(&lruvec->lru_lock);

		list_for_each_entry_safe(page, next, &pages_to_free, lru) {
			list_del(&page->lru);
			VM_BUG_ON(PageTail(page));
			if (PageCompound(page))
				get_compound_page_dtor(page)(page);
			else
				free_hot_page(page);
		}
	}
	update_vmscan_priority(gang);
	update_vmscan_priority(dst_gang);
	cond_resched();
	if (restart)
		goto again;
}

void junk_mem_gangs(struct gang_set *gs)
{
	struct zone *zone;

	cancel_gangs_migration(gs);

	lru_add_drain_all();

	for_each_populated_zone(zone) {
		struct gang *src, *dst;

		/* push normal and shadow gangs into shadow gang */
		src = mem_zone_gang(gs, zone);
		dst = zone_junk_gang(zone);
		move_gang_pages(src, dst);
		move_gang_pages(gang_to_shadow_gang(src), dst);
	}
}

void del_mem_gangs(struct gang_set *gs)
{
	struct zone *zone;

	for_each_populated_zone(zone) {
		struct gang *gang = mem_zone_gang(gs, zone);
		del_zone_gang(zone, gang);
		del_zone_gang(zone, gang_to_shadow_gang(gang));
	}
}

static void __gang_page_stat(struct gang_set *gs, nodemask_t *nodemask,
			     unsigned long *stat, unsigned long *shadow)
{
	struct zoneref *z;
	struct zone *zone;
	struct gang *gang;
	enum lru_list lru;

	for_each_zone_zonelist_nodemask(zone, z,
			node_zonelist(numa_node_id(), GFP_KERNEL),
			MAX_NR_ZONES - 1, nodemask) {
		gang = mem_zone_gang(gs, zone);
		for_each_lru(lru)
			stat[lru] += gang->lruvec.nr_pages[lru];
		if (shadow) {
			gang = gang_to_shadow_gang(gang);
			for_each_lru(lru)
				shadow[lru] += gang->lruvec.nr_pages[lru];
			if (gs == &init_gang_set) {
				gang = zone_junk_gang(zone);
				for_each_lru(lru)
					shadow[lru] += gang->lruvec.nr_pages[lru];
			}
		}
	}
}

void gang_page_stat(struct gang_set *gs, bool acct_hier, nodemask_t *nodemask,
		    unsigned long *stat, unsigned long *shadow)
{
	struct user_beancounter *ub;

	memset(stat, 0, sizeof(unsigned long) * NR_LRU_LISTS);
	if (shadow)
		memset(shadow, 0, sizeof(unsigned long) * NR_LRU_LISTS);

	__gang_page_stat(gs, nodemask, stat, shadow);

	if (!acct_hier)
		return;

	for_each_beancounter_tree(ub, get_gangs_ub(gs))
		if (ub != get_gangs_ub(gs))
			__gang_page_stat(get_ub_gs(ub), nodemask, stat, shadow);
}

static void show_one_gang(struct zone *zone, struct gang *gang)
{
	unsigned long now = jiffies;

	printk(" Node %d %s%s prio:%u portion:%ld scan:%lu"
	       " a_anon:%lu %dms i_anon:%lu %dms"
	       " a_file:%lu %dms i_file:%lu %dms"
	       " unevictable:%lu"
	       " reclaim_stat: %lu %lu %lu %lu\n",
	       zone_to_nid(zone), zone->name,
	       gang_of_junk(gang) ? "/junk" :
	       gang_in_shadow(gang) ? "/shadow" : "",
	       gang->lruvec.priority, gang->portion,
	       atomic_long_read(&gang->lruvec.pages_scanned),
	       gang->lruvec.nr_pages[LRU_ACTIVE_ANON],
	       jiffies_to_msecs(now - gang->timestamp[LRU_ACTIVE_ANON]),
	       gang->lruvec.nr_pages[LRU_INACTIVE_ANON],
	       jiffies_to_msecs(now - gang->timestamp[LRU_INACTIVE_ANON]),
	       gang->lruvec.nr_pages[LRU_ACTIVE_FILE],
	       jiffies_to_msecs(now - gang->timestamp[LRU_ACTIVE_FILE]),
	       gang->lruvec.nr_pages[LRU_INACTIVE_FILE],
	       jiffies_to_msecs(now - gang->timestamp[LRU_INACTIVE_FILE]),
	       gang->lruvec.nr_pages[LRU_UNEVICTABLE],
	       gang->lruvec.recent_scanned[0],
	       gang->lruvec.recent_rotated[0],
	       gang->lruvec.recent_scanned[1],
	       gang->lruvec.recent_rotated[1]);
}

void gang_show_state(struct gang_set *gs)
{
	struct zone *zone;
	struct gang *gang;
	struct user_beancounter *ub;
	unsigned long stat[NR_LRU_LISTS];

	for_each_beancounter_tree(ub, get_gangs_ub(gs)) {
		if (ub->parent) {
			printk("Memory cgroup ");
			ub_print_mem_cgroup_name(ub);
			printk(":\n");
		}
		for_each_populated_zone(zone) {
			gang = mem_zone_gang(get_ub_gs(ub), zone);
			show_one_gang(zone, gang);
			show_one_gang(zone, gang_to_shadow_gang(gang));
			if (ub == get_ub0())
				show_one_gang(zone, zone_junk_gang(zone));
		}
	}

	gang_page_stat(gs, true, NULL, stat, stat);

	printk("Total %lu anon:%lu file:%lu"
			" a_anon:%lu i_anon:%lu"
			" a_file:%lu i_file:%lu"
			" unevictable:%lu\n",
			stat[LRU_ACTIVE_ANON] + stat[LRU_INACTIVE_ANON] +
			stat[LRU_ACTIVE_FILE] + stat[LRU_INACTIVE_FILE] +
			stat[LRU_UNEVICTABLE],
			stat[LRU_ACTIVE_ANON] + stat[LRU_INACTIVE_ANON],
			stat[LRU_ACTIVE_FILE] + stat[LRU_INACTIVE_FILE],
			stat[LRU_ACTIVE_ANON],
			stat[LRU_INACTIVE_ANON],
			stat[LRU_ACTIVE_FILE],
			stat[LRU_INACTIVE_FILE],
			stat[LRU_UNEVICTABLE]);
}

#else /* CONFIG_MEMORY_GANGS */

void gang_page_stat(struct gang_set *gs, bool acct_hier, nodemask_t *nodemask,
		    unsigned long *stat, unsigned long *shadow)
{
	enum lru_list lru;

	if (shadow)
		memset(shadow, 0, sizeof(unsigned long) * NR_LRU_LISTS);
	for_each_lru(lru)
		stat[lru] = global_page_state(NR_LRU_BASE + lru);
}

void gang_show_state(struct gang_set *gs) { }

#endif /* CONFIG_MEMORY_GANGS */

#ifdef CONFIG_MEMORY_GANGS_MIGRATION
static struct workqueue_struct **gangs_migration_wq;

unsigned int gangs_migration_max_isolate = 50;
unsigned int gangs_migration_min_batch = 100;
unsigned int gangs_migration_max_batch = 12800;
unsigned int gangs_migration_interval = 500;

static unsigned long isolate_gang_pages(struct gang *gang, enum lru_list lru,
		unsigned long nr_to_scan, struct list_head *pagelist)
{
	struct lruvec *lruvec = &gang->lruvec;
	struct list_head *lru_list = &lruvec->lru_list[lru];
	unsigned long nr_isolated = 0;
	struct page *page, *next;
	int restart;
	LIST_HEAD(busy_pages);

again:
	restart = 0;
	spin_lock_irq(&lruvec->lru_lock);
	list_for_each_entry_safe_reverse(page, next, lru_list, lru) {

		if (is_lru_milestone(lruvec, &page->lru)) {
			remove_lru_milestone(lruvec, lru);
			continue;
		}

		if (nr_to_scan-- == 0)
			break;

		if (!get_page_unless_zero(page)) {
			list_move(&page->lru, &busy_pages);
			continue;
		}

		if (unlikely(PageTransHuge(page))) {
			spin_unlock_irq(&lruvec->lru_lock);
			split_huge_page(page);
			put_page(page);
			restart = 1;
			spin_lock_irq(&lruvec->lru_lock);
			break;
		}

		ClearPageLRU(page);
		del_page_from_lru_list(lruvec, page, lru);
		inc_zone_page_state(page, NR_ISOLATED_ANON +
				    page_is_file_cache(page));

		nr_isolated++;
		list_add(&page->lru, pagelist);
	}
	list_splice_init(&busy_pages, lru_list);
	spin_unlock_irq(&lruvec->lru_lock);

	if (restart)
		goto again;

	return nr_isolated;
}

static struct page *gangs_migration_new_page(struct page *page,
					     unsigned long private, int **x)
{
	struct gangs_migration_work *w = (void *)private;
	gfp_t gfp_mask = GFP_HIGHUSER_MOVABLE |
			__GFP_NORETRY | __GFP_OTHER_NODE;

	return __alloc_pages_nodemask(gfp_mask, 0,
			node_zonelist(w->preferred_node, gfp_mask),
			&w->dest_nodes);
}

static int __migrate_gangs(struct gang_set *gs, struct gangs_migration_work *w)
{
	struct zoneref *z;
	struct zone *zone;
	enum lru_list lru;
	nodemask_t cur_nodemask;
	LIST_HEAD(pagelist);
	unsigned long nr_to_scan, nr_isolated, nr_moved;
	int rc;

	nr_moved = 0;
	cur_nodemask = nodemask_of_node(w->cur_node);
	for_each_zone_zonelist_nodemask(zone, z,
			node_zonelist(w->cur_node, GFP_KERNEL),
			MAX_NR_ZONES - 1, &cur_nodemask) {
		struct gang *gang = mem_zone_gang(gs, zone);
		unsigned long left = gang->nr_migratepages;

		if (!left)
			continue;
		while (nr_moved < w->batch && left) {
			int empty = 1;

			for_each_lru(lru) {
				if (!gang->lruvec.nr_pages[lru])
					continue;
				empty = 0;

				nr_to_scan = min_t(unsigned long,
					left, gangs_migration_max_isolate);
				left -= nr_to_scan;

				nr_isolated = isolate_gang_pages(gang, lru,
						nr_to_scan, &pagelist);
				if (!nr_isolated)
					continue;
				rc = migrate_pages(&pagelist,
						gangs_migration_new_page,
						(unsigned long)w, false,
						MIGRATE_ASYNC);
				if (rc < 0)
					return -1;
				nr_moved += nr_isolated - rc;
			}
			if (empty)
				left = 0;
		}
		gang->nr_migratepages = left;
		if (nr_moved >= w->batch)
			return 1;
	}
	return 0;
}

static void migrate_gangs(struct work_struct *work)
{
	struct delayed_work *dwork;
	struct gangs_migration_work *w;
	struct gang_set *gs;
	const struct cpumask *cpumask;
	int cpu, rc;
	unsigned long delay = 0;

	dwork = to_delayed_work(work);
	w = container_of(dwork, struct gangs_migration_work, dwork);
	gs = container_of(w, struct gang_set, migration_work);

	if (!node_online(w->cur_node)) {
		node_clear(w->cur_node, w->src_nodes);
		set_gang_limits(gs, NULL, NULL);
		goto next;
	}

	cpu = task_cpu(current);
	cpumask = cpumask_of_node(w->cur_node);
	if (!cpumask_test_cpu(cpu, cpumask))
		set_cpus_allowed_ptr(current, cpumask);

	rc = __migrate_gangs(gs, w);
	if (rc < 0) {
		nodes_clear(w->src_nodes);
		set_gang_limits(gs, NULL, NULL);
		return;
	}
	if (!rc) {
		node_clear(w->cur_node, w->src_nodes);
		set_gang_limits(gs, NULL, NULL);
	}
next:
	if (!nodes_empty(w->src_nodes)) {
		w->cur_node = next_node(w->cur_node, w->src_nodes);
		if (w->cur_node >= MAX_NUMNODES) {
			w->cur_node = first_node(w->src_nodes);
			w->batch *= 2;
			if (w->batch > gangs_migration_max_batch)
				w->batch = gangs_migration_max_batch;
			delay = msecs_to_jiffies(gangs_migration_interval);
		}
		w->preferred_node = next_node(w->preferred_node, w->dest_nodes);
		if (w->preferred_node >= MAX_NUMNODES)
			w->preferred_node = first_node(w->dest_nodes);
		queue_delayed_work(gangs_migration_wq[w->cur_node],
				   dwork, delay);
	}
}

static void __schedule_gangs_migration(struct gang_set *gs,
				       struct gangs_migration_work *w)
{
	struct zoneref *z;
	struct zone *zone;
	enum lru_list lru;

	for_each_zone_zonelist_nodemask(zone, z,
			node_zonelist(numa_node_id(), GFP_KERNEL),
			MAX_NR_ZONES - 1, &w->src_nodes) {
		struct gang *gang = mem_zone_gang(gs, zone);

		gang->nr_migratepages = 0;
		for_each_lru(lru)
			gang->nr_migratepages += gang->lruvec.nr_pages[lru];
		gang->nr_migratepages *= NR_LRU_LISTS;
	}
	w->cur_node = first_node(w->src_nodes);
	w->preferred_node = first_node(w->dest_nodes);
	w->batch = gangs_migration_min_batch;
	queue_delayed_work(gangs_migration_wq[w->cur_node], &w->dwork, 0);
}

/* Returns 0 if migration was already scheduled, non-zero otherwise */
int schedule_gangs_migration(struct gang_set *gs,
		const nodemask_t *src_nodes, const nodemask_t *dest_nodes)
{
	struct gangs_migration_work *w = &gs->migration_work;
	nodemask_t tmp;
	int ret = 0;

	mutex_lock(&w->lock);
	if (!nodes_empty(w->src_nodes))
		goto out;
	cancel_delayed_work_sync(&w->dwork);
	nodes_and(w->dest_nodes, *dest_nodes, node_online_map);
	if (!nodes_empty(w->dest_nodes)) {
		nodes_andnot(tmp, *src_nodes, *dest_nodes);
		nodes_and(w->src_nodes, tmp, node_online_map);
		if (!nodes_empty(w->src_nodes)) {
			set_gang_limits(gs, NULL, NULL);
			__schedule_gangs_migration(gs, w);
		}
	}
	ret = 1;
out:
	mutex_unlock(&w->lock);
	return ret;
}

/* Returns 0 if migration was not pending, non-zero otherwise. */
int cancel_gangs_migration(struct gang_set *gs)
{
	struct gangs_migration_work *w = &gs->migration_work;
	int ret = 0;

	mutex_lock(&w->lock);
	if (nodes_empty(w->src_nodes))
		goto out;
	cancel_delayed_work_sync(&w->dwork);
	nodes_clear(w->src_nodes);
	set_gang_limits(gs, NULL, NULL);
	ret = 1;
out:
	mutex_unlock(&w->lock);
	return ret;
}

int gangs_migration_pending(struct gang_set *gs, nodemask_t *pending)
{
	struct gangs_migration_work *w = &gs->migration_work;
	int ret;

	mutex_lock(&w->lock);
	if (pending)
		*pending = w->src_nodes;
	ret = !nodes_empty(w->src_nodes);
	mutex_unlock(&w->lock);
	return ret;
}

static void init_gangs_migration_work(struct gang_set *gs)
{
	struct gangs_migration_work *w = &gs->migration_work;

	INIT_DELAYED_WORK(&w->dwork, migrate_gangs);
	nodes_clear(w->src_nodes);
	mutex_init(&w->lock);
}

static __init int init_gangs_migration_wq(void)
{
	int node;
	char name[32];

	init_gangs_migration_work(&init_gang_set);

	if (nr_node_ids == 1)
		return 0;

	gangs_migration_wq = kcalloc(nr_node_ids,
			sizeof(struct workqueue_struct *), GFP_KERNEL);
	BUG_ON(!gangs_migration_wq);

	for_each_node(node) {
		snprintf(name, sizeof(name), "gsmigration/%d", node);
		gangs_migration_wq[node] = create_singlethread_workqueue(name);
		BUG_ON(!gangs_migration_wq[node]);
	}

	return 0;
}
late_initcall(init_gangs_migration_wq);

static int gangs_migration_batch_constraints(void)
{
	if (gangs_migration_min_batch <= 0 ||
	    gangs_migration_min_batch > gangs_migration_max_batch)
		return -EINVAL;
	return 0;
}

int gangs_migration_batch_sysctl_handler(struct ctl_table *table,
		int write, void __user *buffer, size_t *lenp, loff_t *ppos)
{
	static DEFINE_MUTEX(lock);
	unsigned int old_min, old_max;
	int err;

	mutex_lock(&lock);

	old_min = gangs_migration_min_batch;
	old_max = gangs_migration_max_batch;

	err = proc_dointvec(table, write, buffer, lenp, ppos);
	if (err || !write)
		goto out;

	err = gangs_migration_batch_constraints();
	if (err) {
		gangs_migration_min_batch = old_min;
		gangs_migration_max_batch = old_max;
	}

out:
	mutex_unlock(&lock);
	return err;
}
#endif /* CONFIG_MEMORY_GANGS_MIGRATION */

struct gang *init_gang_array[MAX_NUMNODES];

#ifndef CONFIG_BC_RSS_ACCOUNTING
struct gang_set init_gang_set = {
#ifdef CONFIG_MEMORY_GANGS
	.gangs = init_gang_array,
#endif
};
#endif
