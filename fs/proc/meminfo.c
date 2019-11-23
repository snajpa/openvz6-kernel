#include <linux/fs.h>
#include <linux/hugetlb.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mmzone.h>
#include <linux/mmgang.h>
#include <linux/proc_fs.h>
#include <linux/quicklist.h>
#include <linux/seq_file.h>
#include <linux/swap.h>
#include <linux/vmstat.h>
#include <linux/virtinfo.h>
#include <asm/atomic.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include "internal.h"

void __attribute__((weak)) arch_report_meminfo(struct seq_file *m)
{
}

/*
 * RHEL6 bz1032702
 * It was backported from upstream a new entry for /proc/meminfo
 * in order to report an estimate of available memory for starting
 * applications without risking an overcommitment & swapping scenario.
 * In order to keep backward compatibility with legacy 2.6.32 layout,
 * we're making this new entry appearance conditional to explicitly
 * disabling the following sysctl by user.
 */
unsigned int sysctl_meminfo_legacy_layout __read_mostly = 1;
int meminfo_legacy_layout_sysctl_handler(ctl_table *table, int write,
			void __user *buffer, size_t *length, loff_t *ppos)
{
        return proc_dointvec(table, write, buffer, length, ppos);
}

#define K(x) ((x) << (PAGE_SHIFT - 10))

void hugetlb_meminfo_mi(struct seq_file *m, struct meminfo *mi)
{
	struct hstate *h = &default_hstate;
	unsigned long total, used, free;
	struct user_beancounter *iter;

	if (!h->nr_huge_pages)
		return;

	total = min(mi->ub->ub_parms[UB_LOCKEDPAGES].limit >> h->order,
		    h->nr_huge_pages);
	used = 0;
	for_each_beancounter_tree(iter, mi->ub)
		used += mi->ub->ub_hugetlb_pages >> h->order;
	free = min(total > used ? total - used : 0ul, h->free_huge_pages);

	seq_printf(m,
		"HugePages_Total:   %5lu\n"
		"HugePages_Free:    %5lu\n"
		"HugePages_Rsvd:    %5lu\n"
		"HugePages_Surp:    %5lu\n"
		"Hugepagesize:   %8lu kB\n",
		total, free, 0ul, 0ul, K(1ul << h->order));
}

static int meminfo_proc_show_mi(struct seq_file *m, struct meminfo *mi)
{
	seq_printf(m,
		"MemTotal:       %8lu kB\n"
		"MemFree:        %8lu kB\n"
		"Cached:         %8lu kB\n"
		"Buffers:        %8lu kB\n"
		"Active:         %8lu kB\n"
		"Inactive:       %8lu kB\n"
		"Active(anon):   %8lu kB\n"
		"Inactive(anon): %8lu kB\n"
		"Active(file):   %8lu kB\n"
		"Inactive(file): %8lu kB\n"
		"Unevictable:    %8lu kB\n"
		"Mlocked:        %8lu kB\n"
		"SwapTotal:      %8lu kB\n"
		"SwapFree:       %8lu kB\n"
		"Dirty:          %8lu kB\n"
		"Writeback:      %8lu kB\n"
		"AnonPages:      %8lu kB\n"
		"Shmem:          %8lu kB\n"
		"Slab:           %8lu kB\n"
		"SReclaimable:   %8lu kB\n"
		"SUnreclaim:     %8lu kB\n"
		,
		K(mi->si->totalram),
		K(mi->si->freeram),
		K(mi->cached),
		K(0L),
		K(mi->pages[LRU_ACTIVE_ANON]   + mi->pages[LRU_ACTIVE_FILE]),
		K(mi->pages[LRU_INACTIVE_ANON] + mi->pages[LRU_INACTIVE_FILE]),
		K(mi->pages[LRU_ACTIVE_ANON]),
		K(mi->pages[LRU_INACTIVE_ANON]),
		K(mi->pages[LRU_ACTIVE_FILE]),
		K(mi->pages[LRU_INACTIVE_FILE]),
		K(mi->pages[LRU_UNEVICTABLE]),
		K(mi->locked),
		K(mi->si->totalswap),
		K(mi->si->freeswap),
		K(mi->dirty_pages),
		K(mi->writeback_pages),
		K(mi->pages[LRU_ACTIVE_ANON] + mi->pages[LRU_INACTIVE_ANON]),
		K(mi->shmem),
		K(mi->slab_reclaimable + mi->slab_unreclaimable),
		K(mi->slab_reclaimable),
		K(mi->slab_unreclaimable));

	if (mi->meminfo_val != VE_MEMINFO_COMPLETE)
		return 0;

	seq_printf(m,
		"MemCommitted:   %8lu kB\n"
		"MemAvailable:   %8lu kB\n"
		"MemPortion:     %8lu kB\n"
		"Shadow:         %8lu kB\n"
		"Shadow(anon):   %8lu kB\n"
		"Shadow(file):   %8lu kB\n",
		K(get_ub_gs(mi->ub)->memory_committed),
		K(get_ub_gs(mi->ub)->memory_available),
		K(get_ub_gs(mi->ub)->memory_portion),
		K(mi->shadow[LRU_ACTIVE_ANON] + mi->shadow[LRU_INACTIVE_ANON] +
		  mi->shadow[LRU_ACTIVE_FILE] + mi->shadow[LRU_INACTIVE_FILE] +
		  mi->shadow[LRU_UNEVICTABLE]),
		K(mi->shadow[LRU_ACTIVE_ANON] + mi->shadow[LRU_INACTIVE_ANON]),
		K(mi->shadow[LRU_ACTIVE_FILE] + mi->shadow[LRU_INACTIVE_FILE]));

	hugetlb_meminfo_mi(m, mi);

	return 0;
}

int meminfo_proc_show_ub(struct seq_file *m, void *v,
		struct user_beancounter *ub, unsigned long meminfo_val)
{
	int ret;
	struct sysinfo i;
	struct meminfo mi;
	unsigned long committed;
	struct vmalloc_info vmi;
	long cached;
	long available;
	unsigned long pagecache;
	unsigned long wmark_low = 0;
	unsigned long pages[NR_LRU_LISTS];
	struct zone *zone;
	int lru;

	si_meminfo(&i);
	si_swapinfo(&i);

	memset(&mi, 0, sizeof(mi));
	mi.si = &i;
	mi.ub = ub;
	mi.meminfo_val = meminfo_val;

	ret = virtinfo_notifier_call(VITYPE_GENERAL, VIRTINFO_MEMINFO, &mi);
	if (ret & NOTIFY_FAIL)
		return 0;
	if (ret & NOTIFY_OK)
		return meminfo_proc_show_mi(m, &mi);

/*
 * display in kilobytes.
 */
	committed = percpu_counter_read_positive(&vm_committed_as);

	cached = global_page_state(NR_FILE_PAGES) -
			total_swapcache_pages - i.bufferram;
	if (cached < 0)
		cached = 0;

	get_vmalloc_info(&vmi);

	for (lru = LRU_BASE; lru < NR_LRU_LISTS; lru++)
		pages[lru] = global_page_state(NR_LRU_BASE + lru);

	for_each_zone(zone)
		wmark_low += zone->watermark[WMARK_LOW];

	/*
	 * Estimate the amount of memory available for userspace allocations,
	 * without causing swapping.
	 *
	 * Free memory cannot be taken below the low watermark, before the
	 * system starts swapping.
	 */
	available = i.freeram - wmark_low;

	/*
	 * Not all the page cache can be freed, otherwise the system will
	 * start swapping. Assume at least half of the page cache, or the
	 * low watermark worth of cache, needs to stay.
	 */
	pagecache = pages[LRU_ACTIVE_FILE] + pages[LRU_INACTIVE_FILE];
	pagecache -= min(pagecache / 2, wmark_low);
	available += pagecache;

	/*
	 * Part of the reclaimable swap consists of items that are in use,
	 * and cannot be freed. Cap this estimate at the low watermark.
	 */
	available += global_page_state(NR_SLAB_RECLAIMABLE) -
		     min(global_page_state(NR_SLAB_RECLAIMABLE) / 2, wmark_low);

	if (available < 0)
		available = 0;

	/*
	 * Tagged format, for easy grepping and expansion.
	 */
	seq_printf(m,
		"MemTotal:       %8lu kB\n"
		"MemFree:        %8lu kB\n"
		"Buffers:        %8lu kB\n"
		"Cached:         %8lu kB\n"
		"SwapCached:     %8lu kB\n"
#ifdef CONFIG_MEMORY_GANGS
		"MemCommitted:   %8lu kB\n"
#endif
#ifdef CONFIG_MEMORY_VSWAP
		"VirtualSwap:    %8lu kB\n"
#endif
		"Active:         %8lu kB\n"
		"Inactive:       %8lu kB\n"
		"Active(anon):   %8lu kB\n"
		"Inactive(anon): %8lu kB\n"
		"Active(file):   %8lu kB\n"
		"Inactive(file): %8lu kB\n"
		"Unevictable:    %8lu kB\n"
		"Mlocked:        %8lu kB\n"
#ifdef CONFIG_HIGHMEM
		"HighTotal:      %8lu kB\n"
		"HighFree:       %8lu kB\n"
		"LowTotal:       %8lu kB\n"
		"LowFree:        %8lu kB\n"
#endif
#ifndef CONFIG_MMU
		"MmapCopy:       %8lu kB\n"
#endif
		"SwapTotal:      %8lu kB\n"
		"SwapFree:       %8lu kB\n"
		"Dirty:          %8lu kB\n"
		"Writeback:      %8lu kB\n"
		"AnonPages:      %8lu kB\n"
		"Mapped:         %8lu kB\n"
		"Shmem:          %8lu kB\n"
		"Slab:           %8lu kB\n"
		"SReclaimable:   %8lu kB\n"
		"SUnreclaim:     %8lu kB\n"
		"KernelStack:    %8lu kB\n"
		"PageTables:     %8lu kB\n"
#ifdef CONFIG_QUICKLIST
		"Quicklists:     %8lu kB\n"
#endif
		"NFS_Unstable:   %8lu kB\n"
		"Bounce:         %8lu kB\n"
		"WritebackTmp:   %8lu kB\n"
		"CommitLimit:    %8lu kB\n"
		"Committed_AS:   %8lu kB\n"
		"VmallocTotal:   %8lu kB\n"
		"VmallocUsed:    %8lu kB\n"
		"VmallocChunk:   %8lu kB\n"
#ifdef CONFIG_MEMORY_FAILURE
		"HardwareCorrupted: %5lu kB\n"
#endif
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
		"AnonHugePages:  %8lu kB\n"
#endif
		,
		K(i.totalram),
		K(i.freeram),
		K(i.bufferram),
		K(cached),
		K(total_swapcache_pages),
#ifdef CONFIG_MEMORY_GANGS
		K(total_committed_pages),
#endif
#ifdef CONFIG_MEMORY_VSWAP
		K(global_page_state(NR_VSWAP)),
#endif
		K(pages[LRU_ACTIVE_ANON]   + pages[LRU_ACTIVE_FILE]),
		K(pages[LRU_INACTIVE_ANON] + pages[LRU_INACTIVE_FILE]),
		K(pages[LRU_ACTIVE_ANON]),
		K(pages[LRU_INACTIVE_ANON]),
		K(pages[LRU_ACTIVE_FILE]),
		K(pages[LRU_INACTIVE_FILE]),
		K(pages[LRU_UNEVICTABLE]),
		K(global_page_state(NR_MLOCK)),
#ifdef CONFIG_HIGHMEM
		K(i.totalhigh),
		K(i.freehigh),
		K(i.totalram-i.totalhigh),
		K(i.freeram-i.freehigh),
#endif
#ifndef CONFIG_MMU
		K((unsigned long) atomic_long_read(&mmap_pages_allocated)),
#endif
		K(i.totalswap),
		K(i.freeswap),
		K(global_page_state(NR_FILE_DIRTY)),
		K(global_page_state(NR_WRITEBACK)),
		K(global_page_state(NR_ANON_PAGES)
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
		  + global_page_state(NR_ANON_TRANSPARENT_HUGEPAGES) *
		  HPAGE_PMD_NR
#endif
		  ),
		K(global_page_state(NR_FILE_MAPPED)),
		K(global_page_state(NR_SHMEM)),
		K(global_page_state(NR_SLAB_RECLAIMABLE) +
				global_page_state(NR_SLAB_UNRECLAIMABLE)),
		K(global_page_state(NR_SLAB_RECLAIMABLE)),
		K(global_page_state(NR_SLAB_UNRECLAIMABLE)),
		global_page_state(NR_KERNEL_STACK) * THREAD_SIZE / 1024,
		K(global_page_state(NR_PAGETABLE)),
#ifdef CONFIG_QUICKLIST
		K(quicklist_total_size()),
#endif
		K(global_page_state(NR_UNSTABLE_NFS)),
		K(global_page_state(NR_BOUNCE)),
		K(global_page_state(NR_WRITEBACK_TEMP)),
		K(vm_commit_limit()),
		K(committed),
		(unsigned long)VMALLOC_TOTAL >> 10,
		vmi.used >> 10,
		vmi.largest_chunk >> 10
#ifdef CONFIG_MEMORY_FAILURE
		,atomic_long_read(&num_poisoned_pages) << (PAGE_SHIFT - 10)
#endif
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
		,K(global_page_state(NR_ANON_TRANSPARENT_HUGEPAGES) *
		   HPAGE_PMD_NR)
#endif
		);

	hugetlb_report_meminfo(m);

	arch_report_meminfo(m);

	/*
	 * RHEL6 bz1032702
	 * if backwards compatibility with legacy meminfo interface layout
	 * is not required, include the new entries at the end of report
	 */
	if (!sysctl_meminfo_legacy_layout)
		seq_printf(m, "MemAvailable:   %8lu kB\n", K(available));

	return 0;
#undef K
}

static int meminfo_proc_show(struct seq_file *m, void *v)
{
	return meminfo_proc_show_ub(m, v, mm_ub_top(current->mm),
			get_exec_env()->meminfo_val);
}

static int meminfo_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, meminfo_proc_show, NULL);
}

static const struct file_operations meminfo_proc_fops = {
	.open		= meminfo_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init proc_meminfo_init(void)
{
	proc_create("meminfo", 0, &glob_proc_root, &meminfo_proc_fops);
	return 0;
}
module_init(proc_meminfo_init);
