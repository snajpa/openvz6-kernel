/*
 *  include/bc/debug.h
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#ifndef __BC_DEBUG_H_
#define __BC_DEBUG_H_

/*
 * general debugging
 */

#define UBD_ALLOC	0x1
#define UBD_CHARGE	0x2
#define UBD_LIMIT	0x4
#define UBD_TRACE	0x8

/*
 * ub_net debugging
 */

#define UBD_NET_SOCKET	0x10
#define UBD_NET_SLEEP	0x20
#define UBD_NET_SEND	0x40
#define UBD_NET_RECV	0x80

/*
 * Main routines
 */

#define UB_DEBUG (0)
#define DEBUG_RESOURCE (0ULL)

#define ub_dbg_cond(__cond, __str, args...)				\
	do { 								\
		if ((__cond) != 0)					\
			printk(__str, ##args);				\
	} while(0)

#define ub_debug(__section, __str, args...) 				\
	ub_dbg_cond(UB_DEBUG & (__section), __str, ##args)

#define ub_debug_resource(__resource, __str, args...)			\
	ub_dbg_cond((UB_DEBUG & UBD_CHARGE) && 				\
			(DEBUG_RESOURCE & (1 << (__resource))), 	\
			__str, ##args)

#if UB_DEBUG & UBD_TRACE
#define ub_debug_trace(__cond, __b, __r)				\
		do {							\
			static DEFINE_RATELIMIT_STATE(rl, __r, __b);	\
			if ((__cond) != 0 && __ratelimit(&rl))		\
				dump_stack(); 				\
		} while(0)
#else
#define ub_debug_trace(__cond, __burst, __rate)
#endif

#ifdef CONFIG_BC_DEBUG_KMEM
#include <linux/list.h>

struct user_beancounter;
struct ub_cache_counter {
	struct list_head ulist;
	struct ub_cache_counter *next;
	struct user_beancounter *ub;
	struct kmem_cache *cachep;
	unsigned long counter;
};

extern spinlock_t cc_lock;
extern void init_cache_counters(void);
extern void ub_free_counters(struct user_beancounter *);
extern void ub_kmemcache_free(struct kmem_cache *cachep);

struct vm_struct;
#define inc_vmalloc_charged(vm, flags)	do {				\
		if (flags & __GFP_UBC)					\
			ub_percpu_add(get_exec_ub_top(),		\
				vmalloc_charged, vm->nr_pages);		\
	} while (0)
#define dec_vmalloc_charged(vm)		do {				\
		struct user_beancounter *ub;				\
		ub = page_kmem_ub(vm->pages[0]);			\
		if (ub != NULL)						\
			ub_percpu_sub(ub, vmalloc_charged,		\
					vm->nr_pages);			\
	} while (0)
#else
#define init_cache_counters()		do { } while (0)
#define inc_vmalloc_charged(vm, f)	do { } while (0)
#define dec_vmalloc_charged(vm)		do { } while (0)

#define ub_free_counters(ub)		do { } while (0)
#define ub_kmemcache_free(cachep)	do { } while (0)
#endif

#endif
