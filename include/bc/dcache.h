#ifndef __UB_DCACHE_H__
#define __UB_DCACHE_H__

#include <bc/decl.h>

extern unsigned int ub_dcache_thres_ratio;
extern unsigned int ub_dcache_time_thresh;
extern unsigned int ub_dcache_lru_popup;
extern unsigned int ub_dcache_no_vzfs_cache;

UB_DECLARE_FUNC(int, ub_dcache_charge(struct user_beancounter *ub, int name_len))
UB_DECLARE_VOID_FUNC(ub_dcache_uncharge(struct user_beancounter *ub, int name_len))
UB_DECLARE_VOID_FUNC(ub_dcache_set_owner(struct dentry *d, struct user_beancounter *ub))
UB_DECLARE_VOID_FUNC(ub_dcache_change_owner(struct dentry *dentry, struct user_beancounter *ub))
UB_DECLARE_VOID_FUNC(ub_dcache_clear_owner(struct dentry *dentry))
UB_DECLARE_VOID_FUNC(ub_dcache_unuse(struct user_beancounter *ub))
UB_DECLARE_FUNC(int, ub_dcache_reclaim(struct user_beancounter *ub, unsigned long, unsigned long))
UB_DECLARE_FUNC(int, ub_dcache_shrink(struct user_beancounter *ub, unsigned long size, gfp_t gfp_mask))
UB_DECLARE_FUNC(unsigned long, ub_dcache_get_size(struct dentry *dentry))

extern unsigned int dcache_update_time(void);

bool ub_dcache_shrinkable(gfp_t gfp_mask);
struct user_beancounter *ub_dcache_next(void);
void ub_dcache_insert(struct user_beancounter *ub, unsigned int time);
void ub_update_threshold(void);

#endif
