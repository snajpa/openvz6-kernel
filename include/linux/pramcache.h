#ifndef _LINUX_PRAMCACHE_H
#define _LINUX_PRAMCACHE_H

struct super_block;

#ifdef CONFIG_PRAMCACHE
extern void pramcache_load_page_cache(struct super_block *sb);
extern void pramcache_load_bdev_cache(struct super_block *sb);
extern void pramcache_save_page_cache(struct super_block *sb, int nosync);
extern void pramcache_save_bdev_cache(struct super_block *sb);
#else
static inline void pramcache_load_page_cache(struct super_block *sb) { }
static inline void pramcache_load_bdev_cache(struct super_block *sb) { }
static inline void pramcache_save_page_cache(struct super_block *sb,
					     int nosync) { }
static inline void pramcache_save_bdev_cache(struct super_block *sb) { }
#endif /* CONFIG_PRAMCACHE */

#endif /* _LINUX_PRAMCACHE_H */
