#include <linux/buffer_head.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/genhd.h>
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/mmgang.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/pram.h>
#include <linux/pramcache.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/sysctl.h>
#include <linux/sysfs.h>
#include <linux/types.h>
#include <linux/writeback.h> /* for inode_lock, oddly enough.. */

static int pramcache_feature_nosync;

#define PRAMCACHE_PAGE_CACHE	"page_cache"
#define PRAMCACHE_BDEV_CACHE	"bdev_cache"

#define PRAMCACHE_MAGIC		0x70667363
#define PRAMCACHE_VERSION	3

#define PRAMCACHE_FHANDLE_MAX	256

struct pramcache_header {
	__u32 magic;
	__u32 version;
	__u32 mnt_count;
};

struct page_state {
	__u64 index;

	__u32 flags;
#define PAGE_STATE_UPTODATE	0x01
#define PAGE_STATE_DIRTY	0x02

	__u32 buffers_uptodate;
#define MAX_PAGE_BUFFERS	32
};

static int pramcache_enabled;	/* if set, page & bdev caches
				   will be saved to pram on umount */

int pramcache_ploop_nosync = 1;

/*
 * pram_write() and pram_push_page() may not fail if pram_prealloc()
 * succeeded. The macros gracefully eliminate redundant retval checks.
 */
#define pramcache_write(s, b, c) do {				\
	if (unlikely(pram_write((s), (b), (c)) != (c)))		\
		BUG();						\
} while (0)
#define pramcache_push_page(s, p) do {				\
	if (unlikely(pram_push_page((s), (p), NULL) != 0))	\
		BUG();						\
} while (0)

static void pramcache_msg(struct super_block *sb, const char *prefix,
			  const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	printk("%sPRAMCACHE (%s): ", prefix, sb->s_id);
	vprintk(fmt, ap);
	printk("\n");
	va_end(ap);
}

static char *pramcache_pram_basename(struct super_block *sb,
				     char *buf, size_t size)
{
	snprintf(buf, size, "pramcache.%pU.", sb->s_uuid);
	return buf;
}

/*
 * Meta and data streams must be opened and closed atomically, otherwise we can
 * get a data storage without corresponding meta storage, which will lead to
 * open_streams() failures.
 */
static DEFINE_MUTEX(streams_mutex);

static int open_streams(struct super_block *sb, const char *name, int mode,
			struct pram_stream *meta_stream,
			struct pram_stream *data_stream)
{
	char *buf;
	size_t basename_len;
	int err = -ENOMEM;

	buf = (char *)__get_free_page(GFP_TEMPORARY);
	if (!buf)
		goto out;

	pramcache_pram_basename(sb, buf, PAGE_SIZE);
	strlcat(buf, name, PAGE_SIZE);
	basename_len = strlen(buf);

	mutex_lock(&streams_mutex);

	/*
	 * Since loss of several pages is not critical when saving
	 * page cache, we will be using GFP_NOWAIT & pram_prealloc()
	 */

	strlcat(buf, ".meta", PAGE_SIZE);
	err = __pram_open(buf, mode, GFP_NOWAIT | __GFP_HIGHMEM, meta_stream);
	if (err)
		goto out_unlock;

	buf[basename_len] = '\0';
	strlcat(buf, ".data", PAGE_SIZE);
	err = __pram_open(buf, mode, GFP_NOWAIT | __GFP_HIGHMEM, data_stream);
	if (err)
		goto out_close_meta;

	mutex_unlock(&streams_mutex);

	free_page((unsigned long)buf);
	return 0;

out_close_meta:
	pram_close(meta_stream, -1);
out_unlock:
	mutex_unlock(&streams_mutex);
	free_page((unsigned long)buf);
out:
	return err;
}

static void close_streams(struct pram_stream *meta_stream,
			  struct pram_stream *data_stream, int err)
{
	mutex_lock(&streams_mutex);
	pram_close(meta_stream, err);
	pram_close(data_stream, err);
	mutex_unlock(&streams_mutex);
}

/* returns non-zero if page should be saved */
static int get_page_state(struct page *page, struct page_state *state)
{
	struct buffer_head *head, *bh;
	int i;

	if (PageWriteback(page))
		return 0;

	state->index = page->index;
	state->flags = 0;
	if (PageDirty(page))
		state->flags |= PAGE_STATE_DIRTY;
	if (PageUptodate(page)) {
		state->flags |= PAGE_STATE_UPTODATE;
		state->buffers_uptodate = ~0;
		return 1;
	}

	if (!page_has_buffers(page))
		return 0;

	i = 0;
	state->buffers_uptodate = 0;
	head = bh = page_buffers(page);
	do {
		if (WARN_ON_ONCE(i >= MAX_PAGE_BUFFERS))
			return 0;
		if (buffer_uptodate(bh))
			state->buffers_uptodate |= 1 << i;
		bh = bh->b_this_page;
		i++;
	} while (bh != head);

	return !!state->buffers_uptodate;
}

static void make_page_uptodate(struct page *page, struct page_state *state)
{
	struct buffer_head *head, *bh;
	int i;

	WARN_ON_ONCE(PageDirty(page));
	WARN_ON_ONCE(page_has_private(page));

	if (state->flags & PAGE_STATE_UPTODATE) {
		SetPageUptodate(page);
		return;
	}

	ClearPageUptodate(page);
	create_empty_buffers(page,
		page->mapping->host->i_sb->s_blocksize, 0);

	i = 0;
	bh = head = page_buffers(page);
	do {
		if (WARN_ON_ONCE(i >= MAX_PAGE_BUFFERS))
			break;
		if (state->buffers_uptodate & (1 << i))
			set_buffer_uptodate(bh);
		bh = bh->b_this_page;
		i++;
	} while (bh != head);
}

/* returns non-zero if page was saved */
static int save_page(struct page *page,
		     struct page_state *state,
		     struct pram_stream *meta_stream,
		     struct pram_stream *data_stream)
{
	/* if prealloc fails, silently skip the page */
	if (pram_prealloc2(GFP_NOWAIT | __GFP_HIGHMEM,
			   sizeof(*state), PAGE_SIZE) == 0) {
		pramcache_write(meta_stream, state, sizeof(*state));
		pramcache_push_page(data_stream, page);
		pram_prealloc_end();
		return 1;
	}
	return 0;
}

static struct page *load_page(struct page_state *state,
			      struct pram_stream *meta_stream,
			      struct pram_stream *data_stream)
{
	struct page *page;
	ssize_t ret;

	ret = pram_read(meta_stream, state, sizeof(*state));
	if (!ret)
		return NULL;
	if (ret != sizeof(*state))
		return ERR_PTR(-EIO);

	/* since we do not save outdated pages, empty uptodate mask
	 * can be used as the 'end of mapping' mark */
	if (!state->buffers_uptodate)
		return NULL;

	page = pram_pop_page(data_stream);
	if (IS_ERR_OR_NULL(page))
		return ERR_PTR(-EIO);

	return page;
}

static int write_page(struct address_space *mapping, loff_t filesize,
		      struct page *page, pgoff_t index)
{
	loff_t pos = index << PAGE_SHIFT;
	unsigned len = PAGE_SIZE;
	struct page *page2;
	void *fsdata;
	int status;

	WARN_ON_ONCE(pos >= filesize);
	if (pos + len > filesize)
		len = filesize - pos;

	status = pagecache_write_begin(NULL, mapping,
				       pos, len, 0, &page2, &fsdata);
	if (status)
		return status;

	if (unlikely(page2 != page))
		copy_highpage(page2, page);

	status = pagecache_write_end(NULL, mapping,
				     pos, len, len, page2, fsdata);
	if (unlikely(status < 0))
		return status;

	return 0;
}

static int insert_page(struct address_space *mapping, loff_t filesize,
		       struct page *page, struct page_state *state)
{
	int err;

	if (!pram_page_dirty(page)) {
		err = add_to_page_cache_lru(page, mapping,
					    state->index, GFP_KERNEL);
	} else {
		/* page already accounted and in lru */
		__set_page_locked(page);
		err = add_to_page_cache_nogang(page, mapping,
					       state->index, GFP_KERNEL);
		if (err)
			__clear_page_locked(page);
	}
	if (!err) {
		make_page_uptodate(page, state);
		unlock_page(page);
	} else if (err != -EEXIST)
		goto out;

	err = 0;
	if (state->flags & PAGE_STATE_DIRTY)
		err = write_page(mapping, filesize, page, state->index);
out:
	put_page(page);
	return err;
}

static void evict_page(struct page *page)
{
	if (page_has_private(page)) {
		do_invalidatepage(page, 0);
		if (page_has_private(page))
			return;
	}
	cancel_dirty_page(page, PAGE_CACHE_SIZE);
	remove_from_page_cache(page);
	page_cache_release(page);
}

static void save_invalidate_page(struct page *page, int nosync,
				 struct pram_stream *meta_stream,
				 struct pram_stream *data_stream)
{
	int evict = 1;
	struct page_state state;

	if (!get_page_state(page, &state))
		goto invalidate;

	if (state.flags & PAGE_STATE_DIRTY) {
		/* for the sake of simplicity evict only
		 * those dirty pages that are fully uptodate
		 * if nosync */
		if (!nosync || !(state.flags & PAGE_STATE_UPTODATE)) {
			/* treat the page as clean because
			 * it will be synced soon */
			state.flags &= ~PAGE_STATE_DIRTY;
			evict = 0;
		}
	}

	if (!save_page(page, &state, meta_stream, data_stream))
		goto invalidate;

	if (evict)
		evict_page(page);
	return;

invalidate:
	invalidate_inode_page(page);
}

static void save_invalidate_mapping_pages(struct address_space *mapping,
					  int nosync,
					  struct pram_stream *meta_stream,
					  struct pram_stream *data_stream)
{
	struct pagevec pvec;
	pgoff_t next = 0;
	int i;

	pagevec_init(&pvec, 0);
	while (pagevec_lookup(&pvec, mapping, next, PAGEVEC_SIZE)) {
		for (i = 0; i < pagevec_count(&pvec); i++) {
			struct page *page = pvec.pages[i];
			pgoff_t index;

			lock_page(page);
			if (unlikely(page->mapping != mapping)) {
				unlock_page(page);
				continue;
			}

			index = page->index;
			if (index > next)
				next = index;
			next++;

			save_invalidate_page(page, nosync,
					     meta_stream, data_stream);
			unlock_page(page);
		}
		pagevec_release(&pvec);
		cond_resched();
	}
}

static long load_mapping_pages(struct address_space *mapping,
			       loff_t filesize,
			       struct pram_stream *meta_stream,
			       struct pram_stream *data_stream)
{
	struct page_state state;
	struct page *page;
	long loaded = 0;
	int err;

next:
	page = load_page(&state, meta_stream, data_stream);
	if (!page)
		return loaded;
	if (IS_ERR(page))
		return PTR_ERR(page);

	err = insert_page(mapping, filesize, page, &state);
	if (err)
		return err;

	loaded++;
	goto next;
}

static void save_invalidate_inode(struct inode *inode,
				  int *first, int nosync,
				  void *buf, size_t bufsize,
				  struct pram_stream *meta_stream,
				  struct pram_stream *data_stream)
{
	const struct page_state eof = { 0, };
	struct dentry *dentry;
	__u64 filesize;
	__u32 len;

	if (hlist_unhashed(&inode->i_hash))
		goto invalidate;

	len = vfs_inode_fhandle(inode, buf, bufsize);
	if (len < 0)
		goto invalidate;

	dentry = vfs_fhandle_to_dentry(inode->i_sb, buf);
	if (IS_ERR(dentry))
		goto invalidate;
	dput(dentry);

	if (pram_prealloc(GFP_NOWAIT | __GFP_HIGHMEM,
			  sizeof(eof) + sizeof(filesize) + len) != 0)
		goto invalidate;

	/* if we have already saved inodes, write the 'end of mapping'
	 * mark (see load_page()) */
	if (!*first)
		pramcache_write(meta_stream, &eof, sizeof(eof));

	pramcache_write(meta_stream, buf, len);

	/* since filesystems usually write file size to disk on page
	 * writeback and we may avoid writeback by emitting dirty pages,
	 * save file size to pram */
	filesize = i_size_read(inode);
	pramcache_write(meta_stream, &filesize, sizeof(filesize));

	pram_prealloc_end();

	save_invalidate_mapping_pages(&inode->i_data, nosync,
				      meta_stream, data_stream);
	*first = 0;
	return;

invalidate:
	invalidate_mapping_pages(&inode->i_data, 0, ~0UL);
}

static long load_inode(struct super_block *sb,
		       void *buf, size_t bufsize,
		       struct pram_stream *meta_stream,
		       struct pram_stream *data_stream)
{
	struct file_handle *handle;
	struct dentry *dentry;
	__u64 filesize;
	ssize_t ret;
	int err;

	if (bufsize < sizeof(*handle))
		return -ENOBUFS;

	handle = buf;
	ret = pram_read(meta_stream, handle, sizeof(*handle));
	if (!ret)
		return -ENODATA;

	err = -EIO;
	if (ret != sizeof(*handle))
		goto out;
	if (handle->handle_bytes > bufsize - sizeof(*handle))
		goto out;

	if (pram_read(meta_stream, (char *)buf + sizeof(*handle),
		      handle->handle_bytes) != handle->handle_bytes)
		goto out;

	dentry = vfs_fhandle_to_dentry(sb, handle);
	err = PTR_ERR(dentry);
	if (IS_ERR(dentry))
		goto out;

	if (pram_read(meta_stream, &filesize,
		      sizeof(filesize)) != sizeof(filesize))
		goto out_dput;

	err = load_mapping_pages(&dentry->d_inode->i_data, filesize,
				 meta_stream, data_stream);
out_dput:
	dput_nocache(dentry, 1);
out:
	return err;
}

static int save_header(struct super_block *sb,
		       struct pram_stream *stream)
{
	struct pramcache_header hdr;
	int err;

	hdr.magic = PRAMCACHE_MAGIC;
	hdr.version = PRAMCACHE_VERSION;
	hdr.mnt_count = sb->s_mnt_count;

	err = pram_prealloc(GFP_KERNEL | __GFP_HIGHMEM, sizeof(hdr));
	if (!err) {
		pramcache_write(stream, &hdr, sizeof(hdr));
		pram_prealloc_end();
	}
	return err;
}

static int check_header(struct super_block *sb,
			struct pram_stream *stream)
{
	struct pramcache_header hdr;

	if (pram_read(stream, &hdr, sizeof(hdr)) != sizeof(hdr))
		return -EIO;

	if (hdr.magic != PRAMCACHE_MAGIC) {
		pramcache_msg(sb, KERN_ERR, "wrong magic");
		return -EINVAL;
	}

	if (hdr.version != PRAMCACHE_VERSION) {
		pramcache_msg(sb, KERN_ERR, "bad version (%d)",
			      (int)hdr.version);
		return -EINVAL;
	}

	if (!(sb->s_flags & MS_RDONLY))
		hdr.mnt_count++;

	if (sb->s_mnt_count != hdr.mnt_count) {
		pramcache_msg(sb, KERN_ERR,
			      "mnt count should be %d, but was %d",
			      (int)hdr.mnt_count, sb->s_mnt_count);
		return -EINVAL;
	}

	return 0;
}

static void pramcache_prune(struct super_block *sb, const char *name)
{
	struct pram_stream meta_stream, data_stream;
	int err;

retry:
	/* first, destroy the cache */
	err = open_streams(sb, name, PRAM_READ, &meta_stream, &data_stream);
	if (!err)
		close_streams(&meta_stream, &data_stream, 0);
	if (err == -ENOENT)
		err = 0;
	if (err)
		goto out;

	/* then, create an empty one */
	err = open_streams(sb, name, PRAM_WRITE, &meta_stream, &data_stream);
	if (!err)
		close_streams(&meta_stream, &data_stream, 0);
out:
	if (err == -EBUSY || err == -EEXIST) {
		/* someone is writing to the cache, let them finish */
		schedule_timeout_uninterruptible(1);
		goto retry;
	}
	if (err) {
		pramcache_msg(sb, KERN_ERR,
			      "prune failed (%d), "
			      "data corruption possible!", err);
	}
}

static void save_invalidate_page_cache(struct super_block *sb, int nosync)
{
	struct pram_stream meta_stream, data_stream;
	struct inode *inode, *old_inode = NULL;
	int first = 1;
	void *buf;
	int err;

	err = open_streams(sb, PRAMCACHE_PAGE_CACHE, PRAM_WRITE,
			   &meta_stream, &data_stream);
	if (err)
		goto out;

	err = save_header(sb, &meta_stream);
	if (err)
		goto out_close_streams;

	err = -ENOMEM;
	buf = kmalloc(PRAMCACHE_FHANDLE_MAX, GFP_KERNEL);
	if (!buf)
		goto out_close_streams;

	spin_lock(&inode_lock);
	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		if (inode->i_state & (I_FREEING|I_CLEAR|I_WILL_FREE|I_NEW))
			continue;
		if (!inode->i_nlink)
			continue;
		if (!inode->i_data.nrpages)
			continue;
		__iget(inode);
		spin_unlock(&inode_lock);

		/* We hold a reference to 'inode' so it couldn't have been
		 * removed from s_inodes list while we dropped the inode_lock.
		 * We cannot iput the inode now as we can be holding the last
		 * reference and we cannot iput it under inode_lock. So we
		 * keep the reference and iput it later. */
		iput(old_inode);
		old_inode = inode;

		save_invalidate_inode(inode, &first, nosync,
				      buf, PRAMCACHE_FHANDLE_MAX,
				      &meta_stream, &data_stream);

		spin_lock(&inode_lock);
	}
	spin_unlock(&inode_lock);
	iput(old_inode);
	err = 0;

	kfree(buf);
out_close_streams:
	close_streams(&meta_stream, &data_stream, err);
out:
	if (err)
		pramcache_msg(sb, KERN_ERR,
			      "Failed to save page cache: %d", err);
	if (err == -EEXIST) {
		pramcache_msg(sb, KERN_ERR,
			      "Filesystem UUID collision detected, "
			      "run `tune2fs -U' to update UUID");
		pramcache_prune(sb, PRAMCACHE_PAGE_CACHE);
	}
}

void pramcache_load_page_cache(struct super_block *sb)
{
	struct pram_stream meta_stream, data_stream;
	long ret, loaded = 0;
	void *buf;
	int err;

	BUG_ON(!sb->s_bdev);

	if (sb->s_flags & MS_RDONLY)
		/* will load on remount rw, since dirty pages
		 * can't be populated right now */
		return;

	err = open_streams(sb, PRAMCACHE_PAGE_CACHE, PRAM_READ,
			   &meta_stream, &data_stream);
	if (err)
		goto out;

	err = check_header(sb, &meta_stream);
	if (err)
		goto out_close_streams;

	err = -ENOMEM;
	buf = kmalloc(PRAMCACHE_FHANDLE_MAX, GFP_KERNEL);
	if (!buf)
		goto out_close_streams;

next:
	ret = load_inode(sb, buf, PRAMCACHE_FHANDLE_MAX,
			 &meta_stream, &data_stream);
	if (ret < 0) {
		err = ret;
		if (err == -ENODATA)
			err = 0;
		goto out_free_buf;
	}
	loaded += ret;
	goto next;

out_free_buf:
	kfree(buf);
out_close_streams:
	close_streams(&meta_stream, &data_stream, 0);
out:
	if (!err)
		pramcache_msg(sb, KERN_INFO,
			      "loaded page cache (%ld pages)", loaded);
	else if (err != -ENOENT)
		pramcache_msg(sb, KERN_ERR,
			      "Failed to load page cache: %d", err);
}
EXPORT_SYMBOL(pramcache_load_page_cache);

static void save_invalidate_bdev_cache(struct super_block *sb)
{
	struct pram_stream meta_stream, data_stream;
	int err;

	err = open_streams(sb, PRAMCACHE_BDEV_CACHE, PRAM_WRITE,
			   &meta_stream, &data_stream);
	if (err)
		goto out;

	err = save_header(sb, &meta_stream);
	if (err)
		goto out_close_streams;

	save_invalidate_mapping_pages(sb->s_bdev->bd_inode->i_mapping, 0,
				      &meta_stream, &data_stream);
out_close_streams:
	close_streams(&meta_stream, &data_stream, err);
out:
	if (err)
		pramcache_msg(sb, KERN_ERR,
			      "Failed to save bdev cache: %d", err);
	if (err == -EEXIST) {
		pramcache_msg(sb, KERN_ERR,
			      "Filesystem UUID collision detected, "
			      "run `tune2fs -U' to update UUID");
		pramcache_prune(sb, PRAMCACHE_BDEV_CACHE);
	}
}

void pramcache_load_bdev_cache(struct super_block *sb)
{
	struct pram_stream meta_stream, data_stream;
	long loaded = 0;
	int err;

	BUG_ON(!sb->s_bdev);

	err = open_streams(sb, PRAMCACHE_BDEV_CACHE, PRAM_READ,
			   &meta_stream, &data_stream);
	if (err)
		goto out;

	err = check_header(sb, &meta_stream);
	if (err)
		goto out_close_streams;

	loaded = load_mapping_pages(sb->s_bdev->bd_inode->i_mapping, 0,
				    &meta_stream, &data_stream);
	if (loaded < 0)
		err = loaded;

out_close_streams:
	close_streams(&meta_stream, &data_stream, 0);
out:
	if (!err)
		pramcache_msg(sb, KERN_INFO,
			      "loaded bdev cache (%ld pages)", loaded);
	else if (err != -ENOENT)
		pramcache_msg(sb, KERN_ERR,
			      "Failed to load bdev cache: %d", err);
}
EXPORT_SYMBOL(pramcache_load_bdev_cache);

void pramcache_save_page_cache(struct super_block *sb, int nosync)
{
	BUG_ON(!sb->s_bdev);

	if (pramcache_ploop_nosync &&
	    !strncmp(sb->s_bdev->bd_disk->disk_name, "ploop", 5))
		nosync = 1;

	if (pramcache_feature_nosync < CONFIG_PRAMCACHE_FEATURE_NOSYNC)
		nosync = 0;

	/*
	 * To avoid collisions with not yet loaded page cache (it is loaded on
	 * mount/remount rw - see pramcache_load_page_cache()), do not save
	 * page cache of fs mounted ro.
	 */
	if (pramcache_enabled && !(sb->s_flags & MS_RDONLY))
		save_invalidate_page_cache(sb, nosync);
}
EXPORT_SYMBOL(pramcache_save_page_cache);

void pramcache_save_bdev_cache(struct super_block *sb)
{
	BUG_ON(!sb->s_bdev);

	if (pramcache_enabled)
		save_invalidate_bdev_cache(sb);
}
EXPORT_SYMBOL(pramcache_save_bdev_cache);

static ssize_t pramcache_show(struct kobject *kobj,
			      struct kobj_attribute *attr,
			      char *buf)
{
	return sprintf(buf, "%d\n", pramcache_enabled);
}

static ssize_t pramcache_store(struct kobject *kobj,
			       struct kobj_attribute *attr,
			       const char *buf, size_t count)
{
	unsigned long val;

	if (strict_strtoul(buf, 10, &val) != 0)
		return -EINVAL;
	val = !!val;
	if (pramcache_enabled != val) {
		pramcache_enabled = val;
		printk(KERN_INFO "PRAMCACHE: %s\n",
		       pramcache_enabled ? "enabled" : "disabled");
	}
	return count;
}

static struct kobj_attribute pramcache_attr =
	__ATTR(pramcache, 0644, pramcache_show, pramcache_store);

static struct attribute *pramcache_attrs[] = {
	&pramcache_attr.attr,
	NULL,
};

static struct attribute_group pramcache_attr_group = {
	.attrs = pramcache_attrs,
};

#ifdef CONFIG_SYSCTL
ctl_table pramcache_table[] = {
	{
		.procname	= "nosync",
		.data		= &pramcache_feature_nosync,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{ .ctl_name = 0 }
};
#endif /* CONFIG_SYSCTL */

static int __init pramcache_init(void)
{
	sysfs_update_group(kernel_kobj, &pramcache_attr_group);
	return 0;
}
module_init(pramcache_init);
