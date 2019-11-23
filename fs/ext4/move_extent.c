/*
 * Copyright (c) 2008,2009 NEC Software Tohoku, Ltd.
 * Written by Takashi Sato <t-sato@yk.jp.nec.com>
 *            Akira Fujita <a-fujita@rs.jp.nec.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2.1 of the GNU Lesser General Public License
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/fs.h>
#include <linux/quotaops.h>
#include "ext4_jbd2.h"
#include "ext4_extents.h"
#include "ext4.h"

/**
 * get_ext_path - Find an extent path for designated logical block number.
 *
 * @inode:	an inode which is searched
 * @lblock:	logical block number to find an extent path
 * @path:	pointer to an extent path pointer (for output)
 *
 * ext4_ext_find_extent wrapper. Return 0 on success, or a negative error value
 * on failure.
 */
static inline int
get_ext_path(struct inode *inode, ext4_lblk_t lblock,
		struct ext4_ext_path **orig_path)
{
	int ret = 0;
	struct ext4_ext_path *path;

	path = ext4_ext_find_extent(inode, lblock, *orig_path);
	if (IS_ERR(path))
		ret = PTR_ERR(path);
	else if (path[ext_depth(inode)].p_ext == NULL)
		ret = -ENODATA;
	else
		*orig_path = path;

	return ret;
}

static void
double_down_write_sem(struct rw_semaphore *first, struct rw_semaphore *second)
{
	if (first > second)
		swap(first, second);
	down_write(first);
	down_write_nested(second, SINGLE_DEPTH_NESTING);
}

/**
 * mext_check_coverage - Check that all extents in range has the same type
 *
 * @inode:		inode in question
 * @from:		block offset of inode
 * @count:		block count to be checked
 * @unwritten:		extents expected to be unwritten
 * @err:		pointer to save error value
 *
 * Return 1 if all extents in range has expected type, and zero otherwise.
 */
static int
mext_check_coverage(struct inode *inode, ext4_lblk_t from, ext4_lblk_t count,
		    int unwritten, int *err)
{
	struct ext4_ext_path *path = NULL;
	struct ext4_extent *ext;
	int ret = 0;
	ext4_lblk_t last = from + count;
	while (from < last) {
		*err = get_ext_path(inode, from, &path);
		if (*err)
			goto out;
		ext = path[ext_depth(inode)].p_ext;
		if (unwritten != ext4_ext_is_uninitialized(ext))
			goto out;
		from += ext4_ext_get_actual_len(ext);
		ext4_ext_drop_refs(path);
	}
	ret = 1;
out:
	if (path) {
		ext4_ext_drop_refs(path);
		kfree(path);
	}
	return ret;
}

/**
 * mext_replace_branches - Replace original extents with new extents
 *
 * @handle:		journal handle
 * @orig_inode:		original inode
 * @donor_inode:	donor inode
 * @from:		block offset of orig_inode
 * @count:		block count to be replaced
 * @err:		pointer to save return value
 *
 * Replace original inode extents and donor inode extents page by page.
 * We implement this replacement in the following three steps:
 * 1. Save the block information of original and donor inodes into
 *    dummy extents.
 * 2. Change the block information of original inode to point at the
 *    donor inode blocks.
 * 3. Change the block information of donor inode to point at the saved
 *    original inode blocks in the dummy extents.
 *
 * Return replaced block count.
 */

/**
 * mext_page_double_lock - Grab and lock pages on both @inode1 and @inode2
 *
 * @inode1:	the inode structure
 * @inode2:	the inode structure
 * @index:	page index
 * @page:	result page vector
 *
 * Grab two locked pages for inode's by inode order
 */
static int
mext_page_double_lock(struct inode *inode1, struct inode *inode2,
		      pgoff_t index1, pgoff_t index2, struct page *page[2])
{
	struct address_space *mapping[2];
	unsigned fl = AOP_FLAG_NOFS;

	BUG_ON(!inode1 || !inode2);
	if (inode1 < inode2) {
		mapping[0] = inode1->i_mapping;
		mapping[1] = inode2->i_mapping;
	} else {
		pgoff_t tmp = index1;
		index1 = index2;
		index2 = tmp;
		mapping[0] = inode2->i_mapping;
		mapping[1] = inode1->i_mapping;
	}

	page[0] = grab_cache_page_write_begin(mapping[0], index1, fl);
	if (!page[0])
		return -ENOMEM;

	page[1] = grab_cache_page_write_begin(mapping[1], index2, fl);
	if (!page[1]) {
		unlock_page(page[0]);
		page_cache_release(page[0]);
		return -ENOMEM;
	}
	/*
	 * grab_cache_page_write_begin() may not wait on page's writeback if
	 * BDI not demand that. But it is reasonable to be very conservative
	 * here and explicitly wait on page's writeback
	 */
	wait_on_page_writeback(page[0]);
	wait_on_page_writeback(page[1]);
	if (inode1 > inode2) {
		struct page *tmp;
		tmp = page[0];
		page[0] = page[1];
		page[1] = tmp;
	}
	return 0;
}

/* Force page buffers uptodate w/o dropping page's lock */
static int
mext_page_mkuptodate(struct page *page, unsigned from, unsigned to)
{
	struct inode *inode = page->mapping->host;
	sector_t block;
	struct buffer_head *bh, *head, *arr[MAX_BUF_PER_PAGE];
	unsigned int blocksize, block_start, block_end;
	int i, err,  nr = 0, partial = 0;
	BUG_ON(!PageLocked(page));
	BUG_ON(PageWriteback(page));

	if (PageUptodate(page))
		return 0;

	blocksize = 1 << inode->i_blkbits;
	if (!page_has_buffers(page))
		create_empty_buffers(page, blocksize, 0);

	head = page_buffers(page);
	block = (sector_t)page->index << (PAGE_CACHE_SHIFT - inode->i_blkbits);
	for (bh = head, block_start = 0; bh != head || !block_start;
	     block++, block_start = block_end, bh = bh->b_this_page) {
		block_end = block_start + blocksize;
		if (block_end <= from || block_start >= to) {
			if (!buffer_uptodate(bh))
				partial = 1;
			continue;
		}
		if (buffer_uptodate(bh))
			continue;
		if (!buffer_mapped(bh)) {
			err = ext4_get_block(inode, block, bh, 0);
			if (err) {
				SetPageError(page);
				return err;
			}
			if (!buffer_mapped(bh)) {
				zero_user(page, block_start, blocksize);
				set_buffer_uptodate(bh);
				continue;
			}
		}
		BUG_ON(nr >= MAX_BUF_PER_PAGE);
		arr[nr++] = bh;
	}
	/* No io required */
	if (!nr)
		goto out;

	for (i = 0; i < nr; i++) {
		bh = arr[i];
		if (!bh_uptodate_or_lock(bh)) {
			err = bh_submit_read(bh);
			if (err)
				return err;
		}
	}
out:
	if (!partial)
		SetPageUptodate(page);
	return 0;
}

/**
 * move_extent_per_page - Move extent data per page
 *
 * @o_filp:			file structure of original file
 * @donor_inode:		donor inode
 * @orig_page_offset:		page index on original file
 * @data_offset_in_page:	block index where data swapping starts
 * @block_len_in_page:		the number of blocks to be swapped
 * @unwritten:			orig extent is unwritten or not
 * @err:			pointer to save return value
 *
 * Save the data in original inode blocks and replace original inode extents
 * with donor inode extents by calling mext_replace_branches().
 * Finally, write out the saved data in new original inode blocks. Return
 * replaced block count.
 */
static int
move_extent_per_page(struct file *o_filp, struct inode *donor_inode,
		     pgoff_t orig_page_offset, pgoff_t donor_page_offset,
		     int data_offset_in_page,
		     int block_len_in_page, int unwritten, int *err)
{
	struct inode *orig_inode = o_filp->f_dentry->d_inode;
	struct page *pagep[2] = {NULL, NULL};
	handle_t *handle;
	ext4_lblk_t orig_blk_offset, donor_blk_offset;
	unsigned long blocksize = orig_inode->i_sb->s_blocksize;
	unsigned int w_flags = 0;
	unsigned int tmp_data_size, data_size, replaced_size;
	int err2, jblocks, retries = 0;
	int replaced_count = 0;
	int from = data_offset_in_page << orig_inode->i_blkbits;
	int blocks_per_page = PAGE_CACHE_SIZE >> orig_inode->i_blkbits;

	/*
	 * It needs twice the amount of ordinary journal buffers because
	 * inode and donor_inode may change each different metadata blocks.
	 */
again:
	*err = 0;
	jblocks = ext4_writepage_trans_blocks(orig_inode) * 2;
	handle = ext4_journal_start(orig_inode, jblocks);
	if (IS_ERR(handle)) {
		*err = PTR_ERR(handle);
		return 0;
	}

	if (segment_eq(get_fs(), KERNEL_DS))
		w_flags |= AOP_FLAG_UNINTERRUPTIBLE;

	orig_blk_offset = orig_page_offset * blocks_per_page +
		data_offset_in_page;

	donor_blk_offset = donor_page_offset * blocks_per_page +
		data_offset_in_page;

	/* Calculate data_size */
	if ((orig_blk_offset + block_len_in_page - 1) ==
	    ((orig_inode->i_size - 1) >> orig_inode->i_blkbits)) {
		/* Replace the last block */
		tmp_data_size = orig_inode->i_size & (blocksize - 1);
		/*
		 * If data_size equal zero, it shows data_size is multiples of
		 * blocksize. So we set appropriate value.
		 */
		if (tmp_data_size == 0)
			tmp_data_size = blocksize;

		data_size = tmp_data_size +
			((block_len_in_page - 1) << orig_inode->i_blkbits);
	} else
		data_size = block_len_in_page << orig_inode->i_blkbits;

	replaced_size = data_size;

	*err = mext_page_double_lock(orig_inode, donor_inode, orig_page_offset,
				     donor_page_offset, pagep);
	if (unlikely(*err < 0))
		goto stop_journal;
	/*
	 * If orig extent was unwritten it can become initialized
	 * at any time after i_data_sem was dropped, in order to
	 * serialize with delalloc we have recheck extent while we
	 * hold page's lock, if it is still the case data copy is not
	 * necessary, just swap data blocks between orig and donor.
	 */
	if (unwritten) {
		double_down_write_sem(&EXT4_I(orig_inode)->i_data_sem,
				      &EXT4_I(donor_inode)->i_data_sem);
		/* If any of extents in range became initialized we have to
		 * fallback to data copying */
		unwritten = mext_check_coverage(orig_inode, orig_blk_offset,
						block_len_in_page, 1, err);
		if (*err)
			goto drop_data_sem;

		unwritten &= mext_check_coverage(donor_inode, donor_blk_offset,
						 block_len_in_page, 1, err);
		if (*err)
			goto drop_data_sem;

		if (!unwritten) {
			up_write(&EXT4_I(orig_inode)->i_data_sem);
			up_write(&EXT4_I(donor_inode)->i_data_sem);
			goto data_copy;
		}
		if ((page_has_private(pagep[0]) &&
		     !try_to_release_page(pagep[0], 0)) ||
		    (page_has_private(pagep[1]) &&
		     !try_to_release_page(pagep[1], 0))) {
			*err = -EBUSY;
			goto drop_data_sem;
		}
		replaced_count = ext4_swap_extents(handle, orig_inode,
						   donor_inode, orig_blk_offset,
						   donor_blk_offset,
						   block_len_in_page, 1, err);
	drop_data_sem:
		up_write(&EXT4_I(orig_inode)->i_data_sem);
		up_write(&EXT4_I(donor_inode)->i_data_sem);
		goto unlock_pages;
	}
data_copy:
	*err = mext_page_mkuptodate(pagep[0], from, from + replaced_size);
	if (*err)
		goto unlock_pages;

	/* At this point all buffers in range are uptodate, old mapping layout
	 * is no longer required, try to drop it now. */
	if ((page_has_private(pagep[0]) && !try_to_release_page(pagep[0], 0)) ||
	    (page_has_private(pagep[1]) && !try_to_release_page(pagep[1], 0))) {
		*err = -EBUSY;
		goto unlock_pages;
	}
	double_down_write_sem(&EXT4_I(orig_inode)->i_data_sem,
			      &EXT4_I(donor_inode)->i_data_sem);
	replaced_count = ext4_swap_extents(handle, orig_inode, donor_inode,
					       orig_blk_offset, donor_blk_offset,
					   block_len_in_page, 1, err);
	up_write(&EXT4_I(orig_inode)->i_data_sem);
	up_write(&EXT4_I(donor_inode)->i_data_sem);

	if (*err) {
		if (replaced_count) {
			block_len_in_page = replaced_count;
			replaced_size =
				block_len_in_page << orig_inode->i_blkbits;
		} else
			goto unlock_pages;
	}
	/* Perform all necessary steps similar write_begin()/write_end()
	 * but keeping in mind that i_size will not change */
/* 	*err = a_ops->write_begin(o_filp, mapping, offs, data_size, w_flags, */
/* -				 &page, &fsdata); */

	*err = __block_prepare_write(orig_inode, pagep[0], from, replaced_size,
				     ext4_get_block);
	if (!*err)
		*err = block_commit_write(pagep[0], from, from + replaced_size);

	if (unlikely(*err < 0))
		goto repair_branches;

	/* Even in case of data=writeback it is reasonable to pin
	 * inode to transaction, to prevent unexpected data loss */
	*err = ext4_jbd2_file_inode(handle, orig_inode);

unlock_pages:
	unlock_page(pagep[0]);
	page_cache_release(pagep[0]);
	unlock_page(pagep[1]);
	page_cache_release(pagep[1]);
stop_journal:
	ext4_journal_stop(handle);
	/* Buffer was busy because probably is pinned to journal transaction,
	 * force transaction commit may help to free it. */
	if (*err == -EBUSY && ext4_should_retry_alloc(orig_inode->i_sb,
						      &retries))
		goto again;
	return replaced_count;

repair_branches:
	/*
	 * This should never ever happen!
	 * Extents are swapped already, but we are not able to copy data.
	 * Try to swap extents to it's original places
	 */
	double_down_write_sem(&EXT4_I(orig_inode)->i_data_sem,
			      &EXT4_I(donor_inode)->i_data_sem);
	replaced_count = ext4_swap_extents(handle, donor_inode, orig_inode,
					       orig_blk_offset, donor_blk_offset,
					   block_len_in_page, 0, &err2);
	up_write(&EXT4_I(orig_inode)->i_data_sem);
	up_write(&EXT4_I(donor_inode)->i_data_sem);

	if (replaced_count != block_len_in_page) {
		EXT4_ERROR_INODE(orig_inode, "Unable to copy data block %u,"
				 " data will be lost.", orig_blk_offset);
		*err = -EIO;
	}
	replaced_count = 0;
	goto unlock_pages;
}

/**
 * mext_check_arguments - Check whether move extent can be done
 *
 * @orig_inode:		original inode
 * @donor_inode:	donor inode
 * @orig_start:		logical start offset in block for orig
 * @donor_start:	logical start offset in block for donor
 * @len:		the number of blocks to be moved
 *
 * Check the arguments of ext4_move_extents() whether the files can be
 * exchanged with each other.
 * Return 0 on success, or a negative error value on failure.
 */
static int
mext_check_arguments(struct inode *orig_inode,
		     struct inode *donor_inode, __u64 orig_start,
		     __u64 donor_start, __u64 *len)
{
	__u64 orig_eof, donor_eof;
	unsigned int blkbits = orig_inode->i_blkbits;
	unsigned int blocksize = 1 << blkbits;

	orig_eof = (i_size_read(orig_inode) + blocksize - 1) >> blkbits;
	donor_eof = (i_size_read(donor_inode) + blocksize - 1) >> blkbits;


	if (donor_inode->i_mode & (S_ISUID|S_ISGID)) {
		ext4_debug("ext4 move extent: suid or sgid is set"
			   " to donor file [ino:orig %lu, donor %lu]\n",
			   orig_inode->i_ino, donor_inode->i_ino);
		return -EINVAL;
	}

	if (IS_IMMUTABLE(donor_inode) || IS_APPEND(donor_inode))
		return -EPERM;

	/* Ext4 move extent does not support swapfile */
	if (IS_SWAPFILE(orig_inode) || IS_SWAPFILE(donor_inode)) {
		ext4_debug("ext4 move extent: The argument files should "
			"not be swapfile [ino:orig %lu, donor %lu]\n",
			orig_inode->i_ino, donor_inode->i_ino);
		return -EBUSY;
	}

	/* Ext4 move extent supports only extent based file */
	if (!(ext4_test_inode_flag(orig_inode, EXT4_INODE_EXTENTS))) {
		ext4_debug("ext4 move extent: orig file is not extents "
			"based file [ino:orig %lu]\n", orig_inode->i_ino);
		return -EOPNOTSUPP;
	} else if (!(ext4_test_inode_flag(donor_inode, EXT4_INODE_EXTENTS))) {
		ext4_debug("ext4 move extent: donor file is not extents "
			"based file [ino:donor %lu]\n", donor_inode->i_ino);
		return -EOPNOTSUPP;
	}

	if ((!orig_inode->i_size) || (!donor_inode->i_size)) {
		ext4_debug("ext4 move extent: File size is 0 byte\n");
		return -EINVAL;
	}

	/* Start offset should be same */
	if ((orig_start & ~(PAGE_MASK >> orig_inode->i_blkbits)) !=
	    (donor_start & ~(PAGE_MASK >> orig_inode->i_blkbits))) {
		ext4_debug("ext4 move extent: orig and donor's start "
			"offset are not alligned [ino:orig %lu, donor %lu]\n",
			orig_inode->i_ino, donor_inode->i_ino);
		return -EINVAL;
	}

	if ((orig_start >= EXT_MAX_BLOCKS) ||
	    (donor_start >= EXT_MAX_BLOCKS) ||
	    (*len > EXT_MAX_BLOCKS) ||
	    (donor_start + *len >= EXT_MAX_BLOCKS) ||
	    (orig_start + *len >= EXT_MAX_BLOCKS))  {
		ext4_debug("ext4 move extent: Can't handle over [%u] blocks "
			"[ino:orig %lu, donor %lu]\n", EXT_MAX_BLOCKS,
			orig_inode->i_ino, donor_inode->i_ino);
		return -EINVAL;
	}
	if (orig_eof < orig_start + *len - 1)
		*len = orig_eof - orig_start;
	if (donor_eof < donor_start + *len - 1)
		*len = donor_eof - donor_start;
	if (!*len) {
		ext4_debug("ext4 move extent: len should not be 0 "
			"[ino:orig %lu, donor %lu]\n", orig_inode->i_ino,
			donor_inode->i_ino);
		return -EINVAL;
	}

	return 0;
}

/**
 * mext_inode_double_lock - Lock i_mutex on both @inode1 and @inode2
 *
 * @inode1:	the inode structure
 * @inode2:	the inode structure
 *
 * Lock two inodes' i_mutex by i_ino order.
  */
static void
mext_inode_double_lock(struct inode *inode1, struct inode *inode2)
{
	BUG_ON(inode1 == NULL || inode2 == NULL);

	if (inode1 == inode2) {
		mutex_lock(&inode1->i_mutex);
		return;
	}

	if (inode1 < inode2) {
		mutex_lock_nested(&inode1->i_mutex, I_MUTEX_PARENT);
		mutex_lock_nested(&inode2->i_mutex, I_MUTEX_CHILD);
	} else {
		mutex_lock_nested(&inode2->i_mutex, I_MUTEX_PARENT);
		mutex_lock_nested(&inode1->i_mutex, I_MUTEX_CHILD);
	}
}

/**
 * mext_inode_double_unlock - Release i_mutex on both @inode1 and @inode2
 *
 * @inode1:     the inode that is released first
 * @inode2:     the inode that is released second
 */

static void
mext_inode_double_unlock(struct inode *inode1, struct inode *inode2)
{
	BUG_ON(inode1 == NULL || inode2 == NULL);

	mutex_unlock(&inode1->i_mutex);
	if (inode2 != inode1)
		mutex_unlock(&inode2->i_mutex);
}

/**
 * ext4_move_extents - Exchange the specified range of a file
 *
 * @o_filp:		file structure of the original file
 * @d_filp:		file structure of the donor file
 * @orig_start:		start offset in block for orig
 * @donor_start:	start offset in block for donor
 * @len:		the number of blocks to be moved
 * @moved_len:		moved block length
 *
 * This function returns 0 and moved block length is set in moved_len
 * if succeed, otherwise returns error value.
 *
 * Note: ext4_move_extents() proceeds the following order.
 * 1:ext4_move_extents() calculates the last block number of moving extent
 *   function by the start block number (orig_start) and the number of blocks
 *   to be moved (len) specified as arguments.
 *   If the {orig, donor}_start points a hole, the extent's start offset
 *   pointed by ext_cur (current extent), holecheck_path, orig_path are set
 *   after hole behind.
 * 2:Continue step 3 to step 5, until the holecheck_path points to last_extent
 *   or the ext_cur exceeds the block_end which is last logical block number.
 * 3:To get the length of continues area, call mext_next_extent()
 *   specified with the ext_cur (initial value is holecheck_path) re-cursive,
 *   until find un-continuous extent, the start logical block number exceeds
 *   the block_end or the extent points to the last extent.
 * 4:Exchange the original inode data with donor inode data
 *   from orig_page_offset to seq_end_page.
 *   The start indexes of data are specified as arguments.
 *   That of the original inode is orig_page_offset,
 *   and the donor inode is also orig_page_offset
 *   (To easily handle blocksize != pagesize case, the offset for the
 *   donor inode is block unit).
 * 5:Update holecheck_path and orig_path to points a next proceeding extent,
 *   then returns to step 2.
 * 6:Release holecheck_path, orig_path and set the len to moved_len
 *   which shows the number of moved blocks.
 *   The moved_len is useful for the command to calculate the file offset
 *   for starting next move extent ioctl.
 * 7:Return 0 on success, or a negative error value on failure.
 */
int
ext4_move_extents(struct file *o_filp, struct file *d_filp, __u64 orig_blk,
		  __u64 donor_blk, __u64 len, __u64 *moved_len)
{
	struct inode *orig_inode = o_filp->f_dentry->d_inode;
	struct inode *donor_inode = d_filp->f_dentry->d_inode;
	struct ext4_ext_path *path = NULL;
	int blocks_per_page = PAGE_CACHE_SIZE >> orig_inode->i_blkbits;
	ext4_lblk_t o_end, o_start = orig_blk;
	ext4_lblk_t d_start = donor_blk;
	int ret;
	__u64 m_len = *moved_len;

	if (orig_inode->i_sb != donor_inode->i_sb) {
		ext4_debug("ext4 move extent: The argument files "
			"should be in same FS [ino:orig %lu, donor %lu]\n",
			orig_inode->i_ino, donor_inode->i_ino);
		return -EINVAL;
	}

	/* orig and donor should be different inodes */
	if (orig_inode == donor_inode) {
		ext4_debug("ext4 move extent: The argument files should not "
			"be same inode [ino:orig %lu, donor %lu]\n",
			orig_inode->i_ino, donor_inode->i_ino);
		return -EINVAL;
	}
	/* Regular file check */
	if (!S_ISREG(orig_inode->i_mode) || !S_ISREG(donor_inode->i_mode)) {
		ext4_debug("ext4 move extent: The argument files should be "
			"regular file [ino:orig %lu, donor %lu]\n",
			orig_inode->i_ino, donor_inode->i_ino);
		return -EINVAL;
	}
	/* TODO: This is non obvious task to swap blocks for inodes with full
	   jornaling enabled */
	if (ext4_should_journal_data(orig_inode) ||
	    ext4_should_journal_data(donor_inode)) {
		return -EINVAL;
	}
	/* Protect orig and donor inodes against a truncate */
	mext_inode_double_lock(orig_inode, donor_inode);
	/* Wait for all existing dio workers */
	ret = ext4_flush_unwritten_io(orig_inode);
	if (ret)
		goto out;
	ret = ext4_flush_unwritten_io(donor_inode);
	if (ret)
		goto out;
	double_down_write_sem(&orig_inode->i_alloc_sem,
			      &donor_inode->i_alloc_sem);
	/* Protect extent tree against block allocations via delalloc */
	double_down_write_sem(&EXT4_I(orig_inode)->i_data_sem,
			      &EXT4_I(donor_inode)->i_data_sem);
	/* Check the filesystem environment whether move_extent can be done */
	ret = mext_check_arguments(orig_inode, donor_inode, orig_blk,
				    donor_blk, &len);
	if (ret)
		goto out;
	o_end = o_start + len;

	while (o_start < o_end) {
		struct ext4_extent *ex;
		ext4_lblk_t cur_blk, next_blk;
		pgoff_t orig_page_index, donor_page_index;
		int offset_in_page;
		int unwritten, cur_len;

		ret = get_ext_path(orig_inode, o_start, &path);
		if (ret)
			goto out;
		ex = path[path->p_depth].p_ext;
		next_blk = ext4_ext_next_allocated_block(path);
		cur_blk = le32_to_cpu(ex->ee_block);
		cur_len = ext4_ext_get_actual_len(ex);
		/* Check hole before the start pos */
		if (cur_blk + cur_len - 1 < o_start) {
			if (next_blk == EXT_MAX_BLOCKS) {
				o_start = o_end;
				ret = -ENODATA;
				break;
			}
			d_start += next_blk - o_start;
			o_start = next_blk;
			goto repeat;
		/* Check hole after the start pos */
		} else if (cur_blk > o_start) {
			/* Skip hole */
			d_start += cur_blk - o_start;
			o_start = cur_blk;
			/* Extent inside requested range ?*/
			if (cur_blk >= o_end)
				break;
		} else { /* in_range(o_start, o_blk, o_len) */
			cur_len += cur_blk - o_start;
		}
		unwritten = ext4_ext_is_uninitialized(ex);
		if (o_end - o_start < cur_len)
			cur_len = o_end - o_start;

		orig_page_index = o_start >> (PAGE_CACHE_SHIFT -
					       orig_inode->i_blkbits);
		donor_page_index = d_start >> (PAGE_CACHE_SHIFT -
					       donor_inode->i_blkbits);
		offset_in_page = o_start % blocks_per_page;
		if (cur_len > blocks_per_page- offset_in_page)
			cur_len = blocks_per_page - offset_in_page;
		/*
		 * Up semaphore to avoid following problems:
		 * a. transaction deadlock among ext4_journal_start,
		 *    ->write_begin via pagefault, and jbd2_journal_commit
		 * b. racing with ->readpage, ->write_begin, and ext4_get_block
		 *    in move_extent_per_page
		 */
		up_write(&EXT4_I(orig_inode)->i_data_sem);
		up_write(&EXT4_I(donor_inode)->i_data_sem);
		/* Swap original branches with new branches */
		move_extent_per_page(o_filp, donor_inode,
				     orig_page_index, donor_page_index,
				     offset_in_page, cur_len,
				     unwritten, &ret);
		double_down_write_sem(&EXT4_I(orig_inode)->i_data_sem,
				      &EXT4_I(donor_inode)->i_data_sem);
		if (ret < 0)
			break;
		o_start += cur_len;
		d_start += cur_len;
		m_len += cur_len;
	repeat:
		if (path) {
			ext4_ext_drop_refs(path);
			kfree(path);
			path = NULL;
		}
	}
out:
	WARN_ON(m_len > len);
	if (ret == 0)
		*moved_len = m_len;

	if (path) {
		ext4_ext_drop_refs(path);
		kfree(path);
	}
	up_write(&EXT4_I(orig_inode)->i_data_sem);
	up_write(&EXT4_I(donor_inode)->i_data_sem);
	up_write(&orig_inode->i_alloc_sem);
	up_write(&donor_inode->i_alloc_sem);


	mext_inode_double_unlock(orig_inode, donor_inode);

	return ret;
}
