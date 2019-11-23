#include <linux/quotaops.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/nfs_fs.h>
#include "internal.h"

#define NFSDBG_FACILITY NFSDBG_QUOTA

static void nfs_dq_free_blocks(struct inode *inode, blkcnt_t blocks);
void nfs_dq_release_preallocated_blocks(struct inode *inode, blkcnt_t blocks);
static blkcnt_t nfs_dq_get_reserved_blocks(struct inode *inode);
static void nfs_dq_update_shrink(struct inode *inode, blkcnt_t shrink,
				 blkcnt_t reserved_blocks);
static void nfs_dq_add_to_prealloc_list(struct inode *inode);
static void nfs_dq_remove_from_prealloc_list(struct inode *inode);
static int nfs_dq_try_to_release_quota(struct inode *inode);

blkcnt_t nfs_quota_reserve_barrier = 1024;

inline void nfs_dq_init(struct inode *inode)
{
	vfs_dq_init(inode);
}

struct inode * nfs_dq_reserve_inode(struct inode * dir)
{
	struct inode * inode;
	struct nfs_inode *nfsi;

	if (!sb_any_quota_active(dir->i_sb))
		return NULL;

	/* Second, allocate "quota" inode and initialize required fields */
	inode = new_inode(dir->i_sb);
	if (inode == NULL)
		return ERR_PTR(-ENOMEM);

	nfsi = NFS_I(inode);
	nfsi->access_cache = RB_ROOT;
#ifdef CONFIG_NFS_FSCACHE
	nfsi->fscache = NULL;
#endif
	inode->i_uid = current_fsuid();
	inode->i_gid = current_fsgid();
	/* Is this optional? */
	if (dir->i_mode & S_ISGID)
		inode->i_gid = dir->i_gid;

	if (vfs_dq_alloc_inode(inode) == NO_QUOTA)
		goto err_drop;

	dprintk("NFS: DQ reserve inode (ino: %ld)\n", inode->i_ino);

	return inode;

err_drop:
	vfs_dq_drop(inode);
	inode->i_flags |= S_NOQUOTA;
	iput(inode);
	return ERR_PTR(-EDQUOT);
}

void nfs_dq_release_inode(struct inode *inode)
{
	if (inode) {
		dprintk("NFS: DQ release inode (ino: %ld)\n", inode->i_ino);
		vfs_dq_free_inode(inode);
		vfs_dq_drop(inode);
		inode->i_flags |= S_NOQUOTA;
		iput(inode);
	}
}

void nfs_dq_swap_inode(struct inode * inode, struct inode * dummy)
{
	if (dummy) {
		dprintk("NFS: DQ swap inodes (ino: %ld to ino: %ld)\n",
						dummy->i_ino, inode->i_ino);
		DQUOT_SWAP(inode, dummy);
	}
}

int nfs_dq_transfer_inode(struct inode *inode, struct iattr *attr)
{
	if (((attr->ia_valid & ATTR_UID) && attr->ia_uid != inode->i_uid) ||
	    ((attr->ia_valid & ATTR_GID) && attr->ia_gid != inode->i_gid)) {
		dprintk("NFS: DQ transfer inode (ino: %ld)\n", inode->i_ino);
		return vfs_dq_transfer(inode, attr) ? -EDQUOT : 0;
	}
	return 0;
}

static int nfs_dq_drop_inode(struct inode *inode)
{
	if (is_bad_inode(inode))
		return 0;

	if (!sb_any_quota_active(inode->i_sb))
		return 0;

	mutex_lock(&NFS_I(inode)->quota_sync);
	nfs_dq_update_shrink(inode, inode->i_blocks,
			     nfs_dq_get_reserved_blocks(inode));
	mutex_unlock(&NFS_I(inode)->quota_sync);
	nfs_dq_remove_from_prealloc_list(inode);
	dprintk("NFS: DQ drop inode (ino: %ld)\n", inode->i_ino);
	return 1;
}

/* Added only to hook vfs_dq_free_inode. --ANK */
void nfs_dq_delete_inode(struct inode * inode)
{
	if (!nfs_dq_drop_inode(inode))
		return;

	dprintk("NFS: DQ delete inode (ino: %ld)\n", inode->i_ino);
	vfs_dq_free_inode(inode);
	vfs_dq_drop(inode);
	inode->i_flags |= S_NOQUOTA;
}

static qsize_t *nfs_get_reserved_space(struct inode *inode)
{
	return &NFS_I(inode)->i_reserved_quota;
}

static const struct dquot_operations nfs_dquot_operations = {
	.reserve_space		= dquot_reserve_space,
	.get_reserved_space	= nfs_get_reserved_space,
	.drop			= nfs_dq_drop_inode,
};

inline void nfs_dq_init_sb(struct super_block *sb)
{
	sb->dq_op = &nfs_dquot_operations;
}

inline void nfs_dq_init_nfs_inode(struct nfs_inode *nfsi)
{
	nfsi->i_reserved_quota = 0;
	INIT_LIST_HEAD(&nfsi->prealloc);
	mutex_init(&nfsi->quota_sync);
}

/*
 * Calculate the number of pages used.
 */
static inline blkcnt_t nfs_calc_page_size(u64 tsize)
{
	blkcnt_t used = (tsize + (PAGE_SIZE - 1)) >> PAGE_SHIFT;
	return (used > ULONG_MAX) ? ULONG_MAX : used;
}

static int nfs_dq_get_new_blocks(struct inode *inode, loff_t pos, size_t size)
{
	int new_pages;

	/*
	 * Quota will be preallocated by page size chunks. We always prealloc
	 * at least 1 page size chunk. If write request crosses page size
	 * borders, we will prealloc more pages accordingly. 
	 */

	/* 
	 * Here we have a complicated situation. 
	 * We know nothing about current file configuration. I.e. it could be a
	 * sparse file. And in this case we can't recognize, was quota already
	 * allocated for current writing blocks or not. Thus we have to
	 * prealloc and claim quota for any write operation. Surplus
	 * preallocated quota will be later freed after inode revalidation.
	 * This approach garantees, that we will not cross quota border, but,
	 * on other hand, could come to quota border during preallocation very
	 * fast in case of many small sizes write requests.
	 *
	 * TODO: we can use RB tree per NFS inode to store already "quoted"
	 * blocks. This will allow us to avoid excess blocks preallocation.
	 * During syncing inode blocks we can shink this tree to root.
	 */
	new_pages = nfs_calc_page_size(pos + size) - nfs_calc_page_size(pos);
	if (!new_pages)
		new_pages = 1;
	return nfs_calc_block_size(inode, new_pages << PAGE_SHIFT);
}

long nfs_dq_prealloc_space(struct inode *inode, loff_t pos, size_t size)
{
	blkcnt_t new_blocks;

	if (!sb_any_quota_active(inode->i_sb))
		return 0;

	new_blocks = nfs_dq_get_new_blocks(inode, pos, size);
	if (new_blocks == 0)
		return 0;

	dprintk("NFS: DQ prealloc %ld blocks (ino: %ld)\n", new_blocks,
							inode->i_ino);

	while (vfs_dq_reserve_block(inode, new_blocks)) {
		if (nfs_dq_try_to_release_quota(inode) < 0)
			return -EDQUOT;
	}

	nfs_dq_add_to_prealloc_list(inode);

	return new_blocks;
}

void nfs_dq_release_preallocated_blocks(struct inode *inode, blkcnt_t blocks)
{
	if (!sb_any_quota_active(inode->i_sb))
		return;

	if (blocks == 0)
		return;

	dprintk("NFS: DQ release %ld reservation blocks (ino: %ld)\n",
		       			blocks, inode->i_ino);
	vfs_dq_release_reservation_block(inode, blocks);
}

static void nfs_dq_claim_preallocated_blocks(struct inode *inode, long new_blocks)
{
	if (new_blocks == 0)
		return;

	dprintk("NFS: DQ claim %ld reserved blocks (ino: %ld)\n",
					new_blocks, inode->i_ino);
	if (vfs_dq_claim_block(inode, new_blocks))
		BUG();
}

static void nfs_dq_free_blocks(struct inode *inode, blkcnt_t blocks)
{
	if (blocks == 0)
		return;

	dprintk("NFS: DQ free %ld blocks (ino: %ld)\n",
			blocks, inode->i_ino);
	vfs_dq_free_block_nodirty(inode, blocks);
}

static qsize_t nfs_inode_rsv_space(struct nfs_inode *nfs_inode)
{
	return inode_get_rsv_space(&nfs_inode->vfs_inode);
}

static blkcnt_t nfs_dq_get_reserved_blocks(struct inode *inode)
{
	qsize_t reserve;

	reserve = inode_get_rsv_space(inode);
	return nfs_calc_block_size(inode, reserve);
}

static void nfs_dq_update_grow(struct inode *inode, blkcnt_t grow,
			       nfs_dq_sync_flags_t flag,
			       blkcnt_t reserved_blocks)
{
	dprintk("NFS: DQ grow %ld blocks (ino: %ld, reserved blocks: %ld)\n",
			grow, inode->i_ino, reserved_blocks);

	if (reserved_blocks >= grow) {
		nfs_dq_claim_preallocated_blocks(inode, grow);
		if (flag == NFS_DQ_SYNC_PREALLOC_RELEASE)
			nfs_dq_release_preallocated_blocks(inode, reserved_blocks - grow);
	} else {
		blkcnt_t blocks_to_alloc = grow - reserved_blocks;

		nfs_dq_claim_preallocated_blocks(inode, reserved_blocks);

		if (blocks_to_alloc) {
			dprintk("NFS: DQ alloc %ld blocks (ino: %ld)\n",
							blocks_to_alloc,
							inode->i_ino);
			vfs_dq_alloc_block_nofail(inode, blocks_to_alloc);
		}
	}
}

static void nfs_dq_update_shrink(struct inode *inode, blkcnt_t shrink,
				 blkcnt_t reserved_blocks)
{
	if (!reserved_blocks && !shrink)
		return;

	dprintk("NFS: DQ shrink %ld blocks (ino: %ld, reserved blocks: %ld)\n",
			shrink, inode->i_ino, reserved_blocks);

	nfs_dq_release_preallocated_blocks(inode, reserved_blocks);
	nfs_dq_free_blocks(inode, shrink);
}

void nfs_dq_sync_blocks(struct inode *inode, struct nfs_fattr *fattr,
				nfs_dq_sync_flags_t flag)
{
	blkcnt_t blocks, reserved_blocks;

	if (!sb_any_quota_active(inode->i_sb))
		return;

	if ((fattr->valid & NFS_ATTR_FATTR) == 0)
		return;

	nfs_dq_remove_from_prealloc_list(inode);

	blocks = inode->i_blocks;

	if (fattr->valid & NFS_ATTR_FATTR_SPACE_USED)
		blocks = nfs_calc_block_size(inode, fattr->du.nfs3.used);
	if (fattr->valid & NFS_ATTR_FATTR_BLOCKS_USED)
		blocks = fattr->du.nfs2.blocks;

	mutex_lock(&NFS_I(inode)->quota_sync);
	reserved_blocks = nfs_dq_get_reserved_blocks(inode);
	if (blocks > inode->i_blocks)
		nfs_dq_update_grow(inode, blocks - inode->i_blocks,
				   flag, reserved_blocks);
	else
		nfs_dq_update_shrink(inode, inode->i_blocks - blocks,
				     reserved_blocks);
	mutex_unlock(&NFS_I(inode)->quota_sync);
}

inline void nfs_dq_init_prealloc_list(struct nfs_server *server)
{
	INIT_LIST_HEAD(&server->prealloc_list);
	spin_lock_init(&server->prealloc_lock);
}

static void nfs_dq_add_to_prealloc_list(struct inode *inode)
{
	struct nfs_server *server = NFS_SERVER(inode);
	struct nfs_inode *nfsi = NFS_I(inode);

	/*
	 * We omit adding of inodes, which preallocated less than
	 * "nfs_quota_reserve_barrier" blocks, to "quota fat inodes" list.
	 */
	if (nfs_dq_get_reserved_blocks(inode) < nfs_quota_reserve_barrier)
		return;

	spin_lock(&server->prealloc_lock);
	if (list_empty(&nfsi->prealloc)) {
		dprintk("NFS: DQ add inode %ld to prealloc list\n", inode->i_ino);
		list_add(&nfsi->prealloc, &server->prealloc_list);
	}
	spin_unlock(&server->prealloc_lock);
}

static void nfs_dq_remove_from_prealloc_list(struct inode *inode)
{
	struct nfs_server *server = NFS_SERVER(inode);
	struct nfs_inode *nfsi = NFS_I(inode);

	if (!list_empty(&nfsi->prealloc)) {
		dprintk("NFS: DQ remove inode %ld from prealloc list\n", inode->i_ino);
		spin_lock(&server->prealloc_lock);
		list_del_init(&nfsi->prealloc);
		spin_unlock(&server->prealloc_lock);
	}
}

static int nfs_dq_try_to_release_quota(struct inode *inode)
{
	struct nfs_server *server = NFS_SERVER(inode);
	struct nfs_inode *fattest = NFS_I(inode);
	struct nfs_inode *tmp;
	struct inode *rev_inode;

	dprintk("NFS: DQ trying to release quota (ino: %ld)\n", inode->i_ino);

	spin_lock(&server->prealloc_lock);
	list_for_each_entry(tmp, &server->prealloc_list, prealloc) {
		if (nfs_inode_rsv_space(tmp) > nfs_inode_rsv_space(fattest))
			fattest = tmp;
	}
	spin_unlock(&server->prealloc_lock);
	
	rev_inode = &fattest->vfs_inode;
	dprintk("NFS: DQ fattest inode: %ld (preallocated blocks: %ld)\n",
		rev_inode->i_ino,
		nfs_calc_block_size(rev_inode, nfs_inode_rsv_space(fattest)));

	if (!nfs_inode_rsv_space(fattest))
		return -EDQUOT;
		
	/*
	 * We found inode with maximum non-zero preallocated space. Or at least
	 * current inode has some preallocated space.
	 * Now we will try to refresh it.
	 * We hope, that after this inode refresh we will release some quota
	 * space.
	 */
	dprintk("NFS: DQ trying to revalidate quota (ino: %ld)\n",
						rev_inode->i_ino);
	return __nfs_revalidate_inode(server, rev_inode);
}
