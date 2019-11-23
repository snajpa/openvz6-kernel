/*
 *
 * Copyright (C) 2005 SWsoft
 * All rights reserved.
 * 
 * Licensing governed by "linux/COPYING.SWsoft" file.
 *
 * This file contains Virtuozzo quota files as proc entry implementation.
 * It is required for std quota tools to work correctly as they are expecting
 * aquota.user and aquota.group files.
 */

#include <linux/ctype.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/sysctl.h>
#include <linux/mount.h>
#include <linux/mnt_namespace.h>
#include "../quotaio_v2.h"
#include "../quota_tree.h"
#include <asm/uaccess.h>

#include <linux/sched.h>
#include <linux/ve.h>
#include <linux/ve_proto.h>
#include <linux/vzdq_tree.h>
#include <linux/vzquota.h>

#define QUOTABLOCK_BITS 10
#define QUOTABLOCK_SIZE (1 << QUOTABLOCK_BITS)

/* ----------------------------------------------------------------------
 *
 * File read operation
 *
 * FIXME: functions in this section (as well as many functions in vzdq_ugid.c,
 * perhaps) abuse vz_quota_mutex.
 * Taking a global mutex for lengthy and user-controlled operations inside
 * VPSs is not a good idea in general.
 * In this case, the reasons for taking this mutex are completely unclear,
 * especially taking into account that the only function that has comments
 * about the necessity to be called under this mutex
 * (create_proc_quotafile) is actually called OUTSIDE it.
 *
 * --------------------------------------------------------------------- */

#define DQBLOCK_SIZE		1024
#define DQUOTBLKNUM		21U
#define DQTREE_DEPTH		4
#define TREENUM_2_BLKNUM(num)	(((num) + 1) << 1)
#define ISINDBLOCK(num)		((num)%2 != 0)
#define FIRST_DATABLK	  	2  /* first even number */
#define LAST_IND_LEVEL		(DQTREE_DEPTH - 1)
#define CONVERT_LEVEL(level)	((level) * (QUOTAID_EBITS/QUOTAID_BBITS))
#define GETLEVINDX(ind, lev)	(((ind) >> QUOTAID_BBITS*(lev)) \
					& QUOTATREE_BMASK)

#if (QUOTAID_EBITS / QUOTAID_BBITS) != (QUOTATREE_DEPTH / DQTREE_DEPTH)
#error xBITS and DQTREE_DEPTH does not correspond
#endif

#define BLOCK_NOT_FOUND	1

/* data for quota file -- one per proc entry */
struct quotatree_data {
	struct list_head	list;
	struct vz_quota_master	*qmblk;
	int			type;	/* type of the tree */
};

/* serialized by vz_quota_mutex */
static LIST_HEAD(qf_data_head);

#define V2_REV0_INITQVERSIONS {\
	0,		/* USRQUOTA */\
	0		/* GRPQUOTA */\
}

static const u_int32_t vzquota_magics[] = V2_INITQMAGICS;
static const u_int32_t vzquota_versions[] = V2_REV0_INITQVERSIONS;
static const char aquota_user[] = "aquota.user";
static const char aquota_group[] = "aquota.group";


static inline loff_t get_depoff(int depth)
{
	loff_t res = 1;
	while (depth) {
		res += (1 << ((depth - 1)*QUOTAID_EBITS + 1));
		depth--;
	}
	return res;
}

static inline loff_t get_blknum(loff_t num, int depth)
{
	loff_t res;
	res = (num << 1) + get_depoff(depth);
	return res;
}

static int get_depth(loff_t num)
{
	int i;
	for (i = 0; i < DQTREE_DEPTH; i++) {
		if (num >= get_depoff(i) && (i == DQTREE_DEPTH - 1
				|| num < get_depoff(i + 1)))
			return i;
	}
	return -1;
}

static inline loff_t get_offset(loff_t num)
{
	loff_t res, tmp;

	tmp = get_depth(num);
	if (tmp < 0)
		return -1;
	num -= get_depoff(tmp);
	BUG_ON(num < 0);
	res = num >> 1;

	return res;
}

static inline loff_t get_quot_blk_num(struct quotatree_tree *tree, int level)
{
	/* return maximum available block num */
	return tree->levels[level].freenum;
}

static inline loff_t get_block_num(struct quotatree_tree *tree)
{
	loff_t ind_blk_num, quot_blk_num, max_ind, max_quot;

	quot_blk_num = get_quot_blk_num(tree, CONVERT_LEVEL(DQTREE_DEPTH) - 1);
	max_quot = TREENUM_2_BLKNUM(quot_blk_num);
	ind_blk_num = get_quot_blk_num(tree, CONVERT_LEVEL(DQTREE_DEPTH - 1));
	max_ind = (quot_blk_num) ? get_blknum(ind_blk_num, LAST_IND_LEVEL)
		: get_blknum(ind_blk_num, 0);

	return (max_ind > max_quot) ? max_ind + 1 : max_quot + 1;
}

/*  Write quota file header */
static int read_header(void *buf, struct quotatree_tree *tree,
	struct dq_kinfo *dq_ugid_info, int type)
{
	struct v2_disk_dqheader *dqh;
	struct v2_disk_dqinfo *dq_disk_info;

	dqh = buf;
	dq_disk_info = buf + sizeof(struct v2_disk_dqheader);

	dqh->dqh_magic = vzquota_magics[type];
	dqh->dqh_version = vzquota_versions[type];

	dq_disk_info->dqi_bgrace = dq_ugid_info[type].bexpire;
	dq_disk_info->dqi_igrace = dq_ugid_info[type].iexpire;
	dq_disk_info->dqi_flags = 0;	/* no flags */
	dq_disk_info->dqi_blocks = get_block_num(tree);
	dq_disk_info->dqi_free_blk = 0;	/* first block in the file */
	dq_disk_info->dqi_free_entry = FIRST_DATABLK;

	return 0;
}

static int get_block_child(int depth, struct quotatree_node *p, u_int32_t *buf)
{
	int i, j, lev_num;

	lev_num = QUOTATREE_DEPTH/DQTREE_DEPTH - 1;
	for (i = 0; i < BLOCK_SIZE/sizeof(u_int32_t); i++) {
		struct quotatree_node *next, *parent;

		parent = p;
		next = p;
		for (j = lev_num; j >= 0; j--) {
			if (!next->blocks[GETLEVINDX(i,j)]) {
				buf[i] = 0;
				goto bad_branch;
			}
			parent = next;
			next = next->blocks[GETLEVINDX(i,j)];
		}
		buf[i] = (depth == DQTREE_DEPTH - 1) ?
			TREENUM_2_BLKNUM(parent->num)
			: get_blknum(next->num, depth + 1);

	bad_branch:
		;
	}

	return 0;
}

/*
 * Write index block to disk (or buffer)
 * @buf has length 256*sizeof(u_int32_t) bytes
 */
static int read_index_block(int num, u_int32_t *buf,
		struct quotatree_tree *tree)
{
	struct quotatree_node *p;
	u_int32_t index;
	loff_t off;
	int depth, res;

	res = BLOCK_NOT_FOUND; 
	index = 0;
	depth = get_depth(num);
	off = get_offset(num);
	if (depth < 0 || off < 0)
		return -EINVAL;

	list_for_each_entry(p, &tree->levels[CONVERT_LEVEL(depth)].usedlh,
			list) {
		if (p->num >= off)
			res = 0;
		if (p->num != off)
			continue;
		get_block_child(depth, p, buf);
		break;
	}

	return res;
}

static inline void convert_quot_format(struct v2r0_disk_dqblk *dq,
		struct vz_quota_ugid *vzq)
{
	dq->dqb_id = vzq->qugid_id;
	dq->dqb_ihardlimit = vzq->qugid_stat.ihardlimit;
	dq->dqb_isoftlimit = vzq->qugid_stat.isoftlimit;
	dq->dqb_curinodes = vzq->qugid_stat.icurrent;
	dq->dqb_bhardlimit = vzq->qugid_stat.bhardlimit / QUOTABLOCK_SIZE;
	dq->dqb_bsoftlimit = vzq->qugid_stat.bsoftlimit / QUOTABLOCK_SIZE;
	dq->dqb_curspace = vzq->qugid_stat.bcurrent;
	dq->dqb_btime = vzq->qugid_stat.btime;
	dq->dqb_itime = vzq->qugid_stat.itime;
}

static int read_dquot(loff_t num, void *buf, struct quotatree_tree *tree)
{
	int res, i, entries = 0;
	struct qt_disk_dqdbheader *dq_header;
	struct quotatree_node *p;
	struct v2r0_disk_dqblk *blk = buf + sizeof(struct qt_disk_dqdbheader);

	res = BLOCK_NOT_FOUND;
	dq_header = buf;
	memset(dq_header, 0, sizeof(*dq_header));

	list_for_each_entry(p, &(tree->levels[QUOTATREE_DEPTH - 1].usedlh),
			list) {
		if (TREENUM_2_BLKNUM(p->num) >= num)
			res = 0;
		if (TREENUM_2_BLKNUM(p->num) != num)
			continue;

		for (i = 0; i < QUOTATREE_BSIZE; i++) {
			if (!p->blocks[i])
				continue;
			convert_quot_format(blk + entries,
					(struct vz_quota_ugid *)p->blocks[i]);
			entries++;
			res = 0;
		}
		break;
	}
	dq_header->dqdh_entries = entries;

	return res;
}

static int read_block(int num, void *buf, struct quotatree_tree *tree,
	struct dq_kinfo *dq_ugid_info, int magic)
{
	int res;

	memset(buf, 0, DQBLOCK_SIZE);
	if (!num)
		res = read_header(buf, tree, dq_ugid_info, magic);
	else if (ISINDBLOCK(num))
		res = read_index_block(num, (u_int32_t*)buf, tree);
	else
		res = read_dquot(num, buf, tree);

	return res;
}

/*
 * FIXME: this function can handle quota files up to 2GB only.
 */
static int read_proc_quotafile(char *page, off_t off, int count,
		int *eof, void *data)
{
	off_t blk_num, blk_off, buf_off;
	char *tmp;
	size_t buf_size;
	struct quotatree_data *qtd;
	struct quotatree_tree *tree;
	struct dq_kinfo *dqi;
	int res;

	tmp = kmalloc(DQBLOCK_SIZE, GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	qtd = data;
	mutex_lock(&vz_quota_mutex);
	mutex_lock(&qtd->qmblk->dq_mutex);

	res = 0;
	tree = QUGID_TREE(qtd->qmblk, qtd->type);
	if (!tree) {
		*eof = 1;
		goto out_dq;
	}

	dqi = &qtd->qmblk->dq_ugid_info[qtd->type];

	buf_off = 0;
	buf_size = count;
	blk_num = off / DQBLOCK_SIZE;
	blk_off = off % DQBLOCK_SIZE;

	while (buf_size > 0) {
		off_t len;

		len = min((size_t)(DQBLOCK_SIZE-blk_off), buf_size);
		res = read_block(blk_num, tmp, tree, dqi, qtd->type);
		if (res < 0)
			goto out_dq;
		if (res == BLOCK_NOT_FOUND) {
			*eof = 1;
			break;
		} 
		memcpy(page + buf_off, tmp + blk_off, len);

		blk_num++;
		buf_size -= len;
		blk_off = 0;
		buf_off += len;
	}
	res = buf_off;

out_dq:
	mutex_unlock(&qtd->qmblk->dq_mutex);
	mutex_unlock(&vz_quota_mutex);
	kfree(tmp);

	return res;
}


/* ----------------------------------------------------------------------
 *
 * /proc/vz/vzaquota/QID/aquota.* files
 *
 * FIXME: this code lacks serialization of read/readdir/lseek.
 * However, this problem should be fixed after the mainstream issue of what
 * appears to be non-atomic read and update of file position in sys_read.
 *
 * --------------------------------------------------------------------- */

static inline unsigned long vzdq_aquot_getino(dev_t dev)
{
	return 0xec000000UL + dev;
}

static inline dev_t vzdq_aquot_getidev(struct inode *inode)
{
	return (dev_t)(unsigned long)PROC_I(inode)->op.proc_get_link;
}

static inline void vzdq_aquot_setidev(struct inode *inode, dev_t dev)
{
	PROC_I(inode)->op.proc_get_link = (void *)(unsigned long)dev;
}

static ssize_t vzdq_aquotf_read(struct file *file,
		char __user *buf, size_t size, loff_t *ppos)
{
	char *page;
	size_t bufsize;
	ssize_t l, l2, copied;
	struct inode *inode;
	struct block_device *bdev;
	struct super_block *sb;
	struct quotatree_data data;
	int eof, err;

	err = -ENOMEM;
	page = (char *)__get_free_page(GFP_KERNEL);
	if (page == NULL)
		goto out_err;

	err = -ENODEV;
	inode = file->f_dentry->d_inode;
	bdev = bdget(vzdq_aquot_getidev(inode));
	if (bdev == NULL)
		goto out_err;
	sb = get_super(bdev);
	bdput(bdev);
	if (sb == NULL)
		goto out_err;
	data.qmblk = vzquota_find_qmblk(sb);
	data.type = PROC_I(inode)->fd - 1;
	drop_super(sb);
	if (data.qmblk == NULL || data.qmblk == VZ_QUOTA_BAD)
		goto out_err;

	copied = 0;
	l = l2 = 0;
	while (1) {
		bufsize = min(size, (size_t)PAGE_SIZE);
		if (bufsize <= 0)
			break;

		l = read_proc_quotafile(page, *ppos, bufsize,
				&eof, &data);
		if (l <= 0)
			break;

		l2 = copy_to_user(buf, page, l);
		copied += l - l2;
		if (l2)
			break;

		buf += l;
		size -= l;
		*ppos += l;
		l = l2 = 0;
	}

	qmblk_put(data.qmblk);
	free_page((unsigned long)page);
	if (copied)
		return copied;
	else if (l2)		/* last copy_to_user failed */
		return -EFAULT;
	else			/* read error or EOF */
		return l;

out_err:
	if (page != NULL)
		free_page((unsigned long)page);
	return err;
}

static struct file_operations vzdq_aquotf_file_operations = {
	.read		= &vzdq_aquotf_read,
};

static struct inode_operations vzdq_aquotf_inode_operations = {
};


/* ----------------------------------------------------------------------
 *
 * /proc/vz/vzaquota/QID directory
 *
 * --------------------------------------------------------------------- */

static int vzdq_aquotq_readdir(struct file *file, void *data, filldir_t filler)
{
	loff_t n;
	int err;

	n = file->f_pos;
	for (err = 0; !err; n++) {
		/* ppc32 can't cmp 2 long long's in switch, calls __cmpdi2() */
		switch ((unsigned long)n) {
		case 0:
			err = (*filler)(data, ".", 1, n,
					file->f_dentry->d_inode->i_ino,
					DT_DIR);
			break;
		case 1:
			err = (*filler)(data, "..", 2, n,
					parent_ino(file->f_dentry), DT_DIR);
			break;
		case 2:
			err = (*filler)(data, aquota_user,
					sizeof(aquota_user)-1, n,
					file->f_dentry->d_inode->i_ino
								+ USRQUOTA + 1,
					DT_REG);
			break;
		case 3:
			err = (*filler)(data, aquota_group,
					sizeof(aquota_group)-1, n,
					file->f_dentry->d_inode->i_ino 
								+ GRPQUOTA + 1,
					DT_REG);
			break;
		default:
			goto out;
		}
	}
out:
	file->f_pos = n;
	return err;
}

struct vzdq_aquotq_lookdata {
	dev_t dev;
	int type;
	struct vz_quota_master *qmblk;
};

static int vzdq_aquotq_looktest(struct inode *inode, void *data)
{
	struct vzdq_aquotq_lookdata *d;

	d = data;
	return inode->i_op == &vzdq_aquotf_inode_operations &&
	       vzdq_aquot_getidev(inode) == d->dev &&
	       PROC_I(inode)->fd == d->type + 1;
}

static int vzdq_aquotq_lookset(struct inode *inode, void *data)
{
	struct vzdq_aquotq_lookdata *d;
	struct quotatree_tree *tree;

	d = data;
	inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME;
	inode->i_ino = vzdq_aquot_getino(d->dev) + d->type + 1;
	inode->i_mode = S_IFREG | S_IRUSR;
	inode->i_uid = 0;
	inode->i_gid = 0;
	inode->i_nlink = 1;
	inode->i_op = &vzdq_aquotf_inode_operations;
	inode->i_fop = &vzdq_aquotf_file_operations;
	PROC_I(inode)->fd = d->type + 1;
	vzdq_aquot_setidev(inode, d->dev);

	/* Setting size */
	tree = QUGID_TREE(d->qmblk, d->type);
	inode->i_size = get_block_num(tree) * 1024;
	return 0;
}

static int vzdq_aquotq_revalidate(struct dentry *vdentry, struct nameidata *nd)
{
	return 0;
}

static struct dentry_operations vzdq_aquotq_dentry_operations = {
	.d_revalidate	= &vzdq_aquotq_revalidate,
};

static struct vz_quota_master *find_qmblk_by_dev(dev_t dev)
{
	struct super_block *sb;
	struct vz_quota_master *qmblk;

	qmblk = NULL;
	sb = user_get_super(dev);
	if (sb != NULL) {
		qmblk = vzquota_find_qmblk(sb);
		drop_super(sb);

		if (qmblk == VZ_QUOTA_BAD)
			qmblk = NULL;
	}

	return qmblk;
}

static struct dentry *vzdq_aquotq_lookup(struct inode *dir,
		struct dentry *dentry,
		struct nameidata *nd)
{
	struct inode *inode;
	struct vzdq_aquotq_lookdata d;
	int k;

	if (dentry->d_name.len == sizeof(aquota_user)-1) {
		if (memcmp(dentry->d_name.name, aquota_user,
					sizeof(aquota_user)-1))
			goto out;
		k = USRQUOTA;
	} else if (dentry->d_name.len == sizeof(aquota_group)-1) {
		if (memcmp(dentry->d_name.name, aquota_group,
					sizeof(aquota_group)-1))
			goto out;
		k = GRPQUOTA;
	} else
		goto out;
	d.dev = vzdq_aquot_getidev(dir);
	d.type = k;
	d.qmblk = find_qmblk_by_dev(d.dev);
	if (d.qmblk == NULL)
		goto out;

	inode = iget5_locked(dir->i_sb, dir->i_ino + k + 1,
			vzdq_aquotq_looktest, vzdq_aquotq_lookset, &d);

	/* qmlbk ref is not needed, we used it for i_size calculation only */
	qmblk_put(d.qmblk);
	if (inode == NULL)
		goto out;

	if (inode->i_state & I_NEW)
		unlock_new_inode(inode);
	dentry->d_op = &vzdq_aquotq_dentry_operations;
	d_add(dentry, inode);
	return NULL;

out:
	return ERR_PTR(-ENOENT);
}

static struct file_operations vzdq_aquotq_file_operations = {
	.read		= &generic_read_dir,
	.readdir	= &vzdq_aquotq_readdir,
};

static struct inode_operations vzdq_aquotq_inode_operations = {
	.lookup		= &vzdq_aquotq_lookup,
};


/* ----------------------------------------------------------------------
 *
 * /proc/vz/vzaquota directory
 *
 * --------------------------------------------------------------------- */

struct vzdq_aquot_de {
	struct list_head list;
	struct vfsmount *mnt;
};

static int vzdq_aquot_buildmntlist(struct ve_struct *ve,
		struct list_head *head)
{
	struct vfsmount *mnt;
	struct path root;
	struct vzdq_aquot_de *p;
	int err;

#ifdef CONFIG_VE
	root = ve->root_path;
	path_get(&root);
#else
	get_fs_root(current->fs, &root)
#endif
	mnt = root.mnt;
	spin_lock(&vfsmount_lock);
	while (1) {
		list_for_each_entry(p, head, list) {
			if (p->mnt->mnt_sb == mnt->mnt_sb)
				goto skip;
		}

		err = -ENOMEM;
		p = kmalloc(sizeof(*p), GFP_ATOMIC);
		if (p == NULL)
			goto out;
		p->mnt = mntget(mnt);
		list_add_tail(&p->list, head);

skip:
		err = 0;
		if (list_empty(&mnt->mnt_mounts)) {
			while (1) {
				if (mnt == root.mnt)
					goto out;
				if (mnt->mnt_child.next !=
						&mnt->mnt_parent->mnt_mounts)
					break;
				mnt = mnt->mnt_parent;
			}
			mnt = list_entry(mnt->mnt_child.next,
					struct vfsmount, mnt_child);
		} else
			mnt = list_entry(mnt->mnt_mounts.next,
					struct vfsmount, mnt_child);
	}
out:
	spin_unlock(&vfsmount_lock);
	path_put(&root);
	return err;
}

static void vzdq_aquot_releasemntlist(struct ve_struct *ve,
		struct list_head *head)
{
	struct vzdq_aquot_de *p;

	while (!list_empty(head)) {
		p = list_entry(head->next, typeof(*p), list);
		mntput(p->mnt);
		list_del(&p->list);
		kfree(p);
	}
}

static int vzdq_aquotd_readdir(struct file *file, void *data, filldir_t filler)
{
	struct ve_struct *ve, *old_ve;
	struct list_head mntlist;
	struct vzdq_aquot_de *de;
	struct super_block *sb;
	struct vz_quota_master *qmblk;
	loff_t i, n;
	char buf[24];
	int l, err;

	i = 0;
	n = file->f_pos;
	ve = file->f_dentry->d_sb->s_type->owner_env;
	old_ve = set_exec_env(ve);

	INIT_LIST_HEAD(&mntlist);
#ifdef CONFIG_VE
	/*
	 * The only reason of disabling readdir for the host system is that
	 * this readdir can be slow and CPU consuming with large number of VPSs
	 * (or just mount points).
	 */
	err = ve_is_super(ve);
#else
	err = 0;
#endif
	if (!err) {
		err = vzdq_aquot_buildmntlist(ve, &mntlist);
		if (err)
			goto out_err;
	}

	if (i >= n) {
		if ((*filler)(data, ".", 1, i,
					file->f_dentry->d_inode->i_ino, DT_DIR))
			goto out_fill;
	}
	i++;

	if (i >= n) {
		if ((*filler)(data, "..", 2, i,
					parent_ino(file->f_dentry), DT_DIR))
			goto out_fill;
	}
	i++;

	list_for_each_entry (de, &mntlist, list) {
		sb = de->mnt->mnt_sb;
		if (get_device_perms_ve(S_IFBLK, sb->s_dev, FMODE_QUOTACTL))
			continue;

		qmblk = vzquota_find_qmblk(sb);
		if (qmblk == NULL || qmblk == VZ_QUOTA_BAD)
			continue;

		qmblk_put(qmblk);
		i++;
		if (i <= n)
			continue;

		l = sprintf(buf, "%08x", new_encode_dev(sb->s_dev));
		if ((*filler)(data, buf, l, i - 1,
					vzdq_aquot_getino(sb->s_dev), DT_DIR))
			break;
	}

out_fill:
	err = 0;
	file->f_pos = i;
out_err:
	vzdq_aquot_releasemntlist(ve, &mntlist);
	(void)set_exec_env(old_ve);
	return err;
}

static int vzdq_aquotd_looktest(struct inode *inode, void *data)
{
	return inode->i_op == &vzdq_aquotq_inode_operations &&
	       vzdq_aquot_getidev(inode) == (dev_t)(unsigned long)data;
}

static int vzdq_aquotd_lookset(struct inode *inode, void *data)
{
	dev_t dev;

	dev = (dev_t)(unsigned long)data;
	inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME;
	inode->i_ino = vzdq_aquot_getino(dev);
	inode->i_mode = S_IFDIR | S_IRUSR | S_IXUSR;
	inode->i_uid = 0;
	inode->i_gid = 0;
	inode->i_nlink = 2;
	inode->i_op = &vzdq_aquotq_inode_operations;
	inode->i_fop = &vzdq_aquotq_file_operations;
	vzdq_aquot_setidev(inode, dev);
	return 0;
}

static struct dentry *vzdq_aquotd_lookup(struct inode *dir,
		struct dentry *dentry,
		struct nameidata *nd)
{
	struct ve_struct *ve, *old_ve;
	const unsigned char *s;
	int l;
	dev_t dev;
	struct inode *inode;

	ve = dir->i_sb->s_type->owner_env;
	old_ve = set_exec_env(ve);
#ifdef CONFIG_VE
	/*
	 * Lookup is much lighter than readdir, so it can be allowed for the
	 * host system.  But it would be strange to be able to do lookup only
	 * without readdir...
	 */
	if (ve_is_super(ve))
		goto out;
#endif

	dev = 0;
	l = dentry->d_name.len;
	if (l <= 0)
		goto out;
	for (s = dentry->d_name.name; l > 0; s++, l--) {
		if (!isxdigit(*s))
			goto out;
		if (dev & ~(~0UL >> 4))
			goto out;
		dev <<= 4;
		if (isdigit(*s))
			dev += *s - '0';
		else if (islower(*s))
			dev += *s - 'a' + 10;
		else
			dev += *s - 'A' + 10;
	}
	dev = new_decode_dev(dev);

	if (get_device_perms_ve(S_IFBLK, dev, FMODE_QUOTACTL))
		goto out;

	inode = iget5_locked(dir->i_sb, vzdq_aquot_getino(dev),
			vzdq_aquotd_looktest, vzdq_aquotd_lookset,
			(void *)(unsigned long)dev);
	if (inode == NULL)
		goto out;

	if (inode->i_state & I_NEW)
		unlock_new_inode(inode);

	d_add(dentry, inode);
	(void)set_exec_env(old_ve);
	return NULL;

out:
	(void)set_exec_env(old_ve);
	return ERR_PTR(-ENOENT);
}

static int vzdq_aquotd_getattr(struct vfsmount *mnt, struct dentry *dentry,
		struct kstat *stat)
{
	struct ve_struct *ve, *old_ve;
	struct list_head mntlist, *pos;

	generic_fillattr(dentry->d_inode, stat);
	ve = dentry->d_sb->s_type->owner_env;
#ifdef CONFIG_VE
	/*
	 * The only reason of disabling getattr for the host system is that
	 * this getattr can be slow and CPU consuming with large number of VPSs
	 * (or just mount points).
	 */
	if (ve_is_super(ve))
		return 0;
#endif
	INIT_LIST_HEAD(&mntlist);
	old_ve = set_exec_env(ve);
	if (!vzdq_aquot_buildmntlist(ve, &mntlist))
		list_for_each(pos, &mntlist)
			stat->nlink++;
	vzdq_aquot_releasemntlist(ve, &mntlist);
	(void)set_exec_env(old_ve);
	return 0;
}

static struct file_operations vzdq_aquotd_file_operations = {
	.read		= &generic_read_dir,
	.readdir	= &vzdq_aquotd_readdir,
};

static struct inode_operations vzdq_aquotd_inode_operations = {
	.lookup		= &vzdq_aquotd_lookup,
	.getattr	= &vzdq_aquotd_getattr,
};


/* ----------------------------------------------------------------------
 *
 * Initialization and deinitialization
 *
 * --------------------------------------------------------------------- */
static int fake_data;
static struct ctl_table fake_table[] = {
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= ".fake",
		.mode		= 0600,
		.proc_handler	= proc_dointvec,
		.data		= &fake_data,
		.maxlen		= sizeof(int),
	},
	{ }
};

static struct ctl_path fake_path[] = {
	{ .ctl_name = CTL_FS, .procname = "fs", },
	{ .ctl_name = FS_DQSTATS, .procname = "quota", },
	{ }
};

/*
 * FIXME: creation of proc entries here is unsafe with respect to module
 * unloading.
 */
void vzaquota_init(void)
{
	struct proc_dir_entry *de;

	de = proc_create("vzaquota", S_IFDIR | S_IRUSR | S_IXUSR,
			glob_proc_vz_dir, &vzdq_aquotd_file_operations);
	if (de != NULL)
		de->proc_iops = &vzdq_aquotd_inode_operations;
	else
		printk("VZDQ: vz/vzaquota creation failed\n");

	register_sysctl_glob_paths(fake_path, fake_table, 1);
}

void vzaquota_fini(void)
{
	remove_proc_entry("vz/vzaquota", NULL);
}
