/*
 *
 * Copyright (C) 2005  SWsoft
 * All rights reserved.
 * 
 * Licensing governed by "linux/COPYING.SWsoft" file.
 *
 * This file contains Virtuozzo quota tree implementation
 */

#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/vzdq_tree.h>

struct quotatree_tree *quotatree_alloc(void)
{
	int l;
	struct quotatree_tree *tree;

	tree = kmalloc(sizeof(struct quotatree_tree), GFP_KERNEL);
	if (tree == NULL)
		goto out;

	for (l = 0; l < QUOTATREE_DEPTH; l++) {
		INIT_LIST_HEAD(&tree->levels[l].usedlh);
		INIT_LIST_HEAD(&tree->levels[l].freelh);
		tree->levels[l].freenum = 0;
	}
	tree->root = NULL;
	tree->leaf_num = 0;
out:
	return tree;
}

static struct quotatree_node *
quotatree_follow(struct quotatree_tree *tree, quotaid_t id, int level,
		struct quotatree_find_state *st)
{
	void **block;
	struct quotatree_node *parent;
	int l, index;

	parent = NULL;
	block = (void **)&tree->root;
	l = 0;
	while (l < level && *block != NULL) {
		index = (id >>  QUOTATREE_BSHIFT(l)) & QUOTATREE_BMASK;
		parent = *block;
		block = parent->blocks + index;
		l++;
	}
	if (st != NULL) {
		st->block = block;
		st->level = l;
	}

	return parent;
}

void *quotatree_find(struct quotatree_tree *tree, quotaid_t id,
		struct quotatree_find_state *st)
{
	quotatree_follow(tree, id, QUOTATREE_DEPTH, st);
	if (st->level == QUOTATREE_DEPTH)
		return *st->block;
	else
		return NULL;
}

void *quotatree_leaf_byindex(struct quotatree_tree *tree, unsigned int index)
{
	int i, count;
	struct quotatree_node *p;
	void *leaf;

	if (QTREE_LEAFNUM(tree) <= index)
		return NULL;

	count = 0;
	list_for_each_entry(p, &QTREE_LEAFLVL(tree)->usedlh, list) {
		for (i = 0; i < QUOTATREE_BSIZE; i++) {	
			leaf = p->blocks[i];
			if (leaf == NULL)
				continue;
			if (count == index)
				return leaf;
			count++;
		}
	}
	return NULL;
}

/* returns data leaf (vz_quota_ugid) after _existent_ ugid (@id)
 * in the tree... */
void *quotatree_get_next(struct quotatree_tree *tree, quotaid_t id)
{
	int off;
	struct quotatree_node *parent, *p;
	struct list_head *lh;

	/* get parent refering correct quota tree node of the last level */
	parent = quotatree_follow(tree, id, QUOTATREE_DEPTH, NULL);
	if (!parent)
		return NULL;

	off = (id & QUOTATREE_BMASK) + 1;	/* next ugid */
	lh = &parent->list;
	do {
		p = list_entry(lh, struct quotatree_node, list);
		for ( ; off < QUOTATREE_BSIZE; off++)
			if (p->blocks[off])
				return p->blocks[off];
		off = 0;
		lh = lh->next;
	} while (lh != &QTREE_LEAFLVL(tree)->usedlh);

	return NULL;
}

int quotatree_insert(struct quotatree_tree *tree, quotaid_t id,
		struct quotatree_find_state *st, void *data)
{
	struct quotatree_node *p;
	int l, index;

	while (st->level < QUOTATREE_DEPTH) {
		l = st->level;
		if (!list_empty(&tree->levels[l].freelh)) {
			p = list_entry(tree->levels[l].freelh.next,
					struct quotatree_node, list);
			list_del(&p->list);
		} else {
			p = kmalloc(sizeof(struct quotatree_node), GFP_NOFS | __GFP_NOFAIL);
			if (p == NULL)
				return -ENOMEM;
			/* save block number in the l-level
			 * it uses for quota file generation */
			p->num = tree->levels[l].freenum++;
		}
		list_add(&p->list, &tree->levels[l].usedlh);
		memset(p->blocks, 0, sizeof(p->blocks));
		*st->block = p;

		index = (id >> QUOTATREE_BSHIFT(l)) & QUOTATREE_BMASK;
		st->block = p->blocks + index;
		st->level++;
	}
	tree->leaf_num++;
	*st->block = data;

	return 0;
}

static struct quotatree_node *
quotatree_remove_ptr(struct quotatree_tree *tree, quotaid_t id,
		int level)
{
	struct quotatree_node *parent;
	struct quotatree_find_state st;

	parent = quotatree_follow(tree, id, level, &st);
	if (st.level == QUOTATREE_DEPTH)
		tree->leaf_num--;
	*st.block = NULL;
	return parent;
}

void quotatree_remove(struct quotatree_tree *tree, quotaid_t id)
{
	struct quotatree_node *p;
	int level, i;

	p = quotatree_remove_ptr(tree, id, QUOTATREE_DEPTH);
	for (level = QUOTATREE_DEPTH - 1; level >= QUOTATREE_CDEPTH; level--) {
		for (i = 0; i < QUOTATREE_BSIZE; i++)
			if (p->blocks[i] != NULL)
				return;
		list_move(&p->list, &tree->levels[level].freelh);
		p = quotatree_remove_ptr(tree, id, level);
	}
}

#if 0
static void quotatree_walk(struct quotatree_tree *tree,
		struct quotatree_node *node_start,
		quotaid_t id_start,
		int level_start, int level_end,
		int (*callback)(struct quotatree_tree *,
				quotaid_t id,
				int level,
				void *ptr,
				void *data),
		void *data)
{
	struct quotatree_node *p;
	int l, shift, index;
	quotaid_t id;
	struct quotatree_find_state st;

	p = node_start;
	l = level_start;
	shift = (QUOTATREE_DEPTH - l) * QUOTAID_BBITS;
	id = id_start;
	index = 0;

	/*
	 * Invariants:
	 * shift == (QUOTATREE_DEPTH - l) * QUOTAID_BBITS;
	 * id & ((1 << shift) - 1) == 0
	 * p is l-level node corresponding to id
	 */
	do {
		if (!p)
			break;

		if (l < level_end) {
			for (; index < QUOTATREE_BSIZE; index++)
				if (p->blocks[index] != NULL)
					break;
			if (index < QUOTATREE_BSIZE) {
				/* descend */
				p = p->blocks[index];
				l++;
				shift -= QUOTAID_BBITS;
				id += (quotaid_t)index << shift;
				index = 0;
				continue;
			}
		}

		if ((*callback)(tree, id, l, p, data))
			break;

		/* ascend and to the next node */
		p = quotatree_follow(tree, id, l, &st);

		index = ((id >> shift) & QUOTATREE_BMASK) + 1;
		l--;
		shift += QUOTAID_BBITS;
		id &= ~(((quotaid_t)1 << shift) - 1);
	} while (l >= level_start);
}
#endif

static void free_list(struct list_head *node_list)
{
	struct quotatree_node *p, *tmp;

	list_for_each_entry_safe(p, tmp, node_list, list) {
		list_del(&p->list);
		kfree(p);
	}
}

static inline void quotatree_free_nodes(struct quotatree_tree *tree)
{
	int i;

	for (i = 0; i < QUOTATREE_DEPTH; i++) {
		free_list(&tree->levels[i].usedlh);
		free_list(&tree->levels[i].freelh);
	}
}

static void quotatree_free_leafs(struct quotatree_tree *tree,
		void (*dtor)(void *))
{
	int i;
	struct quotatree_node *p;

	list_for_each_entry(p, &QTREE_LEAFLVL(tree)->usedlh, list) {
		for (i = 0; i < QUOTATREE_BSIZE; i++) {
			if (p->blocks[i] == NULL)
				continue;

			dtor(p->blocks[i]);
		}
	}
}

void quotatree_free(struct quotatree_tree *tree, void (*dtor)(void *))
{
	quotatree_free_leafs(tree, dtor);
	quotatree_free_nodes(tree);
	kfree(tree);
}
