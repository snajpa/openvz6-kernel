/*
 *
 * Copyright (C) 2005 SWsoft
 * All rights reserved.
 * 
 * Licensing governed by "linux/COPYING.SWsoft" file.
 *
 * This file contains Virtuozzo disk quota tree definition
 */

#ifndef _VZDQ_TREE_H
#define _VZDQ_TREE_H

#include <linux/list.h>
#include <asm/string.h>

typedef unsigned int quotaid_t;
#define QUOTAID_BITS		32
#define QUOTAID_BBITS		4
#define QUOTAID_EBITS		8

#if QUOTAID_EBITS % QUOTAID_BBITS
#error Quota bit assumption failure
#endif

#define QUOTATREE_BSIZE		(1 << QUOTAID_BBITS)
#define QUOTATREE_BMASK		(QUOTATREE_BSIZE - 1)
#define QUOTATREE_DEPTH		((QUOTAID_BITS + QUOTAID_BBITS - 1) \
							/ QUOTAID_BBITS)
#define QUOTATREE_EDEPTH	((QUOTAID_BITS + QUOTAID_EBITS - 1) \
							/ QUOTAID_EBITS)
#define QUOTATREE_BSHIFT(lvl)	((QUOTATREE_DEPTH - (lvl) - 1) * QUOTAID_BBITS)

/*
 * Depth of keeping unused node (not inclusive).
 * 0 means release all nodes including root,
 * QUOTATREE_DEPTH means never release nodes.
 * Current value: release all nodes strictly after QUOTATREE_EDEPTH 
 * (measured in external shift units).
 */
#define QUOTATREE_CDEPTH	(QUOTATREE_DEPTH \
				- 2 * QUOTATREE_DEPTH / QUOTATREE_EDEPTH \
				+ 1)

/*
 * Levels 0..(QUOTATREE_DEPTH-1) are tree nodes.
 * On level i the maximal number of nodes is 2^(i*QUOTAID_BBITS),
 * and each node contains 2^QUOTAID_BBITS pointers.
 * Level 0 is a (single) tree root node.
 *
 * Nodes of level (QUOTATREE_DEPTH-1) contain pointers to caller's data.
 * Nodes of lower levels contain pointers to nodes.
 *
 * Double pointer in array of i-level node, pointing to a (i+1)-level node
 * (such as inside quotatree_find_state) are marked by level (i+1), not i.
 * Level 0 double pointer is a pointer to root inside tree struct.
 *
 * The tree is permanent, i.e. all index blocks allocated are keeped alive to
 * preserve the blocks numbers in the quota file tree to keep its changes
 * locally.
 */
struct quotatree_node {
	struct list_head list;
	quotaid_t num;
	void *blocks[QUOTATREE_BSIZE];
};

struct quotatree_level {
	struct list_head usedlh, freelh;
	quotaid_t freenum;
};

struct quotatree_tree {
	struct quotatree_level levels[QUOTATREE_DEPTH];
	struct quotatree_node *root;
	unsigned int leaf_num;
};

struct quotatree_find_state {
	void **block;
	int level;
};

/* number of leafs (objects) and leaf level of the tree */
#define QTREE_LEAFNUM(tree)	((tree)->leaf_num)
#define QTREE_LEAFLVL(tree)	(&(tree)->levels[QUOTATREE_DEPTH - 1])

struct quotatree_tree *quotatree_alloc(void);
void *quotatree_find(struct quotatree_tree *tree, quotaid_t id,
		struct quotatree_find_state *st);
int quotatree_insert(struct quotatree_tree *tree, quotaid_t id,
		struct quotatree_find_state *st, void *data);
void quotatree_remove(struct quotatree_tree *tree, quotaid_t id);
void quotatree_free(struct quotatree_tree *tree, void (*dtor)(void *));
void *quotatree_get_next(struct quotatree_tree *tree, quotaid_t id);
void *quotatree_leaf_byindex(struct quotatree_tree *tree, unsigned int index);

#endif /* _VZDQ_TREE_H */

