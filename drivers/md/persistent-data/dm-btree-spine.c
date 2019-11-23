/*
 * Copyright (C) 2011 Red Hat, Inc.
 *
 * This file is released under the GPL.
 */

#include "dm-btree-internal.h"
#include "dm-transaction-manager.h"

#include <linux/device-mapper.h>

#define DM_MSG_PREFIX "btree spine"

/*----------------------------------------------------------------*/

#define BTREE_CSUM_XOR 121107

static int node_check(struct dm_block_validator *v,
		      struct dm_block *b,
		      size_t block_size);

static void node_prepare_for_write(struct dm_block_validator *v,
				   struct dm_block *b,
				   size_t block_size)
{
	struct btree_node *n = dm_block_data(b);
	struct node_header *h = &n->header;

	h->blocknr = cpu_to_le64(dm_block_location(b));
	h->csum = cpu_to_le32(dm_bm_checksum(&h->flags,
					     block_size - sizeof(__le32),
					     BTREE_CSUM_XOR));

	BUG_ON(node_check(v, b, 4096));
}

static int node_check(struct dm_block_validator *v,
		      struct dm_block *b,
		      size_t block_size)
{
	struct btree_node *n = dm_block_data(b);
	struct node_header *h = &n->header;
	size_t value_size;
	__le32 csum_disk;
	uint32_t flags;

	if (dm_block_location(b) != le64_to_cpu(h->blocknr)) {
		DMERR_LIMIT("node_check failed: blocknr %llu != wanted %llu",
			    le64_to_cpu(h->blocknr), dm_block_location(b));
		return -ENOTBLK;
	}

	csum_disk = cpu_to_le32(dm_bm_checksum(&h->flags,
					       block_size - sizeof(__le32),
					       BTREE_CSUM_XOR));
	if (csum_disk != h->csum) {
		DMERR_LIMIT("node_check failed: csum %u != wanted %u",
			    le32_to_cpu(csum_disk), le32_to_cpu(h->csum));
		return -EILSEQ;
	}

	value_size = le32_to_cpu(h->value_size);

	if (sizeof(struct node_header) +
	    (sizeof(__le64) + value_size) * le32_to_cpu(h->max_entries) > block_size) {
		DMERR_LIMIT("node_check failed: max_entries too large");
		return -EILSEQ;
	}

	if (le32_to_cpu(h->nr_entries) > le32_to_cpu(h->max_entries)) {
		DMERR_LIMIT("node_check failed: too many entries");
		return -EILSEQ;
	}

	/*
	 * The node must be either INTERNAL or LEAF.
	 */
	flags = le32_to_cpu(h->flags);
	if (!(flags & INTERNAL_NODE) && !(flags & LEAF_NODE)) {
		DMERR_LIMIT("node_check failed: node is neither INTERNAL or LEAF");
		return -EILSEQ;
	}

	return 0;
}

struct dm_block_validator btree_node_validator = {
	.name = "btree_node",
	.prepare_for_write = node_prepare_for_write,
	.check = node_check
};

/*----------------------------------------------------------------*/

int bn_read_lock(struct dm_btree_info *info, dm_block_t b,
		 struct dm_block **result)
{
	return dm_tm_read_lock(info->tm, b, &btree_node_validator, result);
}

static int bn_shadow(struct dm_btree_info *info, dm_block_t orig,
	      struct dm_btree_value_type *vt,
	      struct dm_block **result)
{
	int r, inc;

	r = dm_tm_shadow_block(info->tm, orig, &btree_node_validator,
			       result, &inc);
	if (!r && inc)
		inc_children(info->tm, dm_block_data(*result), vt);

	return r;
}

int new_block(struct dm_btree_info *info, struct dm_block **result)
{
	return dm_tm_new_block(info->tm, &btree_node_validator, result);
}

void unlock_block(struct dm_btree_info *info, struct dm_block *b)
{
	dm_tm_unlock(info->tm, b);
}

/*----------------------------------------------------------------*/

static void __init_ro_spine(struct ro_spine *s, struct dm_btree_info *info, int len)
{
	int i;
	int *idxs = NULL;

	if (len == RO_SPINE_LONG_LEN) {
		struct ro_spine_long *sl =
			container_of(s, struct ro_spine_long, ro_spine);
		idxs = sl->idxs;
	}

	s->info = info;
	s->length = len;
	s->count = 0;
	for (i = 0; i < len; i++) {
		s->nodes[i] = NULL;
		if (idxs)
			idxs[i] = 0;
	}

}

void init_ro_spine(struct ro_spine *s, struct dm_btree_info *info)
{
	__init_ro_spine(s, info, 2);
}

void init_ro_spine_long(struct ro_spine_long *s, struct dm_btree_info *info)
{
	__init_ro_spine(&s->ro_spine, info, RO_SPINE_LONG_LEN);
}

int exit_ro_spine(struct ro_spine *s)
{
	int r = 0, i;

	for (i = 0; i < s->count; i++) {
		unlock_block(s->info, s->nodes[i]);
	}

	return r;
}

int exit_ro_spine_long(struct ro_spine_long *s)
{
	return exit_ro_spine(&s->ro_spine);
}

int __ro_step(struct ro_spine *s, dm_block_t new_child, int idx, int *idxs)
{
	int r;

	if (s->count == s->length) {
		int i;
		unlock_block(s->info, s->nodes[0]);

		for (i = 0; i < s->length - 1; i++) {
			s->nodes[i] = s->nodes[i+1];
			if (idxs)
				idxs[i] = idxs[i+1];
		}
		s->count--;
	}

	r = bn_read_lock(s->info, new_child, s->nodes + s->count);
	if (!r) {
		if (idxs)
			idxs[s->count] = idx;
		s->count++;

	}
	return r;
}

int ro_step(struct ro_spine *s, dm_block_t new_child)
{
	return __ro_step(s, new_child, 0, NULL);
}

int ro_step_long(struct ro_spine_long *s, dm_block_t new_child, int idx)
{
	return __ro_step(&s->ro_spine, new_child, idx, s->idxs);
}

int __ro_pop(struct ro_spine *s, int *idxs, int *idx)
{
	BUG_ON(!s->count);

	if (idxs) {
		if (idxs[s->count - 1] < 0)
			return -ENODATA;

		if (s->count == 1)
			return -ENOSPC;
	}

	--s->count;

	if (idxs)
		*idx = idxs[s->count];

	unlock_block(s->info, s->nodes[s->count]);
	return 0;
}

void ro_pop(struct ro_spine *s)
{
	(void)__ro_pop(s, NULL, NULL);
}

int ro_pop_long(struct ro_spine_long *s, int *idx)
{
	return __ro_pop(&s->ro_spine, s->idxs, idx);
}

struct btree_node *ro_node(struct ro_spine *s)
{
	struct dm_block *block;

	BUG_ON(!s->count);
	block = s->nodes[s->count - 1];

	return dm_block_data(block);
}

struct btree_node *ro_node_long(struct ro_spine_long *s)
{
	return ro_node(&s->ro_spine);
}
/*----------------------------------------------------------------*/

void init_shadow_spine(struct shadow_spine *s, struct dm_btree_info *info)
{
	s->info = info;
	s->count = 0;
}

int exit_shadow_spine(struct shadow_spine *s)
{
	int r = 0, i;

	for (i = 0; i < s->count; i++) {
		unlock_block(s->info, s->nodes[i]);
	}

	return r;
}

int shadow_step(struct shadow_spine *s, dm_block_t b,
		struct dm_btree_value_type *vt)
{
	int r;

	if (s->count == 2) {
		unlock_block(s->info, s->nodes[0]);
		s->nodes[0] = s->nodes[1];
		s->count--;
	}

	r = bn_shadow(s->info, b, vt, s->nodes + s->count);
	if (!r) {
		if (!s->count)
			s->root = dm_block_location(s->nodes[0]);

		s->count++;
	}

	return r;
}

struct dm_block *shadow_current(struct shadow_spine *s)
{
	BUG_ON(!s->count);

	return s->nodes[s->count - 1];
}

struct dm_block *shadow_parent(struct shadow_spine *s)
{
	BUG_ON(s->count != 2);

	return s->count == 2 ? s->nodes[0] : NULL;
}

int shadow_has_parent(struct shadow_spine *s)
{
	return s->count >= 2;
}

int shadow_root(struct shadow_spine *s)
{
	return s->root;
}

static void le64_inc(void *context, const void *value_le)
{
	struct dm_transaction_manager *tm = context;
	__le64 v_le;

	memcpy(&v_le, value_le, sizeof(v_le));
	dm_tm_inc(tm, le64_to_cpu(v_le));
}

static void le64_dec(void *context, const void *value_le)
{
	struct dm_transaction_manager *tm = context;
	__le64 v_le;

	memcpy(&v_le, value_le, sizeof(v_le));
	dm_tm_dec(tm, le64_to_cpu(v_le));
}

static int le64_equal(void *context, const void *value1_le, const void *value2_le)
{
	__le64 v1_le, v2_le;

	memcpy(&v1_le, value1_le, sizeof(v1_le));
	memcpy(&v2_le, value2_le, sizeof(v2_le));
	return v1_le == v2_le;
}

void init_le64_type(struct dm_transaction_manager *tm,
		    struct dm_btree_value_type *vt)
{
	vt->context = tm;
	vt->size = sizeof(__le64);
	vt->inc = le64_inc;
	vt->dec = le64_dec;
	vt->equal = le64_equal;
}
