/*
 *
 *  kernel/cpt/cpt_obj.c
 *
 *  Copyright (C) 2000-2005  SWsoft
 *  All rights reserved.
 *
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/errno.h>

#include <linux/cpt_obj.h>
#include <linux/cpt_context.h>

cpt_object_t *alloc_cpt_object(int gfp, struct cpt_context *ctx)
{
	cpt_object_t *obj;

	obj = kmalloc(sizeof(cpt_object_t), gfp);
	if (obj) {
		INIT_LIST_HEAD(&obj->o_list);
		INIT_LIST_HEAD(&obj->o_hash);
		obj->o_count = 1;
		obj->o_pos = CPT_NULL;
		obj->o_lock = 0;
		obj->o_parent = NULL;
		obj->o_index = CPT_NOINDEX;
		obj->o_obj = NULL;
		obj->o_image = NULL;
		obj->o_flags = 0;
		ctx->objcount++;
	}
	return obj;
}

void free_cpt_object(cpt_object_t *obj, cpt_context_t *ctx)
{
	kfree(obj);
	ctx->objcount--;
}

void intern_cpt_object(enum _cpt_object_type type, cpt_object_t *obj, cpt_context_t *ctx)
{
	list_add_tail(&obj->o_list, &ctx->object_array[type]);
}

void insert_cpt_object(enum _cpt_object_type type, cpt_object_t *obj,
			cpt_object_t *head, cpt_context_t *ctx)
{
	list_add(&obj->o_list, &head->o_list);
}

cpt_object_t * __cpt_object_add(enum _cpt_object_type type, void *p,
		unsigned gfp_mask, cpt_context_t *ctx)
{
	cpt_object_t *obj;

	obj = lookup_cpt_object(type, p, ctx);

	if (obj) {
		obj->o_count++;
		return obj;
	}

	if ((obj = alloc_cpt_object(gfp_mask, ctx)) != NULL) {
		if (p)
			cpt_obj_setobj(obj, p, ctx);
		intern_cpt_object(type, obj, ctx);
		return obj;
	}
	return NULL;
}

cpt_object_t * cpt_object_add(enum _cpt_object_type type, void *p, cpt_context_t *ctx)
{
	return __cpt_object_add(type, p, GFP_KERNEL, ctx);
}

cpt_object_t * cpt_object_get(enum _cpt_object_type type, void *p, cpt_context_t *ctx)
{
	cpt_object_t *obj;

	obj = lookup_cpt_object(type, p, ctx);

	if (obj)
		obj->o_count++;

	return obj;
}

int cpt_object_init(cpt_context_t *ctx)
{
	int i;

	for (i=0; i<CPT_OBJ_MAX; i++) {
		INIT_LIST_HEAD(&ctx->object_array[i]);
	}
	return 0;
}

int cpt_object_destroy(cpt_context_t *ctx)
{
	int i;

	for (i=0; i<CPT_OBJ_MAX; i++) {
		while (!list_empty(&ctx->object_array[i])) {
			struct list_head *head = ctx->object_array[i].next;
			cpt_object_t *obj = list_entry(head, cpt_object_t, o_list);
			list_del(head);
			if (obj->o_image)
				kfree(obj->o_image);
			free_cpt_object(obj, ctx);
		}
	}
	if (ctx->objcount != 0)
		eprintk_ctx("BUG: ctx->objcount=%d\n", ctx->objcount);
	return 0;
}

cpt_object_t *lookup_cpt_object(enum _cpt_object_type type, void *p, struct cpt_context *ctx)
{
	cpt_object_t *obj;

	for_each_object(obj, type) {
		if (obj->o_obj == p)
			return obj;
	}
	return NULL;
}

cpt_object_t *lookup_cpt_obj_bypos(enum _cpt_object_type type, loff_t pos, struct cpt_context *ctx)
{
	cpt_object_t *obj;

	for_each_object(obj, type) {
		if (obj->o_pos == pos)
			return obj;
	}
	return NULL;
}

cpt_object_t *lookup_cpt_obj_byindex(enum _cpt_object_type type, __u32 index, struct cpt_context *ctx)
{
	cpt_object_t *obj;

	for_each_object(obj, type) {
		if (obj->o_index == index)
			return obj;
	}
	return NULL;
}
