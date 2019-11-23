/*
 *
 *  kernel/cpt/cpt_ubc.c
 *
 *  Copyright (C) 2000-2005  SWsoft
 *  All rights reserved.
 *
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#include <linux/types.h>
#include <bc/beancounter.h>
#include <asm/signal.h>

#include <linux/cpt_obj.h>
#include <linux/cpt_context.h>

cpt_object_t *cpt_add_ubc(struct user_beancounter *bc, struct cpt_context *ctx)
{
	cpt_object_t *obj;

	obj = cpt_object_add(CPT_OBJ_UBC, bc, ctx);
	if (obj != NULL) {
		if (obj->o_count == 1)
			get_beancounter(bc);
	}
	return obj;
}

__u64 cpt_lookup_ubc(struct user_beancounter *bc, struct cpt_context *ctx)
{
	cpt_object_t *obj;

	obj = lookup_cpt_object(CPT_OBJ_UBC, bc, ctx);
	if (obj == NULL) {
		eprintk("CPT: unknown ub %u (%p)\n", bc->ub_uid, bc);
		dump_stack();
		return CPT_NULL;
	}
	return obj->o_pos;
}

static void dump_one_bc_parm(struct cpt_ubparm *dmp, struct ubparm *prm,
		int held)
{
	dmp->barrier = (prm->barrier < UB_MAXVALUE ? prm->barrier : CPT_NULL);
	dmp->limit = (prm->limit < UB_MAXVALUE ? prm->limit : CPT_NULL);
	dmp->held = (held ? prm->held : CPT_NULL);
	dmp->maxheld = prm->maxheld;
	dmp->minheld = prm->minheld;
	dmp->failcnt = prm->failcnt;
}

static int dump_one_bc(cpt_object_t *obj, struct cpt_context *ctx)
{
	struct user_beancounter *bc;
	struct cpt_beancounter_image *v;
	int i;

	bc = obj->o_obj;
	ub_update_resources(bc);
	v = cpt_get_buf(ctx);

	v->cpt_next = CPT_NULL;
	v->cpt_object = CPT_OBJ_UBC;
	v->cpt_hdrlen = sizeof(*v);
	v->cpt_content = CPT_CONTENT_ARRAY;

	if (obj->o_parent != NULL)
		v->cpt_parent = ((cpt_object_t *)obj->o_parent)->o_pos;
	else
		v->cpt_parent = CPT_NULL;
	v->cpt_id = (obj->o_parent != NULL) ? bc->ub_uid : 0;
	v->cpt_ub_resources = UB_RESOURCES;
	BUILD_BUG_ON(ARRAY_SIZE(v->cpt_parms) < UB_RESOURCES * 2);

	if (bc->ub_store == NULL)
		v->cpt_ub_flags = CPT_UB_NOSTORE;
	else
		v->cpt_ub_flags = 0;

	for (i = 0; i < UB_RESOURCES; i++) {
		dump_one_bc_parm(v->cpt_parms + i * 2, bc->ub_parms + i, 0);
		if (bc->ub_store != NULL)
			dump_one_bc_parm(v->cpt_parms + i * 2 + 1, bc->ub_store + i, 1);
	}
	memset(v->cpt_parms + UB_RESOURCES * 2, 0,
			sizeof(v->cpt_parms)
				- UB_RESOURCES * 2 * sizeof(v->cpt_parms[0]));

	cpt_open_object(obj, ctx);
	ctx->write(v, sizeof(*v), ctx);
	cpt_close_object(ctx);

	cpt_release_buf(ctx);
	return 0;
}

int cpt_dump_ubc(struct cpt_context *ctx)
{
	cpt_object_t *obj;
	int skipped;
	int top;

	cpt_open_section(ctx, CPT_SECT_UBC);

	do {
		skipped = 0;
		top = 0;
		for_each_object(obj, CPT_OBJ_UBC) {
			if (obj->o_parent == NULL)
				top++;
			if (obj->o_pos != CPT_NULL)
				continue;
			if (obj->o_parent != NULL &&
			    ((cpt_object_t *)obj->o_parent)->o_pos == CPT_NULL)
				skipped++;
			else
				dump_one_bc(obj, ctx);
		}
	} while (skipped && (top < 2));

	cpt_close_section(ctx);
	if (top > 1) {
		eprintk_ctx("More than one top level ub exist\n");
		return -EINVAL;
	}

	return 0;
}

void cpt_finish_ubc(struct cpt_context *ctx)
{
	cpt_object_t *obj;

	for_each_object(obj, CPT_OBJ_UBC)
		put_beancounter(obj->o_obj);
}
