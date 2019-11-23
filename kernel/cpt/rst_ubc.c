/*
 *
 *  kernel/cpt/rst_ubc.c
 *
 *  Copyright (C) 2000-2005  SWsoft
 *  All rights reserved.
 *
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#include <linux/types.h>
#include <linux/sched.h>
#include <bc/beancounter.h>
#include <asm/signal.h>

#include <linux/cpt_obj.h>
#include <linux/cpt_context.h>
#include "cpt_ubc.h"

struct user_beancounter *rst_lookup_ubc(__u64 pos, struct cpt_context *ctx)
{
	cpt_object_t *obj;

	obj = lookup_cpt_obj_bypos(CPT_OBJ_UBC, pos, ctx);
	if (obj == NULL) {
		eprintk("RST: unknown ub @%Ld\n", (long long)pos);
		return get_beancounter(get_exec_ub_top());
	}
	return get_beancounter(obj->o_obj);
}

static void restore_one_bc_parm(struct cpt_ubparm *dmp, struct ubparm *prm,
		int held)
{
	prm->barrier = (dmp->barrier == CPT_NULL ? UB_MAXVALUE : dmp->barrier);
	prm->limit = (dmp->limit == CPT_NULL ? UB_MAXVALUE : dmp->limit);
	if (held)
		prm->held = dmp->held;
	prm->maxheld = dmp->maxheld;
	prm->minheld = dmp->minheld;
	prm->failcnt = max_t(long, prm->failcnt, dmp->failcnt);
}

static int restore_one_bc(struct cpt_beancounter_image *v,
		cpt_object_t *obj, struct cpt_context *ctx)
{
	struct user_beancounter *bc;
	int resources, i;

	if (v->cpt_parent != CPT_NULL) {
		/*
		 * No subbeancounters supported anymore. So just exit.
		 */
		return 0;
	} else {
		bc = get_exec_ub_top();
		get_beancounter(bc);
	}
	if (bc == NULL)
		return -ENOMEM;
	obj->o_obj = bc;

	if (ctx->image_version < CPT_VERSION_18 &&
			CPT_VERSION_MINOR(ctx->image_version) < 1)
		return 0;

	if (v->cpt_content == CPT_CONTENT_ARRAY)
		resources = v->cpt_ub_resources;
	else
		resources = UB_RESOURCES_COMPAT;

	if (resources > UB_RESOURCES)
		return -EINVAL;

	if (!(v->cpt_ub_flags & CPT_UB_NOSTORE)) {
		int res;

		res = ubstat_alloc_store(bc);
		if (res)
			return res;
	}

	for (i = 0; i < resources; i++) {
		restore_one_bc_parm(v->cpt_parms + i * 2, ctx->saved_ubc + i, 0);
		if (!(v->cpt_ub_flags & CPT_UB_NOSTORE))
			restore_one_bc_parm(v->cpt_parms + i * 2 + 1,
						bc->ub_store + i, 1);
	}

	return 0;
}

int rst_undump_ubc(struct cpt_context *ctx)
{
	loff_t start, end;
	struct cpt_beancounter_image *v;
	cpt_object_t *obj;
	int err;

	err = rst_get_section(CPT_SECT_UBC, ctx, &start, &end);
	if (err)
		return err;

	while (start < end) {
		v = cpt_get_buf(ctx);
		err = rst_get_object(CPT_OBJ_UBC, start, v, ctx);
		if (err) {
			cpt_release_buf(ctx);
			return err;
		}

		obj = alloc_cpt_object(GFP_KERNEL, ctx);
		cpt_obj_setpos(obj, start, ctx);
		intern_cpt_object(CPT_OBJ_UBC, obj, ctx);

		err = restore_one_bc(v, obj, ctx);

		cpt_release_buf(ctx);
		if (err)
			return err;

		start += v->cpt_next;
	}

	return 0;
}

void rst_finish_ubc(struct cpt_context *ctx)
{
	cpt_object_t *obj;

	for_each_object(obj, CPT_OBJ_UBC)
		put_beancounter(obj->o_obj);
}
