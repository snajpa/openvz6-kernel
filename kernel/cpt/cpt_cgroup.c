#include <linux/cgroup.h>
#include <linux/mount.h>
#include <linux/seq_file.h>
#include <linux/nsproxy.h>

#include <linux/cpt_obj.h>
#include <linux/cpt_context.h>
#include "cpt_files.h"
#include "cpt_process.h"

static int cgroup_index = 0;

static void cpt_dump_one_cgroup_pid(struct task_struct *task,
				struct cgroup_scanner *scan)
{
	struct cpt_context *ctx = scan->data;
	u32 pid;

	pid = cpt_task_pid_nr(task, PIDTYPE_PID);
	BUG_ON(!pid);
	ctx->write(&pid, sizeof(pid), ctx);
}

static int cpt_dump_one_cgroup(struct cgroup *cgrp, void *args)
{
	int ret = 0;
	cpt_object_t *obj;
	struct cpt_context *ctx = (struct cpt_context *) args;
	struct cpt_cgroup_image *v;
	loff_t saved_obj;
	u32 pid;

	const char *name = cgrp->dentry->d_name.name;

	obj = cpt_object_add(CPT_OBJ_CGROUP, cgrp, ctx);
	if (obj == NULL)
		return -ENOMEM;

	if (obj->o_index == CPT_NOINDEX)
		cpt_obj_setindex(obj, cgroup_index++, ctx);
	if (cgroup_index == INT_MAX)
		return -ENOMEM;

	cpt_open_object(obj, ctx);

	v = cpt_get_buf(ctx);

	v->cpt_next = CPT_NULL;
	v->cpt_object = CPT_OBJ_CGROUP;
	v->cpt_hdrlen = sizeof(*v);
	v->cpt_content = CPT_CONTENT_VOID;
	v->cpt_index = obj->o_index;

	if (test_bit(CGRP_NOTIFY_ON_RELEASE, &cgrp->flags))
		v->cpt_flags |= CPT_CGRP_NOTIFY_ON_RELEASE;
	if (test_bit(CGRP_SELF_DESTRUCTION, &cgrp->flags))
		v->cpt_flags |= CPT_CGRP_SELF_DESTRUCTION;

	if (cgrp == cgrp->top_cgroup) {
		v->cpt_parent = -1;
	} else {
		obj = lookup_cpt_object(CPT_OBJ_CGROUP, cgrp->parent, ctx);
		v->cpt_parent = obj->o_index;
	}

	ctx->write(v, sizeof(*v), ctx);
	cpt_release_buf(ctx);

	cpt_push_object(&saved_obj, ctx);
	if (v->cpt_parent != -1) {
		struct cgroup_scanner scan = {
			.cg = cgrp,
			.process_task = cpt_dump_one_cgroup_pid,
			.data = ctx,
		};

		cpt_dump_string(name, ctx);

		ret = cgroup_scan_tasks(&scan);
	}
	cpt_pop_object(&saved_obj, ctx);

	pid = 0;
	ctx->write(&pid, sizeof(pid), ctx);

	cpt_close_object(ctx);

	return ret;
}

static int cpt_dump_cgroup_options(struct vfsmount *mnt, struct cpt_context *ctx)
{
	struct seq_file sf;

	sf.buf = (char *) __get_free_page(GFP_KERNEL);
	if (!sf.buf)
		return -ENOMEM;
	sf.count = 0;
	sf.size = PAGE_SIZE;

	mnt->mnt_sb->s_op->show_options(&sf, mnt);

	if (strstr(sf.buf, "name=systemd"))
		seq_printf(&sf, ",none");

	/* ->show_options prepends a comma to the output */
	cpt_dump_string(sf.buf + 1, ctx);

	free_page((unsigned long) sf.buf);

	return 0;
}

static int cpt_dump_one_cgroup_mnt(cpt_object_t *obj, struct cpt_context *ctx)
{
	struct cpt_object_hdr *v;
	loff_t saved_obj;
	int err;

	cpt_open_object(NULL, ctx);
	v = cpt_get_buf(ctx);

	v->cpt_next = CPT_NULL;
	v->cpt_object = CPT_OBJ_CGROUPS;
	v->cpt_hdrlen = sizeof(*v);
	v->cpt_content = CPT_CONTENT_ARRAY;
	ctx->write(v, sizeof(*v), ctx);
	cpt_release_buf(ctx);

	cpt_push_object(&saved_obj, ctx);
	err = cpt_dump_cgroup_options(obj->o_parent, ctx);
	if (err)
		return err;

	err = cpt_collect_cgroups(obj->o_parent, cpt_dump_one_cgroup, ctx);
	cpt_pop_object(&saved_obj, ctx);

	cpt_close_object(ctx);

	return err;
}

int cpt_dump_cgroups(struct cpt_context *ctx)
{
	cpt_object_t *obj, *cgrp_obj;
	int err;
	struct vfsmount *mnt;

	for_each_object(cgrp_obj, CPT_OBJ_CGROUP) {
		mnt = cgrp_obj->o_parent;

		obj = cpt_object_add(CPT_OBJ_CGROUPS, mnt->mnt_sb, ctx);
		if (obj == NULL)
			return -ENOMEM;

		obj->o_parent = mnt;
	}

	cpt_open_section(ctx, CPT_SECT_CGROUPS);

	for_each_object(obj, CPT_OBJ_CGROUPS) {
		err = cpt_dump_one_cgroup_mnt(obj, ctx);
		if (err)
			return err;
	}

	cpt_close_section(ctx);

	return 0;
}

int cpt_add_cgroup(struct vfsmount *mnt, struct cpt_context *ctx)
{
	struct cgroup *cgrp = mnt->mnt_root->d_fsdata;
	cpt_object_t *obj;

	obj = cpt_object_add(CPT_OBJ_CGROUP, cgrp, ctx);
	if (obj == NULL)
		return CPT_NOINDEX;

	if (obj->o_index == CPT_NOINDEX) {
		cpt_obj_setindex(obj, cgroup_index++, ctx);
		obj->o_parent = mnt;
	}

	return obj->o_index;
}
