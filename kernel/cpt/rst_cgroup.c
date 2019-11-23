#include <linux/cgroup.h>
#include <linux/mount.h>

#include <linux/cpt_obj.h>
#include <linux/cpt_context.h>
#include "cpt_files.h"

static int rst_restore_one_cgroup_mnt(loff_t *pos, struct cpt_context * ctx)
{
	struct cpt_object_hdr gi;
	struct cgroup *cgrp;
	cpt_object_t *pobj, *obj;
	loff_t endpos;
	char *name, *mntdata;
	int err, first = 1;
	struct vfsmount *mnt;

	err = rst_get_object(CPT_OBJ_CGROUPS, *pos, &gi, ctx);
	if (err)
		return err;

	endpos = *pos + gi.cpt_next;
	*pos += gi.cpt_hdrlen;

	mntdata = __rst_get_name(pos, ctx);
	if (!mntdata)
		return -EINVAL;

	mnt = vfs_kern_mount(&cgroup_fs_type, 0, cgroup_fs_type.name, mntdata);
	rst_put_name(mntdata, ctx);
	if (IS_ERR(mnt))
		return PTR_ERR(mnt);

	obj = cpt_object_add(CPT_OBJ_CGROUPS, mnt->mnt_sb, ctx);
	if (!obj) {
		mntput(mnt);
		return -ENOMEM;
	}
	obj->o_parent = mnt;

	cgrp = mnt->mnt_root->d_fsdata;

	while (*pos < endpos) {
		struct cpt_cgroup_image ci;
		loff_t p;

		err = rst_get_object(CPT_OBJ_CGROUP, *pos, &ci, ctx);
		if (err)
			return err;

		/* The root cgroup should be first */
		if (first) {
			if (ci.cpt_parent != -1)
				return -EINVAL;
			first = 0;
		} else if (ci.cpt_parent == -1)
			return -EINVAL;

		p = *pos + ci.cpt_hdrlen;
		*pos += ci.cpt_next;

		if (ci.cpt_parent != -1) {
			pobj = lookup_cpt_obj_byindex(CPT_OBJ_CGROUP, ci.cpt_parent, ctx);
			if (!pobj)
				return -ENOENT;

			name =__rst_get_name(&p, ctx);
			cgrp = cgroup_kernel_open(pobj->o_obj, CGRP_CREAT, name);
			rst_put_name(name, ctx);
			if (IS_ERR(cgrp)) {
				return PTR_ERR(cgrp);
			}
		} else
			__cgroup_kernel_open(cgrp);

		if (ci.cpt_flags & CPT_CGRP_NOTIFY_ON_RELEASE)
			set_bit(CGRP_NOTIFY_ON_RELEASE, &cgrp->flags);
		if (ci.cpt_flags & CPT_CGRP_SELF_DESTRUCTION)
			set_bit(CGRP_SELF_DESTRUCTION, &cgrp->flags);

		obj = cpt_object_add(CPT_OBJ_CGROUP, cgrp, ctx);
		if (obj) {
			cpt_obj_setindex(obj, ci.cpt_index, ctx);
			cpt_obj_setpos(obj, p, ctx);
		} else
			return -ENOMEM;
	}

	return err;
}

int rst_cgroups(struct cpt_context *ctx)
{
	int err = 0;
	loff_t sec = ctx->sections[CPT_SECT_CGROUPS];
	loff_t endsec;
	struct cpt_section_hdr h;

	if (sec == CPT_NULL)
		return 0;

	err = ctx->pread(&h, sizeof(h), ctx, sec);
	if (err)
		return err;
	if (h.cpt_section != CPT_SECT_CGROUPS || h.cpt_hdrlen < sizeof(h))
		return -EINVAL;

	endsec = sec + h.cpt_next;
	sec += h.cpt_hdrlen;
	while (sec < endsec && !err)
		err = rst_restore_one_cgroup_mnt(&sec, ctx);

	return err;
}

int rst_cgroup_task(struct cpt_context * ctx)
{
	cpt_object_t *obj;
	struct task_struct *tsk;
	u32 pid;
	struct cgroup *cgrp;

	for_each_object(obj, CPT_OBJ_CGROUP) {
		cgrp = obj->o_obj;
		ctx->file->f_pos = obj->o_pos;
		while (1) {
			ctx->read(&pid, sizeof(pid), ctx);
			if (!pid)
				break;
			tsk = find_task_by_vpid(pid);
			if (!tsk) {
				eprintk_ctx("can't get task with pid %d\n", pid);
				return -ENOENT;
			}
			cgroup_kernel_attach(cgrp, tsk);
		}
	}
	return 0;
}

void rst_cgroup_close(struct cpt_context * ctx)
{
	cpt_object_t *obj;

	for_each_object(obj, CPT_OBJ_CGROUP)
		cgroup_kernel_close(obj->o_obj);

	for_each_object(obj, CPT_OBJ_CGROUPS)
		mntput(obj->o_parent);
}
