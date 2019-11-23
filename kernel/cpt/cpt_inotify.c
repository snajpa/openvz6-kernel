/*
 *
 *  kernel/cpt/cpt_inotify.c
 *
 *  Copyright (C) 2000-2007  SWsoft
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
#include <linux/major.h>
#include <linux/pipe_fs_i.h>
#include <linux/mman.h>
#include <linux/mnt_namespace.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/smp_lock.h>
#include <asm/uaccess.h>
#include <linux/vzcalluser.h>
#include <linux/inotify.h>
#include <linux/cpt_image.h>
#include <linux/fsnotify_backend.h>

#include "../../fs/notify/inotify/inotify.h"

#include <linux/cpt_obj.h>
#include <linux/cpt_context.h>
#include "cpt_mm.h"
#include "cpt_files.h"
#include "cpt_kernel.h"
#include "cpt_fsmagic.h"
#include "cpt_syscalls.h"

static int is_fake_file_dentry(struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;

	if (inode != anon_inode_inode)
		return 0;

	return !strcmp(dentry->d_name.name, FAKE_FILE_NAME);
}

static int dump_watch_inode(struct path *path, cpt_context_t *ctx)
{
	struct dentry *d;

	if (cpt_need_delayfs(path->mnt)) {
		eprintk_ctx("inotify migration for delayed mounts (NFS) is not "
				"supported\n");
		return -EINVAL;
	}

	d = path->dentry;

	if ((d_unhashed(d) && !IS_ROOT(d)) || is_fake_file_dentry(d))
		d = NULL;

	return cpt_dump_dir(d, path->mnt, ctx);
}

static int cpt_dump_watches(struct fsnotify_group *g, struct cpt_context *ctx)
{
	int err = 0;
	struct fsnotify_mark_entry *fse;
	struct inotify_inode_mark_entry *ie;
	struct cpt_inotify_wd_image wi;
	loff_t saved_obj;

	/*
	 * NOTE: We don't take spin lock over @mark_lock here on purpose:
	 * the lock put the kernel in atomic context which is prohibited
	 * if ctx->write operation is used. This is actually safe to run
	 * over all marks without lock taken -- all tasks which belong to
	 * the container are stopped so the marks won't be removed while
	 * we're dumping them.
	 */
	list_for_each_entry(fse, &g->mark_entries, g_list) {
		struct nameidata nd;

		ie = container_of(fse, struct inotify_inode_mark_entry,
				fsn_entry);

		err = path_lookup(ie->cpt_wd_path, 0, &nd);
		if (err) {
			/*
			 * If the watchee we're looking for has been
			 * deleted, the "delete" event should be in
			 * notify queue, mark is alive but path no
			 * longer accessible, thus simply skip it
			 * from dumping -- we won't receive any new
			 * event from it.
			 */
			if (err == -ENOENT) {
				err = 0;
				continue;
			} else {
				eprintk_ctx("Unable to resolve inotify mark path `%s': err = %d\n",
					    ie->cpt_wd_path, err);
				break;
			}
		}

		/*
		 * There one more weird scenarion is still possible.
		 *
		 * 	fd1 = create(name);
		 * 	inotify-add-watch(name)
		 * 	unlink(name)
		 * 	fd2 = create(name)
		 *	inotify-add-watch(name)
		 *
		 * The fd1 still pointing to deleted file entry
		 * and the mark is in chain, but no longer usable,
		 * so we should drop it from the list. Thus make
		 * sure the inode we've looked up to is exactly
		 * that the mark is pointing at.
		 */
		if (nd.path.dentry->d_inode != fse->inode) {
			path_put(&nd.path);
			continue;
		}

		cpt_open_object(NULL, ctx);

		wi.cpt_next = CPT_NULL;
		wi.cpt_object = CPT_OBJ_INOTIFY_WATCH;
		wi.cpt_hdrlen = sizeof(wi);
		wi.cpt_content = CPT_CONTENT_ARRAY;
		wi.cpt_wd = ie->wd;
		wi.cpt_mask = fse->mask;

		ctx->write(&wi, sizeof(wi), ctx);

		cpt_push_object(&saved_obj, ctx);

		err = dump_watch_inode(&nd.path, ctx);
		path_put(&nd.path);

		cpt_pop_object(&saved_obj, ctx);

		cpt_close_object(ctx);

		if (err)
			break;
	}

	return err;
}

static int cpt_dump_events(struct fsnotify_group *g, struct cpt_context *ctx)
{
	/* FIXME - implement */
	if (!list_empty(&g->notification_list))
		wprintk_ctx("Inotify events are lost. Sorry...\n");

	return 0;
}

int cpt_dump_inotify(cpt_object_t *obj, cpt_context_t *ctx)
{
	int err;
	struct file *file = obj->o_obj;
	struct fsnotify_group *group;
	struct cpt_inotify_image ii;
	loff_t saved_obj;

	if (file->f_op != &inotify_fops) {
		eprintk_ctx("bad inotify file\n");
		return -EINVAL;
	}

	group = file->private_data;
	if (unlikely(group == NULL)) {
		eprintk_ctx("bad inotify group\n");
		return -EINVAL;
	}

	if (group->inotify_data.fa != NULL) {
		eprintk_ctx("inotify with fasync\n");
		return -ENOTSUPP;
	}

	cpt_open_object(NULL, ctx);

	ii.cpt_next = CPT_NULL;
	ii.cpt_object = CPT_OBJ_INOTIFY;
	ii.cpt_hdrlen = sizeof(ii);
	ii.cpt_content = CPT_CONTENT_ARRAY;
	ii.cpt_file = obj->o_pos;
	ii.cpt_user = group->inotify_data.user->uid;
	ii.cpt_max_events = group->max_events;
	ii.cpt_last_wd = group->max_events;

	ctx->write(&ii, sizeof(ii), ctx);
	cpt_push_object(&saved_obj, ctx);

	err = cpt_dump_watches(group, ctx);
	if (err == 0)
		err = cpt_dump_events(group, ctx);

	cpt_pop_object(&saved_obj, ctx);
	cpt_close_object(ctx);

	return err;
}
