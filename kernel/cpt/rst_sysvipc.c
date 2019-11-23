/*
 *
 *  kernel/cpt/rst_sysvipc.c
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
#include <linux/nsproxy.h>
#include <linux/errno.h>
#include <linux/major.h>
#include <linux/pipe_fs_i.h>
#include <linux/mman.h>
#include <linux/shm.h>
#include <linux/msg.h>
#include <linux/mount.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <bc/kmem.h>
#include <linux/cpt_image.h>
#include <linux/init_task.h>

#include <linux/cpt_obj.h>
#include <linux/cpt_context.h>
#include "cpt_kernel.h"
#include "cpt_mm.h"

struct _warg {
		struct file		*file;
		struct cpt_sysvshm_image	*v;
};

static int fixup_one_shm(struct shmid_kernel *shp, void *arg)
{
	struct _warg *warg = arg;

	if (shp->shm_file != warg->file)
		return 0;
	if (shp->shm_nattch)
		return -EEXIST;

	shp->shm_perm.uid = warg->v->cpt_uid;
	shp->shm_perm.gid = warg->v->cpt_gid;
	shp->shm_perm.cuid = warg->v->cpt_cuid;
	shp->shm_perm.cgid = warg->v->cpt_cgid;
	shp->shm_perm.mode = warg->v->cpt_mode;

	shp->shm_atim = warg->v->cpt_atime;
	shp->shm_dtim = warg->v->cpt_dtime;
	shp->shm_ctim = warg->v->cpt_ctime;
	shp->shm_cprid = warg->v->cpt_creator;
	shp->shm_lprid = warg->v->cpt_last;

	/* TODO: fix shp->mlock_user? */
	return 1;
}

static int fixup_shm(struct file *file, struct cpt_sysvshm_image *v)
{
	struct _warg warg;

	warg.file = file;
	warg.v = v;

	return sysvipc_walk_shm(fixup_one_shm, &warg);
}

static int restore_shm_chunk(struct file *file, loff_t pos,
		struct cpt_page_block * pgb, cpt_context_t *ctx)
{
	int err;
	loff_t opos;
	loff_t ipos;
	int count;

	ipos = pos + pgb->cpt_hdrlen;
	opos = pgb->cpt_start;
	count = pgb->cpt_end-pgb->cpt_start;
	while (count > 0) {
		mm_segment_t oldfs;
		int copy = count;

		if (copy > PAGE_SIZE)
			copy = PAGE_SIZE;
		(void)cpt_get_buf(ctx);
		oldfs = get_fs(); set_fs(KERNEL_DS);
		err = ctx->pread(ctx->tmpbuf, copy, ctx, ipos);
		set_fs(oldfs);
		if (err) {
			__cpt_release_buf(ctx);
			return err;
		}
		oldfs = get_fs(); set_fs(KERNEL_DS);
		ipos += copy;
		err = file->f_dentry->d_inode->i_fop->write(file, ctx->tmpbuf,
								copy, &opos);
		set_fs(oldfs);
		__cpt_release_buf(ctx);
		if (err != copy) {
			eprintk_ctx("%s: write() failure - copy: %d, opos: %Ld\n",
					__func__, copy, opos);
			if (err >= 0)
				err = -EIO;
			return err;
		}
		count -= copy;
	}
	return 0;
}

static int fixup_shm_data(struct file *file, loff_t pos, loff_t end,
			  struct cpt_context *ctx)
{
	struct cpt_page_block pgb;

	if (file->f_dentry->d_inode->i_fop->write == NULL) {
		eprintk_ctx("No TMPFS? Cannot restore content of SYSV SHM\n");
		return -EINVAL;
	}

	while (pos < end) {
		int err;

		err = rst_get_object(-1, pos, &pgb, ctx);
		if (err)
			return err;
		dprintk_ctx("restoring SHM block: %08x-%08x\n",
		       (__u32)pgb.cpt_start, (__u32)pgb.cpt_end);

		switch (pgb.cpt_object) {
			case CPT_OBJ_PAGES:
				err = restore_shm_chunk(file, pos, &pgb, ctx);
				if (err) {
					eprintk_ctx("%s: restore_shm_chunk failed\n", __func__);
					return err;
				}
				break;
#ifdef CONFIG_VZ_CHECKPOINT_ITER
			case CPT_OBJ_ITERPAGES:
			case CPT_OBJ_ITERYOUNGPAGES:
				err = rst_iter_chunk(file, pos, &pgb, ctx);
				if (err)
					return err;
				break;
#endif
			default:
				eprintk_ctx("unsupported page type: %d.\n",
							pgb.cpt_object);
				return -EINVAL;
		}


		pos += pgb.cpt_next;
	}
	return 0;
}

struct file * rst_sysv_shm_itself(loff_t pos, struct cpt_context *ctx)
{
	struct file *file;
	int err;
	loff_t dpos, epos;
	union {
		struct cpt_file_image		fi;
		struct cpt_sysvshm_image	shmi;
		struct cpt_inode_image 		ii;
	} u;
	const struct cred *curr_cred;

	err = rst_get_object(CPT_OBJ_FILE, pos, &u.fi, ctx);
	if (err < 0)
		goto err_out;
	pos = u.fi.cpt_inode;
	err = rst_get_object(CPT_OBJ_INODE, pos, &u.ii, ctx);
	if (err < 0)
		goto err_out;
	dpos = pos + u.ii.cpt_hdrlen;
	epos = pos + u.ii.cpt_next;
	err = rst_get_object(CPT_OBJ_SYSV_SHM, pos + u.ii.cpt_hdrlen, &u.shmi, ctx);
	if (err < 0)
		goto err_out;
	dpos += u.shmi.cpt_next;

	curr_cred = override_creds(get_exec_env()->init_cred);
	file = sysvipc_setup_shm(u.shmi.cpt_key, u.shmi.cpt_id,
				 u.shmi.cpt_segsz, u.shmi.cpt_mode);
	revert_creds(curr_cred);
	if (!IS_ERR(file)) {
		err = fixup_shm(file, &u.shmi);
		if (err != -EEXIST && dpos < epos) {
			err = fixup_shm_data(file, dpos, epos, ctx);
			if (err) {
				eprintk_ctx("%s: fixup_shm_data failed: %d\n",
						__func__, err);
				goto err_put;
			}
		}
	} else if (IS_ERR(file) && PTR_ERR(file) == -EEXIST) {
		struct ipc_namespace *ipc_ns = current->nsproxy->ipc_ns;
		struct shmid_kernel *shp;

		shp = shm_lock(ipc_ns, u.shmi.cpt_id);
		BUG_ON(IS_ERR(shp));
		get_file(shp->shm_file);
		file = shp->shm_file;
		shm_unlock(shp);
	} else
		eprintk_ctx("%s: sysvipc setup failed: %ld (key: %Ld)\n",
				__func__, PTR_ERR(file), u.shmi.cpt_key);
	return file;

err_put:
	fput(file);
err_out:
	return ERR_PTR(err);
}

struct file * rst_sysv_shm_vma(struct cpt_vma_image *vmai, struct cpt_context *ctx)
{
	struct ipc_namespace *ipc_ns = current->nsproxy->ipc_ns;
	struct file *file;
	union {
		struct cpt_file_image		fi;
		struct cpt_inode_image		ii;
		struct cpt_sysvshm_image	shmi;
	} u;
	struct shmid_kernel *shp;
	struct shm_file_data *sfd;
	struct path path;
	mode_t f_mode;
	loff_t pos;
	int err;

	pos = vmai->cpt_file;
	file = rst_sysv_shm_itself(pos, ctx);
	if (IS_ERR(file) && PTR_ERR(file) != -EEXIST) {
		eprintk_ctx("%s: rst_sysv_shm_itself failed: %ld\n",
				__func__, PTR_ERR(file));
		return file;
	}
	fput(file);

	err = rst_get_object(CPT_OBJ_FILE, pos, &u.fi, ctx);
	if (err < 0)
		goto err_out;
	pos = u.fi.cpt_inode;
	err = rst_get_object(CPT_OBJ_INODE, pos, &u.ii, ctx);
	if (err < 0)
		goto err_out;
	err = rst_get_object(CPT_OBJ_SYSV_SHM, pos + u.ii.cpt_hdrlen, &u.shmi, ctx);
	if (err < 0)
		goto err_out;

	shp = shm_lock(ipc_ns, u.shmi.cpt_id);
	BUG_ON(IS_ERR(shp));
	path = shp->shm_file->f_path;
	path_get(&shp->shm_file->f_path);
	shm_unlock(shp);

	err = -ENOMEM;
	sfd = kzalloc(sizeof(*sfd), GFP_KERNEL);
	if (!sfd)
		goto out_put_dentry;

	f_mode = 0;
	if (vmai->cpt_flags & VM_READ)
		f_mode |= FMODE_READ;
	if (vmai->cpt_flags & VM_WRITE)
		f_mode |= FMODE_WRITE;
	if (vmai->cpt_flags & VM_EXEC)
		f_mode |= FMODE_EXEC;

	err = -ENOMEM;
	file = alloc_file(&path, f_mode, &shm_file_operations);
	if (!file)
		goto out_free;

	file->private_data = sfd;
	file->f_mapping = shp->shm_file->f_mapping;
	sfd->id = shp->shm_perm.id;
	sfd->ns = get_ipc_ns(ipc_ns);
	sfd->file = shp->shm_file;
	sfd->vm_ops = NULL;

	return file;

out_free:
	kfree(sfd);
out_put_dentry:
	path_put(&path);
err_out:
	return ERR_PTR(err);
}

static int attach_one_undo(int semid, struct sem_array *sma, void *arg)
{
	struct sem_undo *su = arg;
	struct sem_undo_list *undo_list = current->sysvsem.undo_list;

	if (semid != su->semid)
		return 0;

	spin_lock(&undo_list->lock);
	su->ulp = undo_list;
	list_add(&su->list_proc, &undo_list->list_proc);
	list_add(&su->list_id, &sma->list_id);
	spin_unlock(&undo_list->lock);

	return 1;
}

static int attach_undo(struct sem_undo *su)
{
	return sysvipc_walk_sem(attach_one_undo, su);
}

static int do_rst_semundo(struct cpt_object_hdr *sui, loff_t pos, struct cpt_context *ctx)
{
	int err;
	struct sem_undo_list *undo_list;

	if (current->sysvsem.undo_list) {
		eprintk_ctx("Funny undo_list\n");
		return 0;
	}

	undo_list = kzalloc(sizeof(struct sem_undo_list), GFP_KERNEL_UBC);
	if (undo_list == NULL)
		return -ENOMEM;

	atomic_set(&undo_list->refcnt, 1);
	spin_lock_init(&undo_list->lock);
	INIT_LIST_HEAD(&undo_list->list_proc);
	current->sysvsem.undo_list = undo_list;

	if (sui->cpt_next > sui->cpt_hdrlen) {
		loff_t offset = pos + sui->cpt_hdrlen;
		do {
			struct sem_undo *new;
			struct cpt_sysvsem_undo_image spi;
			err = rst_get_object(CPT_OBJ_SYSVSEM_UNDO_REC, offset, &spi, ctx);
			if (err)
				goto out;
			new = kmalloc(sizeof(struct sem_undo) +
					sizeof(short)*spi.cpt_nsem,
					GFP_KERNEL_UBC);
			if (!new) {
				err = -ENOMEM;
				goto out;
			}

			memset(new, 0, sizeof(struct sem_undo) + sizeof(short)*spi.cpt_nsem);
			new->semadj = (short *) &new[1];
			new->semid = spi.cpt_id;
			err = ctx->pread(new->semadj, spi.cpt_nsem*sizeof(short), ctx, offset + spi.cpt_hdrlen);
			if (err) {
				kfree(new);
				goto out;
			}
			err = attach_undo(new);
			if (err <= 0) {
				if (err == 0)
					err = -ENOENT;
				kfree(new);
				goto out;
			}
			offset += spi.cpt_next;
		} while (offset < pos + sui->cpt_next);
	}
	err = 0;

out:
	return err;
}

__u32 rst_semundo_flag(struct cpt_task_image *ti, struct cpt_context *ctx)
{
	__u32 flag = 0;

#if 0
	if (ti->cpt_sysvsem_undo == CPT_NULL ||
	    lookup_cpt_obj_bypos(CPT_OBJ_SYSVSEM_UNDO, ti->cpt_sysvsem_undo))
		flag |= CLONE_SYSVSEM;
#endif
	return flag;
}

int rst_semundo_complete(struct cpt_task_image *ti, struct cpt_context *ctx)
{
	int err;
	struct sem_undo_list *f = current->sysvsem.undo_list;
	cpt_object_t *obj;
	struct cpt_object_hdr sui;

	if (ti->cpt_sysvsem_undo == CPT_NULL) {
		exit_sem(current);
		return 0;
	}

	obj = lookup_cpt_obj_bypos(CPT_OBJ_SYSVSEM_UNDO, ti->cpt_sysvsem_undo, ctx);
	if (obj) {
		if (obj->o_obj != f) {
			exit_sem(current);
			f = obj->o_obj;
			atomic_inc(&f->refcnt);
			current->sysvsem.undo_list = f;
		}
		return 0;
	}

	if ((err = rst_get_object(CPT_OBJ_SYSVSEM_UNDO, ti->cpt_sysvsem_undo, &sui, ctx)) != 0)
		goto out;

	if ((err = do_rst_semundo(&sui, ti->cpt_sysvsem_undo, ctx)) != 0)
		goto out;

	err = -ENOMEM;
	obj = cpt_object_add(CPT_OBJ_SYSVSEM_UNDO, f, ctx);
	if (obj) {
		err = 0;
		cpt_obj_setpos(obj, ti->cpt_sysvsem_undo, ctx);
	}

	return 0;

out:
	return err;
}

struct _sarg {
	int semid;
	struct cpt_sysvsem_image	*v;
	__u32				*arr;
};

static int fixup_one_sem(int semid, struct sem_array *sma, void *arg)
{
	struct _sarg *warg = arg;

	if (semid != warg->semid)
		return 0;

	sma->sem_perm.uid = warg->v->cpt_uid;
	sma->sem_perm.gid = warg->v->cpt_gid;
	sma->sem_perm.cuid = warg->v->cpt_cuid;
	sma->sem_perm.cgid = warg->v->cpt_cgid;
	sma->sem_perm.mode = warg->v->cpt_mode;
	sma->sem_perm.seq = warg->v->cpt_seq;

	sma->sem_ctime = warg->v->cpt_ctime;
	sma->sem_otime = warg->v->cpt_otime;
	{
		int i;
		struct {
			__u32 semval;
			__u32 sempid;
		} *s = (void*)warg->arr;

		for (i=0; i < sma->sem_nsems; i++) {
			sma->sem_base[i].semval = s[i].semval;
			sma->sem_base[i].sempid = s[i].sempid;
		}
	}
	return 1;
}

static int fixup_sem(int semid, struct cpt_sysvsem_image *v, __u32 *arr)
{
	struct _sarg warg;

	warg.semid = semid;
	warg.v = v;
	warg.arr = arr;

	return sysvipc_walk_sem(fixup_one_sem, &warg);
}


static int restore_sem(loff_t pos, struct cpt_sysvsem_image *si,
		       struct cpt_context *ctx)
{
	int err;
	__u32 *arr;
	int nsems = (si->cpt_next - si->cpt_hdrlen)/8;

	arr = kmalloc(nsems*8, GFP_KERNEL);
	if (!arr)
		return -ENOMEM;

	err = ctx->pread(arr, nsems*8, ctx, pos+si->cpt_hdrlen);
	if (err)
		goto out;
	err = sysvipc_setup_sem(si->cpt_key, si->cpt_id, nsems, si->cpt_mode);
	if (err < 0) {
		eprintk_ctx("SEM 3\n");
		goto out;
	}
	err = fixup_sem(si->cpt_id, si, arr);
	if (err == 0)
		err = -ESRCH;
	if (err > 0)
		err = 0;
out:
	kfree(arr);
	return err;
}

static int rst_sysv_sem(struct cpt_context *ctx)
{
	int err;
	loff_t sec = ctx->sections[CPT_SECT_SYSV_SEM];
	loff_t endsec;
	struct cpt_section_hdr h;
	struct cpt_sysvsem_image sbuf;

	if (sec == CPT_NULL)
		return 0;

	err = ctx->pread(&h, sizeof(h), ctx, sec);
	if (err)
		return err;
	if (h.cpt_section != CPT_SECT_SYSV_SEM || h.cpt_hdrlen < sizeof(h))
		return -EINVAL;

	endsec = sec + h.cpt_next;
	sec += h.cpt_hdrlen;
	while (sec < endsec) {
		int err;
		err = rst_get_object(CPT_OBJ_SYSV_SEM, sec, &sbuf, ctx);
		if (err)
			return err;
		err = restore_sem(sec, &sbuf, ctx);
		if (err)
			return err;
		sec += sbuf.cpt_next;
	}
	return 0;
}

struct _marg {
	int				msqid;
	struct cpt_sysvmsg_image	*v;
	struct msg_queue		*m;
};

static int fixup_one_msg(int msqid, struct msg_queue *msq, void *arg)
{
	struct _marg *warg = arg;

	if (msqid != warg->msqid)
		return 0;

	msq->q_perm.uid = warg->v->cpt_uid;
	msq->q_perm.gid = warg->v->cpt_gid;
	msq->q_perm.cuid = warg->v->cpt_cuid;
	msq->q_perm.cgid = warg->v->cpt_cgid;
	msq->q_perm.mode = warg->v->cpt_mode;
	msq->q_perm.seq = warg->v->cpt_seq;

	msq->q_stime = warg->v->cpt_stime;
	msq->q_rtime = warg->v->cpt_rtime;
	msq->q_ctime = warg->v->cpt_ctime;
	msq->q_lspid = warg->v->cpt_last_sender;
	msq->q_lrpid = warg->v->cpt_last_receiver;
	msq->q_qbytes = warg->v->cpt_qbytes;

	warg->m = msq;
	return 1;
}

struct _larg
{
	cpt_context_t * ctx;
	loff_t		pos;
};

static int do_load_msg(void * dst, int len, int offset, void * data)
{
	struct _larg * arg = data;
	return arg->ctx->pread(dst, len, arg->ctx, arg->pos + offset);
}

static int fixup_msg(int msqid, struct cpt_sysvmsg_image *v, loff_t pos,
		     cpt_context_t * ctx)
{
	int err;
	struct _marg warg;
	loff_t endpos = pos + v->cpt_next;
	struct ipc_namespace *ns = current->nsproxy->ipc_ns;

	pos += v->cpt_hdrlen;

	warg.msqid = msqid;
	warg.v = v;

	err = sysvipc_walk_msg(fixup_one_msg, &warg);
	if (err <= 0)
		return err;

	while (pos < endpos) {
		struct cpt_sysvmsg_msg_image mi;
		struct msg_msg *m;
		struct _larg data = {
			.ctx = ctx
		};

		err = rst_get_object(CPT_OBJ_SYSVMSG_MSG, pos, &mi, ctx);
		if (err)
			return err;
		data.pos = pos + mi.cpt_hdrlen;
		m = sysv_msg_load(do_load_msg, mi.cpt_size, &data);
		if (IS_ERR(m))
			return PTR_ERR(m);
		m->m_type = mi.cpt_type;
		m->m_ts = mi.cpt_size;
		list_add_tail(&m->m_list, &warg.m->q_messages);
		warg.m->q_cbytes += m->m_ts;
		warg.m->q_qnum++;
		atomic_add(m->m_ts, &ns->msg_bytes);
		atomic_inc(&ns->msg_hdrs);
			
		pos += mi.cpt_next;
	}
	return 1;
}

static int restore_msg(loff_t pos, struct cpt_sysvmsg_image *si,
		       struct cpt_context *ctx)
{
	int err;

	err = sysvipc_setup_msg(si->cpt_key, si->cpt_id, si->cpt_mode);
	if (err < 0) {
		eprintk_ctx("MSG 3\n");
		goto out;
	}
	err = fixup_msg(si->cpt_id, si, pos, ctx);
	if (err == 0)
		err = -ESRCH;
	if (err > 0)
		err = 0;
out:
	return err;
}

static int rst_sysv_msg(struct cpt_context *ctx)
{
	int err;
	loff_t sec = ctx->sections[CPT_SECT_SYSV_MSG];
	loff_t endsec;
	struct cpt_section_hdr h;
	struct cpt_sysvmsg_image sbuf;

	if (sec == CPT_NULL)
		return 0;

	err = ctx->pread(&h, sizeof(h), ctx, sec);
	if (err)
		return err;
	if (h.cpt_section != CPT_SECT_SYSV_MSG || h.cpt_hdrlen < sizeof(h))
		return -EINVAL;

	endsec = sec + h.cpt_next;
	sec += h.cpt_hdrlen;
	while (sec < endsec) {
		int err;
		err = rst_get_object(CPT_OBJ_SYSVMSG, sec, &sbuf, ctx);
		if (err)
			return err;
		err = restore_msg(sec, &sbuf, ctx);
		if (err)
			return err;
		sec += sbuf.cpt_next;
	}
	return 0;
}


int rst_sysv_ipc(struct cpt_context *ctx)
{
	int err;

	err = rst_sysv_sem(ctx);
	if (!err)
		err = rst_sysv_msg(ctx);

	return err;
}
