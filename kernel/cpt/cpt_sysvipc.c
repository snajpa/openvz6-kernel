/*
 *
 *  kernel/cpt/cpt_sysvipc.c
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
#include <linux/mount.h>
#include <linux/nsproxy.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/major.h>
#include <linux/pipe_fs_i.h>
#include <linux/mman.h>
#include <linux/shm.h>
#include <linux/sem.h>
#include <linux/msg.h>
#include <asm/uaccess.h>
#include <linux/cpt_image.h>

#include <linux/cpt_obj.h>
#include <linux/cpt_context.h>
#include "cpt_kernel.h"

struct _warg {
		struct file			*file;
		struct cpt_sysvshm_image	*v;
};

static int dump_one_shm(struct shmid_kernel *shp, void *arg)
{
	struct _warg *warg = arg;
	struct cpt_sysvshm_image *v = (struct cpt_sysvshm_image *)warg->v;

	if (shp->shm_file != warg->file)
		return 0;

	v->cpt_key = shp->shm_perm.key;
	v->cpt_uid = shp->shm_perm.uid;
	v->cpt_gid = shp->shm_perm.gid;
	v->cpt_cuid = shp->shm_perm.cuid;
	v->cpt_cgid = shp->shm_perm.cgid;
	v->cpt_mode = shp->shm_perm.mode;
	v->cpt_seq = shp->shm_perm.seq;

	v->cpt_id = shp->shm_perm.id;
	v->cpt_segsz = shp->shm_segsz;
	v->cpt_atime = shp->shm_atim;
	v->cpt_ctime = shp->shm_ctim;
	v->cpt_dtime = shp->shm_dtim;
	v->cpt_creator = shp->shm_cprid;
	v->cpt_last = shp->shm_lprid;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,9)
	v->cpt_mlockuser = shp->mlock_user ? shp->mlock_user->uid : -1;
#else
	v->cpt_mlockuser = -1;
#endif
	return 1;
}

int cpt_dump_content_sysvshm(struct file *file, struct cpt_context *ctx)
{
	struct cpt_sysvshm_image *v = cpt_get_buf(ctx);
	struct _warg warg;

	v->cpt_next = sizeof(*v);
	v->cpt_object = CPT_OBJ_SYSV_SHM;
	v->cpt_hdrlen = sizeof(*v);
	v->cpt_content = CPT_CONTENT_VOID;

	warg.file = file;
	warg.v = v;
	if (sysvipc_walk_shm(dump_one_shm, &warg) == 0) {
		cpt_release_buf(ctx);
		return -ESRCH;
	}

	ctx->write(v, sizeof(*v), ctx);
	cpt_release_buf(ctx);
	return 0;
}


int match_sem(int id, struct sem_array *sema, void *arg)
{
	if (id != (unsigned long)arg)
		return 0;
	return sema->sem_nsems + 1;
}

static int get_sem_nsem(int id, cpt_context_t *ctx)
{
	int res;
	res = sysvipc_walk_sem(match_sem, (void*)(unsigned long)id);
	if (res > 0)
		return res - 1;
	eprintk_ctx("get_sem_nsem: SYSV semaphore %d not found\n", id);
	return -ESRCH;
}

static int dump_one_semundo(struct sem_undo *su, struct cpt_context *ctx)
{
	struct cpt_sysvsem_undo_image v;
	loff_t saved_obj;

	cpt_open_object(NULL, ctx);

	v.cpt_next = CPT_NULL;
	v.cpt_object = CPT_OBJ_SYSVSEM_UNDO_REC;
	v.cpt_hdrlen = sizeof(v);
	v.cpt_content = CPT_CONTENT_SEMUNDO;
	v.cpt_id = su->semid;
	v.cpt_nsem = get_sem_nsem(su->semid, ctx);
	if ((int)v.cpt_nsem < 0)
		return -ESRCH;

	ctx->write(&v, sizeof(v), ctx);

	cpt_push_object(&saved_obj, ctx);
	ctx->write(su->semadj, v.cpt_nsem*sizeof(short), ctx);
	cpt_pop_object(&saved_obj, ctx);

	cpt_close_object(ctx);
	return 0;
}

struct sem_warg {
	int				last_id;
	struct cpt_sysvsem_image	*v;
};

static int dump_one_sem(int id, struct sem_array *sma, void *arg)
{
	struct sem_warg * warg = (struct sem_warg *)arg;
	struct cpt_sysvsem_image *v = warg->v;
	int i;

	if (warg->last_id != -1) {
		if ((id % IPCMNI) <= warg->last_id)
			return 0;
	}

	v->cpt_next = sizeof(*v);
	v->cpt_object = CPT_OBJ_SYSV_SEM;
	v->cpt_hdrlen = sizeof(*v);
	v->cpt_content = CPT_CONTENT_SEMARRAY;

	v->cpt_key = sma->sem_perm.key;
	v->cpt_uid = sma->sem_perm.uid;
	v->cpt_gid = sma->sem_perm.gid;
	v->cpt_cuid = sma->sem_perm.cuid;
	v->cpt_cgid = sma->sem_perm.cgid;
	v->cpt_mode = sma->sem_perm.mode;
	v->cpt_seq = sma->sem_perm.seq;

	v->cpt_id = id;
	v->cpt_ctime = sma->sem_ctime;
	v->cpt_otime = sma->sem_otime;

	for (i=0; i<sma->sem_nsems; i++) {
		struct {
			__u32 semval;
			__u32 sempid;
		} *s = (void*)v + v->cpt_next;
		if (v->cpt_next >= PAGE_SIZE - sizeof(*s))
			return -EINVAL;
		s->semval = sma->sem_base[i].semval;
		s->sempid = sma->sem_base[i].sempid;
		v->cpt_next += sizeof(*s);
	}

	warg->last_id = id % IPCMNI;
	return 1;
}


int cpt_dump_sysvsem(struct cpt_context *ctx)
{
	cpt_object_t *obj;
	struct sem_warg warg;

	/* Dumping semaphores is quite tricky because we cannot
	 * write to dump file under lock inside sysvipc_walk_sem().
	 */
	cpt_open_section(ctx, CPT_SECT_SYSV_SEM);
	warg.last_id = -1;
	warg.v = cpt_get_buf(ctx);
	for (;;) {
		if (sysvipc_walk_sem(dump_one_sem, &warg) <= 0)
			break;
		ctx->write(warg.v, warg.v->cpt_next, ctx);
	}
	cpt_release_buf(ctx);
	cpt_close_section(ctx);

	cpt_open_section(ctx, CPT_SECT_SYSVSEM_UNDO);
	for_each_object(obj, CPT_OBJ_SYSVSEM_UNDO) {
		struct sem_undo_list *semu = obj->o_obj;
		struct sem_undo *su;
		struct cpt_object_hdr v;
		loff_t saved_obj;

		cpt_open_object(obj, ctx);

		v.cpt_next = CPT_NULL;
		v.cpt_object = CPT_OBJ_SYSVSEM_UNDO;
		v.cpt_hdrlen = sizeof(v);
		v.cpt_content = CPT_CONTENT_ARRAY;

		ctx->write(&v, sizeof(v), ctx);

		cpt_push_object(&saved_obj, ctx);
		list_for_each_entry(su, &semu->list_proc, list_proc) {
			if (su->semid != -1) {
				int err;
				err = dump_one_semundo(su, ctx);
				if (err < 0)
					return err;
			}
		}
		cpt_pop_object(&saved_obj, ctx);

		cpt_close_object(ctx);
	}
	cpt_close_section(ctx);
	return 0;
}

struct msg_warg {
	int				last_id;
	struct msg_queue		*msq;
	struct cpt_sysvmsg_image	*v;
};

static int dump_one_msg(int id, struct msg_queue *msq, void *arg)
{
	struct msg_warg * warg = (struct msg_warg *)arg;
	struct cpt_sysvmsg_image *v = warg->v;

	if (warg->last_id != -1) {
		if ((id % IPCMNI) <= warg->last_id)
			return 0;
	}

	v->cpt_next = sizeof(*v);
	v->cpt_object = CPT_OBJ_SYSVMSG;
	v->cpt_hdrlen = sizeof(*v);
	v->cpt_content = CPT_CONTENT_ARRAY;

	v->cpt_key = msq->q_perm.key;
	v->cpt_uid = msq->q_perm.uid;
	v->cpt_gid = msq->q_perm.gid;
	v->cpt_cuid = msq->q_perm.cuid;
	v->cpt_cgid = msq->q_perm.cgid;
	v->cpt_mode = msq->q_perm.mode;
	v->cpt_seq = msq->q_perm.seq;

	v->cpt_id = id;
	v->cpt_stime = msq->q_stime;
	v->cpt_rtime = msq->q_rtime;
	v->cpt_ctime = msq->q_ctime;
	v->cpt_last_sender = msq->q_lspid;
	v->cpt_last_receiver = msq->q_lrpid;
	v->cpt_qbytes = msq->q_qbytes;

	warg->msq = msq;
	warg->last_id = id % IPCMNI;
	return 1;
}

static int do_store(void * src, int len, int offset, void * data)
{
	cpt_context_t * ctx = data;
	ctx->write(src, len, ctx);
	return 0;
}

static void cpt_dump_one_sysvmsg(struct msg_msg *m, cpt_context_t * ctx)
{
	loff_t saved_obj;
	struct cpt_sysvmsg_msg_image mv;
			
	cpt_open_object(NULL, ctx);
	mv.cpt_next = CPT_NULL;
	mv.cpt_object = CPT_OBJ_SYSVMSG_MSG;
	mv.cpt_hdrlen = sizeof(mv);
	mv.cpt_content = CPT_CONTENT_DATA;

	mv.cpt_type = m->m_type;
	mv.cpt_size = m->m_ts;

	ctx->write(&mv, sizeof(mv), ctx);

	cpt_push_object(&saved_obj, ctx);
	sysv_msg_store(m, do_store, m->m_ts, ctx);
	cpt_pop_object(&saved_obj, ctx);
	cpt_close_object(ctx);
}

int cpt_dump_sysvmsg(struct cpt_context *ctx)
{
	struct msg_warg warg;

	/* Dumping msg queues is tricky because we cannot
	 * write to dump file under lock inside sysvipc_walk_msg().
	 *
	 * And even worse, we have to access msg list in an unserialized
	 * context. It is fragile. But VE is still frozen, remember?
	 */
	cpt_open_section(ctx, CPT_SECT_SYSV_MSG);
	warg.last_id = -1;
	warg.v = cpt_get_buf(ctx);
	for (;;) {
		loff_t saved_obj;
		struct msg_msg * m;

		if (sysvipc_walk_msg(dump_one_msg, &warg) <= 0)
			break;

		cpt_open_object(NULL, ctx);

		ctx->write(warg.v, warg.v->cpt_next, ctx);

		cpt_push_object(&saved_obj, ctx);
		list_for_each_entry(m, &warg.msq->q_messages, m_list) {
			cpt_dump_one_sysvmsg(m, ctx);
		}
		cpt_pop_object(&saved_obj, ctx);

		cpt_close_object(ctx);
	}
	cpt_release_buf(ctx);
	cpt_close_section(ctx);
	return 0;
}

static int cpt_collect_sysvsem_undo(cpt_context_t *ctx)
{
	cpt_object_t *obj;

	for_each_object(obj, CPT_OBJ_TASK) {
		struct task_struct *tsk = obj->o_obj;
		if (tsk->exit_state) {
			/* ipc/sem.c forgets to clear tsk->sysvsem.undo_list
			 * on exit. Grrr... */
			continue;
		}
		if (tsk->sysvsem.undo_list &&
		    cpt_object_add(CPT_OBJ_SYSVSEM_UNDO, tsk->sysvsem.undo_list, ctx) == NULL)
			return -ENOMEM;
	}

	for_each_object(obj, CPT_OBJ_SYSVSEM_UNDO) {
		struct sem_undo_list *semu = obj->o_obj;

		if (atomic_read(&semu->refcnt) != obj->o_count) {
			eprintk_ctx("sem_undo_list is referenced outside %d %d\n", obj->o_count, atomic_read(&semu->refcnt));
			return -EBUSY;
		}
	}
	return 0;
}

static int collect_one_shm(struct shmid_kernel *shp, void *arg)
{
	cpt_context_t *ctx = arg;
	cpt_object_t *obj;

	obj = __cpt_object_add(CPT_OBJ_FILE, shp->shm_file, GFP_ATOMIC, ctx);
	if (!obj)
		return -ENOMEM;
	obj->o_flags |= CPT_FILE_SYSVIPC;
	return 0;
}

int cpt_collect_sysvshm(cpt_context_t * ctx)
{
	int err;

	err = sysvipc_walk_shm(collect_one_shm, ctx);

	return err < 0 ? err : 0;
}

static int cpt_check_posix_mqueue(cpt_context_t * ctx)
{
	struct ipc_namespace *ipc_ns = current->nsproxy->ipc_ns;

	if (!list_is_singular(&ipc_ns->mq_mnt->mnt_sb->s_inodes)) {
		eprintk_ctx("posix message queues are not supported\n");
		return -EBUSY;
	}

	return 0;
}

int cpt_collect_sysv(cpt_context_t * ctx)
{
	int err;

	err = cpt_check_posix_mqueue(ctx);
	if (err)
		return err;
	err = cpt_collect_sysvsem_undo(ctx);
	if (err)
		return err;
	err = cpt_collect_sysvshm(ctx);
	if (err)
		return err;

	return 0;
}
