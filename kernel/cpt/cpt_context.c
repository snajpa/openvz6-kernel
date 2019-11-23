/*
 *
 *  kernel/cpt/cpt_context.c
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
#include <linux/pagemap.h>

#include <linux/cpt_image.h>
#include <linux/cpt_export.h>

#include <linux/cpt_obj.h>
#include <linux/cpt_context.h>

#ifdef CONFIG_PRAM
struct cpt_pram_ops *cpt_pram_ops;
EXPORT_SYMBOL(cpt_pram_ops);

int cpt_open_pram(cpt_context_t *ctx)
{
	int err = -ENOSYS;

	if (cpt_pram_ops)
		err = cpt_pram_ops->cpt_open(ctx);
	if (err)
		eprintk_ctx("cpt_open_pram: %d\n", err);
	return err;
}

void cpt_close_pram(cpt_context_t *ctx, int err)
{
	if (cpt_pram_ops)
		cpt_pram_ops->cpt_close(ctx, err);
}

void cpt_dump_pram(struct vm_area_struct *vma,
		unsigned long start, unsigned long end,
		struct cpt_context *ctx)
{
	int err = 0;

	if (cpt_pram_ops)
		err = cpt_pram_ops->cpt_dump(vma, start, end, ctx);
	if (err)
		eprintk_ctx("cpt_dump_pram: %d\n", err);
}
#endif

static int check_dumpsize(struct cpt_context *ctx, size_t count, loff_t pos)
{
	if (pos + count > ctx->dumpsize)
		ctx->dumpsize = pos + count;
	if (ctx->maxdumpsize && ctx->dumpsize > ctx->maxdumpsize) {
		ctx->write_error = -ENOSPC;
		return 0;
	}
	return 1;
}

static void file_write(const void *addr, size_t count, struct cpt_context *ctx)
{
	mm_segment_t oldfs;
	ssize_t err = -EBADF;
	struct file *file = ctx->file;

	if (file && !check_dumpsize(ctx, count, file->f_pos))
		return;

	oldfs = get_fs(); set_fs(KERNEL_DS);
	if (file)
		err = file->f_op->write(file, addr, count, &file->f_pos);
	set_fs(oldfs);
	if (err != count && !ctx->write_error)
		ctx->write_error = err < 0 ? err : -EIO;
}

static void file_pwrite(void *addr, size_t count, struct cpt_context *ctx, loff_t pos)
{
	mm_segment_t oldfs;
	ssize_t err = -EBADF;
	struct file *file = ctx->file;

	if (file && !check_dumpsize(ctx, count, pos))
		return;

	oldfs = get_fs(); set_fs(KERNEL_DS);
	if (file)
		err = file->f_op->write(file, addr, count, &pos);
	set_fs(oldfs);
	if (err != count && !ctx->write_error)
		ctx->write_error = err < 0 ? err : -EIO;
}

static void file_align(struct cpt_context *ctx)
{
	struct file *file = ctx->file;

	if (file)
		file->f_pos = CPT_ALIGN(file->f_pos);
}

static void cpt_push(loff_t *p, struct cpt_context *ctx)
{
	cpt_push_object(p, ctx);
	cpt_open_object(NULL, ctx);
}

static void cpt_pop(loff_t *p, struct cpt_context *ctx)
{
	cpt_close_object(ctx);
	cpt_pop_object(p, ctx);
}

static loff_t lookup_cpt_object_pos(int type, void *p, struct cpt_context *ctx)
{
	cpt_object_t *obj;

	obj = lookup_cpt_object(type, p, ctx);
	return obj->o_pos;
}

struct cpt_ops cpt_ops = {
	.write = file_write,
	.push_object = cpt_push,
	.pop_object = cpt_pop,
	.lookup_object = lookup_cpt_object_pos,
};

void cpt_context_init(struct cpt_context *ctx)
{
	int i;

	memset(ctx, 0, sizeof(*ctx));

	init_MUTEX(&ctx->main_sem);
	ctx->refcount = 1;

	ctx->current_section = -1;
	ctx->current_object = -1;
	ctx->pagesize = PAGE_SIZE;
	ctx->write = file_write;
	ctx->pwrite = file_pwrite;
	ctx->align = file_align;
	for (i=0; i < CPT_SECT_MAX; i++)
		ctx->sections[i] = CPT_NULL;
	cpt_object_init(ctx);
}

int cpt_open_dumpfile(struct cpt_context *ctx)
{
	if (ctx->file)
		ctx->maxdumpsize = i_size_read(ctx->file->f_mapping->host);
	ctx->tmpbuf = (char*)__get_free_page(GFP_KERNEL);
	if (ctx->tmpbuf == NULL)
		return -ENOMEM;
	__cpt_release_buf(ctx);
	return 0;
}

int cpt_close_dumpfile(struct cpt_context *ctx)
{
	if (ctx->file) {
		WARN_ON(i_size_read(ctx->file->f_mapping->host) != ctx->dumpsize);
		fput(ctx->file);
		ctx->file = NULL;
	}
	if (ctx->tmpbuf) {
		free_page((unsigned long)ctx->tmpbuf);
		ctx->tmpbuf = NULL;
	}
	if (ctx->write_error)
		eprintk_ctx("error while writing dump file: %d\n", ctx->write_error);
	return ctx->write_error;
}

int cpt_major_hdr_out(struct cpt_context *ctx)
{
	struct cpt_major_hdr hdr;

	if (ctx->file == NULL)
		return 0;

	memset(&hdr, 0, sizeof(hdr));
	hdr.cpt_signature[0] = CPT_SIGNATURE0;
	hdr.cpt_signature[1] = CPT_SIGNATURE1;
	hdr.cpt_signature[2] = CPT_SIGNATURE2;
	hdr.cpt_signature[3] = CPT_SIGNATURE3;
	hdr.cpt_hdrlen = sizeof(hdr);
	hdr.cpt_image_version = CPT_CURRENT_VERSION;
#ifdef CONFIG_X86_64
	hdr.cpt_os_arch = CPT_OS_ARCH_EMT64;
#elif defined(CONFIG_X86_32)
	hdr.cpt_os_arch = CPT_OS_ARCH_I386;
#elif defined(CONFIG_IA64)
	hdr.cpt_os_arch = CPT_OS_ARCH_IA64;
#else
#error	Arch is not supported
#endif
	hdr.cpt_ve_features = (__u32)ctx->features;
	hdr.cpt_ve_features2 = (__u32)(ctx->features>>32);
	hdr.cpt_pagesize = (__u16)PAGE_SIZE;
	hdr.cpt_hz = HZ;
	hdr.cpt_start_jiffies64 = ctx->virt_jiffies64;
	hdr.cpt_start_sec = ctx->start_time.tv_sec;
	hdr.cpt_start_nsec = ctx->start_time.tv_nsec;
	hdr.cpt_cpu_caps[0] = ctx->src_cpu_flags;
	hdr.cpt_kernel_config[0] = ctx->kernel_config_flags;
	hdr.cpt_iptables_mask = ctx->iptables_mask;

	ctx->write(&hdr, sizeof(hdr), ctx);
	return 0;
}

int cpt_close_section(struct cpt_context *ctx)
{
	if (ctx->file && ctx->current_section >= 0) {
		__u64 next = ctx->file->f_pos - ctx->current_section;
		ctx->pwrite(&next, 8, ctx, ctx->current_section);
		ctx->current_section = -1;
	}
	return 0;
}
EXPORT_SYMBOL(cpt_close_section);

int cpt_open_section(struct cpt_context *ctx, __u32 type)
{
	struct cpt_section_hdr hdr;

	if (ctx->file == NULL)
		return 0;

	cpt_close_section(ctx);

	ctx->current_section = ctx->file->f_pos;
	ctx->sections[type] = ctx->current_section;

	hdr.cpt_next = 0;
	hdr.cpt_section = type;
	hdr.cpt_hdrlen = sizeof(hdr);
	hdr.cpt_align = 0;
	ctx->write(&hdr, sizeof(hdr), ctx);

	return 0;
}
EXPORT_SYMBOL(cpt_open_section);


int cpt_close_object(struct cpt_context *ctx)
{
	if (ctx->file && ctx->current_object >= 0) {
		__u64 next = ctx->file->f_pos - ctx->current_object;
		ctx->pwrite(&next, 8, ctx, ctx->current_object);
		ctx->current_object = -1;
	}
	return 0;
}
EXPORT_SYMBOL(cpt_close_object);

int cpt_open_object(cpt_object_t *obj, struct cpt_context *ctx)
{
	if (ctx->file == NULL)
		return 0;

	cpt_close_object(ctx);

	ctx->current_object = ctx->file->f_pos;
	if (obj)
		cpt_obj_setpos(obj, ctx->current_object, ctx);

	return 0;
}
EXPORT_SYMBOL(cpt_open_object);

int cpt_push_object(loff_t *saved, struct cpt_context *ctx)
{
	if (ctx->file) {
		*saved = ctx->current_object;
		ctx->current_object = ctx->file->f_pos;
	}
	return 0;
}
EXPORT_SYMBOL(cpt_push_object);

int cpt_pop_object(loff_t *saved, struct cpt_context *ctx)
{
	ctx->current_object = *saved;
	return 0;
}
EXPORT_SYMBOL(cpt_pop_object);

int cpt_dump_tail(struct cpt_context *ctx)
{
	struct cpt_major_tail hdr;
	int i;

	if (ctx->file == NULL)
		return 0;

	cpt_open_section(ctx, CPT_SECT_TRAILER);
	memset(&hdr, 0, sizeof(hdr));
	hdr.cpt_next = sizeof(hdr);
	hdr.cpt_object = CPT_OBJ_TRAILER;
	hdr.cpt_hdrlen = sizeof(hdr);
	hdr.cpt_content = CPT_CONTENT_VOID;
	hdr.cpt_lazypages = 0;
	hdr.cpt_64bit = ctx->tasks64;
	hdr.cpt_signature[0] = CPT_SIGNATURE0;
	hdr.cpt_signature[1] = CPT_SIGNATURE1;
	hdr.cpt_signature[2] = CPT_SIGNATURE2;
	hdr.cpt_signature[3] = CPT_SIGNATURE3;
	hdr.cpt_nsect = CPT_SECT_MAX_INDEX;
	for (i = 0; i < CPT_SECT_MAX_INDEX; i++)
		hdr.cpt_sections[i] = ctx->sections[i];

	ctx->write(&hdr, sizeof(hdr), ctx);
	cpt_close_section(ctx);
	return 0;
}
