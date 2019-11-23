#include <linux/fs.h>
#include <asm/uaccess.h>
#include <bc/beancounter.h>

#define	CPT_CTX_ERROR		-1
#define	CPT_CTX_IDLE		0
#define CPT_CTX_SUSPENDING	1
#define	CPT_CTX_SUSPENDED	2
#define CPT_CTX_DUMPING		3
#define CPT_CTX_UNDUMPING	4
#define CPT_CTX_UNDUMPED	5

#define CPT_TID(tsk)   task_pid_nr(tsk), task_pid_vnr(tsk), (tsk)->comm
#define CPT_FID		"%d,%d(%s)"

enum {
	CPT_DOBJ_VFSMOUNT_REF,
	CPT_DOBJ_FILE,
	CPT_DOBJ_MAX,
};

struct cpt_delayed_context {
	int ve_id;
	struct task_struct *dfs_daemon;
	struct completion dfs_notify;
	struct list_head object_array[CPT_DOBJ_MAX];
};

void destroy_delayed_context(struct cpt_delayed_context *);

struct pram_stream;

typedef struct cpt_context
{
	struct list_head ctx_list;
	int	refcount;
	int	ctx_state;
	int	objcount;
	int	sticky;
	struct semaphore main_sem;

	struct file *errorfile;
	struct file *statusfile;
	struct file *lockfile;
	int lockfile_new;

	int	errno;
	char	*error_msg;
	loff_t	err_offset;

	struct file	*file;
	char		*tmpbuf;
	int		pagesize;
#ifdef CONFIG_VZ_CHECKPOINT_ITER
	int		iter_done;
	struct rb_root	iter_rb_root;
	struct user_beancounter *iter_ub;
	int		iter_shm_start;
	struct file	*pagein_file_in;
	struct file	*pagein_file_out;
#endif
	loff_t		current_section;
	loff_t		current_object;

	loff_t		sections[CPT_SECT_MAX];

	__u32		errormask;
	__u32		write_error;

	struct list_head object_array[CPT_OBJ_MAX];

	void		(*write)(const void *addr, size_t count, struct cpt_context *ctx);
	void		(*pwrite)(void *addr, size_t count, struct cpt_context *ctx, loff_t pos);
	ssize_t		(*read)(void *addr, size_t count, struct cpt_context *ctx);
	ssize_t		(*pread)(void *addr, size_t count, struct cpt_context *ctx, loff_t pos);
	void		(*align)(struct cpt_context *ctx);
	int		ve_id;
	int		contextid;
	struct timespec cpt_monotonic_time; /* Host monotonic time at the moment of cpt/rst
					     * corresponging to start_time */
	__u64		virt_jiffies64;	/* Virtual jiffies64. It is == cpt_jiffies64 when
					 * VE did not migrate. */
	struct timespec	start_time;
	struct timespec delta_time;
	__s64		delta_nsec;
	int		image_version;
	__u16		image_arch;
	__u64		iptables_mask;
	__u64		features;

#define CPT_ANONVMA_HBITS (sizeof(void*) == 4 ? 10 : 9)
#define CPT_ANONVMA_HSIZE (1<<CPT_ANONVMA_HBITS)
	struct hlist_head *anonvmas;
	int		tasks64;
	__u32		src_cpu_flags;
	__u32		dst_cpu_flags;
	__u32		kernel_config_flags;

	__u32		last_vpid;

	struct filejob  *filejob_queue;

	int		slm_count;

	char		*vdso;

	struct cpt_delayed_context *dctx;

#ifdef CONFIG_BEANCOUNTERS
	/* Store here ubc limits and barriers during undumping,
	   and restore them before resuming */
	struct ubparm	saved_ubc[UB_RESOURCES];
#endif

#define CPT_MAX_LINKDIRS	1
	struct file	*linkdirs[CPT_MAX_LINKDIRS];
	int		linkdirs_num;
	unsigned int	linkcnt; /* for create hardlinked files */
	int	hardlinked_on;

#ifdef CONFIG_PRAM
	struct pram_stream *pram_stream;
#endif

	loff_t dumpsize;
	loff_t maxdumpsize;
} cpt_context_t;

typedef struct {
	int pid;
	cpt_context_t *ctx;
	struct completion done;
} pagein_info_t;

int pagein_info_printf(char *buf, cpt_context_t *ctx);

#ifdef CONFIG_PRAM
struct cpt_pram_ops {
	int (*cpt_open)(cpt_context_t *ctx);
	int (*cpt_dump)(struct vm_area_struct *vma,
			unsigned long start, unsigned long end,
			struct cpt_context *ctx);
	void (*cpt_close)(cpt_context_t *ctx, int err);
	int (*rst_open)(cpt_context_t *ctx);
	int (*rst_undump)(struct mm_struct *mm,
			  unsigned long start, unsigned long end,
			  loff_t pos, struct cpt_context *ctx);
	void (*rst_close)(cpt_context_t *ctx);
};
extern struct cpt_pram_ops *cpt_pram_ops;

int cpt_open_pram(cpt_context_t *ctx);
void cpt_dump_pram(struct vm_area_struct *vma,
		unsigned long start, unsigned long end,
		struct cpt_context *ctx);
void cpt_close_pram(cpt_context_t *ctx, int err);
int rst_open_pram(cpt_context_t *ctx);
int rst_undump_pram(struct mm_struct *mm,
		unsigned long start, unsigned long end,
		loff_t pos, struct cpt_context *ctx);
void rst_close_pram(cpt_context_t *ctx);
#else
static inline int cpt_open_pram(cpt_context_t *ctx) { return -ENOSYS; }
static inline void cpt_dump_pram(struct vm_area_struct *vma,
		unsigned long start, unsigned long end,
		struct cpt_context *ctx) { }
static inline void cpt_close_pram(cpt_context_t *ctx, int err) { }
static inline int rst_open_pram(cpt_context_t *ctx) { return 0; }
static inline int rst_undump_pram(struct mm_struct *mm,
		unsigned long start, unsigned long end,
		loff_t pos, struct cpt_context *ctx) { return -ENOSYS; }
static inline void rst_close_pram(cpt_context_t *ctx) { }
#endif

int cpt_open_dumpfile(struct cpt_context *);
int cpt_close_dumpfile(struct cpt_context *);
int rst_open_dumpfile(struct cpt_context *);
void rst_close_dumpfile(struct cpt_context *);
void cpt_context_init(struct cpt_context *);
void rst_context_init(struct cpt_context *);
void cpt_context_destroy(struct cpt_context *);

void rst_report_error(int err, cpt_context_t *ctx);


int cpt_major_hdr_out(struct cpt_context *ctx);
int cpt_dump_tail(struct cpt_context *ctx);
int cpt_close_section(struct cpt_context *ctx);
int cpt_open_section(struct cpt_context *ctx, __u32 type);
int cpt_close_object(struct cpt_context *ctx);
int cpt_open_object(cpt_object_t *obj, struct cpt_context *ctx);
int cpt_push_object(loff_t *saved, struct cpt_context *ctx);
int cpt_pop_object(loff_t *saved, struct cpt_context *ctx);

int rst_get_section(int type, struct cpt_context * ctx, loff_t *, loff_t *);
__u8 *__rst_get_name(loff_t *pos_p, struct cpt_context *ctx);
__u8 *rst_get_name(loff_t pos, struct cpt_context *ctx);
void rst_put_name(__u8 *name, struct cpt_context *ctx);
int _rst_get_object(int type, loff_t pos, void *tmp, int size, struct cpt_context *ctx);
void * __rst_get_object(int type, loff_t pos, struct cpt_context *ctx);

pid_t vpid_to_pid(pid_t);

#define rst_get_object(type, pos, tmp, ctx) \
 _rst_get_object((type), (pos), (tmp), sizeof(*(tmp)), (ctx))

extern int debug_level;
extern int swap_percent;

#define cpt_printk(lvl, fmt, args...)	do {	\
		if (lvl <= debug_level)		\
			printk(fmt, ##args);	\
	} while (0)

#define dprintk(a...) cpt_printk(3, "CPT DBG: " a)
#define dprintk_ctx(f, arg...) dprintk("%p,%u: " f, ctx, ctx->ve_id, ##arg)

#define wprintk(a...) cpt_printk(2, "CPT WRN: " a)
#define wprintk_ctx(f, arg...) wprintk("%p,%u: " f, ctx, ctx->ve_id, ##arg)

#define iprintk(a...) cpt_printk(1, "CPT INF: " a)
#define iprintk_ctx(f, arg...) iprintk("%p,%u: " f, ctx, ctx->ve_id, ##arg)

#define eprintk(a...) cpt_printk(1, "CPT ERR: " a)
#define eprintk_ctx(f, arg...)						\
do {									\
	eprintk("%p,%u :" f, ctx, ctx->ve_id, ##arg);			\
	if (ctx->error_msg && ctx->err_offset < PAGE_SIZE)		\
		ctx->err_offset += snprintf((char*)(ctx->error_msg +	\
				ctx->err_offset),			\
			       	PAGE_SIZE - ctx->err_offset,		\
				"Error: " f, ##arg);			\
} while(0)

#define CPT_TMPBUF_FREE 0x789adf12
#define CPT_TMPBUF_BUSY 0xabcd9876

static inline void *cpt_get_buf(cpt_context_t *ctx)
{
	void *buf = ctx->tmpbuf;

	BUG_ON(*(u32*)(buf + PAGE_SIZE - 4) != CPT_TMPBUF_FREE);
	*(u32*)(buf + PAGE_SIZE - 4) = CPT_TMPBUF_BUSY;
	return buf;
}

static inline void __cpt_release_buf(cpt_context_t *ctx)
{
	void *buf = ctx->tmpbuf;

	*(u32*)(buf + PAGE_SIZE - 4) = CPT_TMPBUF_FREE;
}

static inline void cpt_release_buf(cpt_context_t *ctx)
{
	void *buf = ctx->tmpbuf;

	BUG_ON(*(u32*)(buf + PAGE_SIZE - 4) != CPT_TMPBUF_BUSY);
	*(u32*)(buf + PAGE_SIZE - 4) = CPT_TMPBUF_FREE;
}

static inline void cpt_flush_error(cpt_context_t *ctx)
{
	mm_segment_t oldfs;

	if (ctx->errorfile && ctx->error_msg && ctx->err_offset) {
		if (ctx->errorfile->f_op && ctx->errorfile->f_op->write) {
			oldfs = get_fs();
			set_fs(KERNEL_DS);
			ctx->errorfile->f_op->write(ctx->errorfile,
				ctx->error_msg, ctx->err_offset,
				&ctx->errorfile->f_pos);
			set_fs(oldfs);
		}
		ctx->error_msg[0] = 0;
		ctx->err_offset = 0;
	}
}
