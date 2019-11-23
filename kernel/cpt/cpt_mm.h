int cpt_collect_mm(cpt_context_t *);

int cpt_dump_vm(struct cpt_context *ctx);

__u32 rst_mm_flag(struct cpt_task_image *ti, struct cpt_context *ctx);
int rst_mm_basic(cpt_object_t *obj, struct cpt_task_image *ti, struct cpt_context *ctx);
int rst_mm_complete(struct cpt_task_image *ti, struct cpt_context *ctx);
int set_mlock_creds(int cap);

int cpt_iteration(cpt_context_t *ctx);
int rst_iteration(cpt_context_t *ctx);
void rst_drop_iter_rbtree(cpt_context_t *ctx);
int rst_iter(struct vm_area_struct *vma, u64 pfn,
	     unsigned long addr, cpt_context_t * ctx);
int rst_iter_chunk(struct file *file, loff_t pos, struct cpt_page_block * pgb,
			cpt_context_t *ctx);

#ifdef ARCH_HAS_SETUP_ADDITIONAL_PAGES
struct linux_binprm;
extern int arch_setup_additional_pages(struct linux_binprm *bprm, int exstack,
				       unsigned long map_address);
#endif

#ifdef CONFIG_X86
extern struct page *vdso32_pages[1];
#define vsyscall_addr page_address(vdso32_pages[0])
#endif

int cpt_check_page(struct vm_area_struct *vma, unsigned long address,
		   struct page *page, int wrprot);
int cpt_verify_wrprot(struct page * page, cpt_context_t * ctx);
