int cpt_collect_files(cpt_context_t *);
int cpt_collect_fs(cpt_context_t *);
int cpt_collect_namespace(cpt_context_t *);
int cpt_collect_sysvsem_undo(cpt_context_t *);
int cpt_collect_tty(struct file *, cpt_context_t *);
void cpt_stop_tracker(struct cpt_context *);
int cpt_dump_files(struct cpt_context *ctx);
int cpt_dump_files_struct(struct cpt_context *ctx);
int cpt_dump_fs_struct(struct cpt_context *ctx);
int cpt_dump_content_sysvshm(struct file *file, struct cpt_context *ctx);
int cpt_dump_content_tty(struct file *file, struct cpt_context *ctx);
int cpt_dump_tty(cpt_object_t *, struct cpt_context *ctx);
struct file * rst_sysv_shm_vma(struct cpt_vma_image *vmai, struct cpt_context *ctx);
struct file * rst_sysv_shm_itself(loff_t pos, struct cpt_context *ctx);
struct file * rst_open_file(cpt_object_t *mntobj, char *name,
		struct cpt_file_image *fi, unsigned flags, struct cpt_context *ctx);
struct file * rst_open_tty(cpt_object_t *mntobj, char *name,
		struct cpt_file_image *fi, struct cpt_inode_image *ii,
		unsigned flags, struct cpt_context *ctx);
__u32 cpt_tty_fasync(struct file *file, struct cpt_context *ctx);

int rst_posix_locks(struct cpt_context *ctx);
void fixup_lock_pid(struct inode *inode, unsigned int cpt_pid, struct ve_struct *ve);

struct file *rst_file(loff_t pos, int fd, struct cpt_context *ctx);
int rst_task_namespace(struct cpt_task_image *ti, struct cpt_context *ctx);
int rst_files(struct cpt_task_image *ti, struct cpt_context *ctx);
__u32 rst_files_flag(struct cpt_task_image *ti, struct cpt_context *ctx);
int rst_fs_complete(struct cpt_task_image *ti, struct cpt_context *ctx);
int rst_restore_fs(struct cpt_context *ctx);

int cpt_collect_sysv(cpt_context_t *);
int cpt_dump_sysvsem(struct cpt_context *ctx);
int cpt_dump_sysvmsg(struct cpt_context *ctx);
int rst_sysv_ipc(struct cpt_context *ctx);
int rst_semundo_complete(struct cpt_task_image *ti, struct cpt_context *ctx);
__u32 rst_semundo_flag(struct cpt_task_image *ti, struct cpt_context *ctx);

int cpt_dump_namespace(struct cpt_context *ctx);
int rst_root_namespace(struct cpt_context *ctx);

int rst_stray_files(struct cpt_context *ctx);
int rst_tty_jobcontrol(struct cpt_context *ctx);
int chrdev_is_tty(dev_t dev);

void rst_flush_filejobs(struct cpt_context *);
int rst_do_filejobs(struct cpt_context *);

extern struct file_operations signalfd_fops;

int rst_eventpoll(struct cpt_context *);
struct file *cpt_open_epolldev(struct cpt_file_image *fi,
			       unsigned flags,
			       struct cpt_context *ctx);
int cpt_dump_epolldev(cpt_object_t *obj, struct cpt_context *);

int cpt_dump_dir(struct dentry *d, struct vfsmount *mnt, struct cpt_context *ctx);
int rst_get_dentry(struct dentry **dp, struct vfsmount **mp,
		   loff_t *pos, struct cpt_context *ctx);

int cpt_dump_inotify(cpt_object_t *obj, cpt_context_t *ctx);
int rst_inotify(cpt_context_t *ctx);
struct file *rst_open_inotify(struct cpt_file_image *fi,
			      unsigned flags,
			      struct cpt_context *ctx);

extern struct dentry_operations delay_dir_dops;

#define FAKE_FILE_NAME "[fake_file]"

int rst_path_lookup_at(struct vfsmount *mnt, struct dentry *dentry,
		const char *name, unsigned int flags, struct nameidata *nd);
int rst_path_lookup(cpt_object_t *mntobj, const char *path,
		unsigned int flags, struct nameidata *nd);

#define check_one_vfsmount(mnt) \
	(strcmp(mnt->mnt_sb->s_type->name, "rootfs") != 0 && \
	 strcmp(mnt->mnt_sb->s_type->name, "ext3") != 0 && \
	 strcmp(mnt->mnt_sb->s_type->name, "ext2") != 0 && \
	 strcmp(mnt->mnt_sb->s_type->name, "simfs") != 0 && \
	 strcmp(mnt->mnt_sb->s_type->name, "unionfs") != 0 && \
	 strcmp(mnt->mnt_sb->s_type->name, "tmpfs") != 0 && \
	 strcmp(mnt->mnt_sb->s_type->name, "devtmpfs") != 0 && \
	 strcmp(mnt->mnt_sb->s_type->name, "nfs") != 0 && \
	 strcmp(mnt->mnt_sb->s_type->name, "nfs4") != 0 && \
	 strcmp(mnt->mnt_sb->s_type->name, "autofs") != 0 && \
	 strcmp(mnt->mnt_sb->s_type->name, "devpts") != 0 && \
	 strcmp(mnt->mnt_sb->s_type->name, "proc") != 0 && \
	 strcmp(mnt->mnt_sb->s_type->name, "sysfs") != 0 && \
	 strcmp(mnt->mnt_sb->s_type->name, "binfmt_misc") != 0 && \
	 strcmp(mnt->mnt_sb->s_type->name, "ext4") != 0 && \
	 strcmp(mnt->mnt_sb->s_type->name, "vzfs") != 0 && \
	 strcmp(mnt->mnt_sb->s_type->name, "rpc_pipefs") != 0 && \
	 strcmp(mnt->mnt_sb->s_type->name, "mqueue") != 0 && \
	 strcmp(mnt->mnt_sb->s_type->name, "cgroup") != 0)

#define is_autofs_mount(mnt) ((mnt)->mnt_sb->s_magic == FSMAGIC_AUTOFS)
#define is_sunrpc_pipefs(mnt) ((mnt)->mnt_sb->s_magic == FSMAGIC_RPCAUTH)

int cpt_page_is_zero(struct page * page);
void cpt_finish_vfsmount_ref(struct cpt_context *ctx);
void rst_finish_vfsmount_ref(struct cpt_context *ctx);

struct vfsmount *rst_kern_mount(const char *fstype, int flags,
		const char *name, void *data);

cpt_object_t *cpt_lookup_vfsmount_obj(struct vfsmount *mnt,
		struct cpt_context *ctx);

int cpt_need_delayfs(struct vfsmount *mnt);
extern struct file_system_type delayfs_type;
struct file *rst_delayfs_screw(struct vfsmount *mnt, char *name, int flags, loff_t offset, unsigned int mode);
struct vfsmount *rst_mount_delayfs(char *type, int flags,
		char *name, void *data, cpt_context_t *ctx);
int rst_freeze_delayfs(cpt_context_t *ctx);
int rst_init_delayfs_daemon(cpt_context_t *ctx);
int rst_delay_flock(struct file *, struct cpt_flock_image *, cpt_context_t *);

int cpt_dump_string(const char *s, struct cpt_context *ctx);

int cpt_dump_cgroups(struct cpt_context *ctx);
int rst_cgroups(struct cpt_context *ctx);

int cpt_add_cgroup(struct vfsmount *mnt, struct cpt_context *ctx);
int rst_cgroup_task(struct cpt_context * ctx);
void rst_cgroup_close(struct cpt_context * ctx);

void uuid_bytes_to_hex(char *buf, const u8 *u);

struct dentry *get_linked_dentry(struct dentry *d, struct vfsmount *mnt,
					struct cpt_context *ctx);

bool mnt_is_tmpfs(struct vfsmount *mnt);

int mknod_by_mntref(const char __user *filename, int mode,
			unsigned dev, struct vfsmount *mnt);
