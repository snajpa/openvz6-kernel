#include <linux/unistd.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <asm/uaccess.h>

#define WRAP(c, args) return sys_##c args
#define WRAP2(c, args) int err; mm_segment_t oldfs; \
	               oldfs = get_fs(); set_fs(KERNEL_DS); \
                       err = sys_##c args ;\
                       set_fs(oldfs); \
                       return err

static inline int sc_close(int fd)
{
	WRAP(close, (fd));
}

static inline int sc_dup2(int fd1, int fd2)
{
	WRAP(dup2, (fd1, fd2));
}

static inline int sc_unlink(char *name)
{
	WRAP2(unlink, (name));
}

static inline int sc_pipe(int *pfd)
{
	return do_pipe_flags(pfd, 0);
}

static inline int sc_mknod(char *name, int mode, int dev)
{
	WRAP2(mknod, (name, mode, dev));
}

static inline int sc_chmod(char *name, int mode)
{
	WRAP2(chmod, (name, mode));
}

static inline int sc_chown(char *name, int uid, int gid)
{
	WRAP2(chown, (name, uid, gid));
}

static inline int sc_mkdir(char *name, int mode)
{
	WRAP2(mkdir, (name, mode));
}

static inline int sc_rmdir(char *name)
{
	WRAP2(rmdir, (name));
}

static inline int sc_mount(char *mntdev, char *mntpnt, char *type, unsigned long flags)
{
	WRAP2(mount, (mntdev ? : "none", mntpnt, type, flags, NULL));
}

static inline int sc_mprotect(unsigned long start, size_t len,
			      unsigned long prot)
{
	WRAP(mprotect, (start, len, prot));
}

static inline int sc_mlock(unsigned long start, size_t len)
{
	WRAP(mlock, (start, len));
}

static inline int sc_munlock(unsigned long start, size_t len)
{
	WRAP(munlock, (start, len));
}

static inline int sc_remap_file_pages(unsigned long start, size_t len,
				      unsigned long prot, unsigned long pgoff,
				      unsigned long flags)
{
	WRAP(remap_file_pages, (start, len, prot, pgoff, flags));
}

static inline int sc_waitx(int pid, int opt, int *stat_addr)
{
	WRAP(wait4, (pid, stat_addr, opt, NULL));
}

static inline int sc_flock(int fd, int flags)
{
	WRAP(flock, (fd, flags));
}

static inline int sc_open(char* path, int flags, int mode)
{
	WRAP(open, (path, flags, mode));
}
