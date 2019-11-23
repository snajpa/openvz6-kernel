#ifndef _LINUX_SHM_H_
#define _LINUX_SHM_H_

#include <linux/ipc.h>
#include <linux/errno.h>
#ifdef __KERNEL__
#include <asm/page.h>
#else
#include <unistd.h>
#endif

/*
 * SHMMAX, SHMMNI and SHMALL are upper limits are defaults which can
 * be increased by sysctl
 */

#define SHMMAX 0x2000000		 /* max shared seg size (bytes) */
#define SHMMIN 1			 /* min shared seg size (bytes) */
#define SHMMNI 4096			 /* max num of segs system wide */
#ifdef __KERNEL__
#define SHMALL (SHMMAX/PAGE_SIZE*(SHMMNI/16)) /* max shm system wide (pages) */
#else
#define SHMALL (SHMMAX/getpagesize()*(SHMMNI/16))
#endif
#define SHMSEG SHMMNI			 /* max shared segs per process */

#ifdef __KERNEL__
#include <asm/shmparam.h>
#endif

/* Obsolete, used only for backwards compatibility and libc5 compiles */
struct shmid_ds {
	struct ipc_perm		shm_perm;	/* operation perms */
	int			shm_segsz;	/* size of segment (bytes) */
	__kernel_time_t		shm_atime;	/* last attach time */
	__kernel_time_t		shm_dtime;	/* last detach time */
	__kernel_time_t		shm_ctime;	/* last change time */
	__kernel_ipc_pid_t	shm_cpid;	/* pid of creator */
	__kernel_ipc_pid_t	shm_lpid;	/* pid of last operator */
	unsigned short		shm_nattch;	/* no. of current attaches */
	unsigned short 		shm_unused;	/* compatibility */
	void 			*shm_unused2;	/* ditto - used by DIPC */
	void			*shm_unused3;	/* unused */
};

/* Include the definition of shmid64_ds and shminfo64 */
#include <asm/shmbuf.h>

/* permission flag for shmget */
#define SHM_R		0400	/* or S_IRUGO from <linux/stat.h> */
#define SHM_W		0200	/* or S_IWUGO from <linux/stat.h> */

/* mode for attach */
#define	SHM_RDONLY	010000	/* read-only access */
#define	SHM_RND		020000	/* round attach address to SHMLBA boundary */
#define	SHM_REMAP	040000	/* take-over region on attach */
#define	SHM_EXEC	0100000	/* execution access */

/* super user shmctl commands */
#define SHM_LOCK 	11
#define SHM_UNLOCK 	12

/* ipcs ctl commands */
#define SHM_STAT 	13
#define SHM_INFO 	14

/* Obsolete, used only for backwards compatibility */
struct	shminfo {
	int shmmax;
	int shmmin;
	int shmmni;
	int shmseg;
	int shmall;
};

struct shm_info {
	int used_ids;
	unsigned long shm_tot;	/* total allocated shm */
	unsigned long shm_rss;	/* total resident shm */
	unsigned long shm_swp;	/* total swapped shm */
	unsigned long swap_attempts;
	unsigned long swap_successes;
};

#ifdef __KERNEL__

#include <linux/ipc_namespace.h>

#define IPC_SEM_IDS	0
#define IPC_MSG_IDS	1
#define IPC_SHM_IDS	2

struct shm_file_data {
	int id;
	struct ipc_namespace *ns;
	struct file *file;
	const struct vm_operations_struct *vm_ops;
};
#define shm_file_data(file) (*((struct shm_file_data **)&(file)->private_data))
#define shm_ids(ns)	((ns)->ids[IPC_SHM_IDS])

struct shmid_kernel /* private to the kernel */
{	
	struct kern_ipc_perm	shm_perm;
	struct file *		shm_file;
	unsigned long		shm_nattch;
	unsigned long		shm_segsz;
	time_t			shm_atim;
	time_t			shm_dtim;
	time_t			shm_ctim;
	pid_t			shm_cprid;
	pid_t			shm_lprid;
	struct user_struct	*mlock_user;
};

/*
 * shm_lock_(check_) routines are called in the paths where the rw_mutex
 * is not held.
 */
static inline struct shmid_kernel *shm_lock(struct ipc_namespace *ns, int id)
{
	struct kern_ipc_perm *ipcp = ipc_lock(&shm_ids(ns), id);

	if (IS_ERR(ipcp))
		return (struct shmid_kernel *)ipcp;

	return container_of(ipcp, struct shmid_kernel, shm_perm);
}

#define shm_unlock(shp)			\
	ipc_unlock(&(shp)->shm_perm)

/* shm_mode upper byte flags */
#define	SHM_DEST	01000	/* segment will be destroyed on last detach */
#define SHM_LOCKED      02000   /* segment will not be swapped */
#define SHM_HUGETLB     04000   /* segment will use huge TLB pages */
#define SHM_NORESERVE   010000  /* don't check for reservations */

/* Bits [26:31] are reserved */

/*
 * When SHM_HUGETLB is set bits [26:31] encode the log2 of the huge page size.
 * This gives us 6 bits, which is enough until someone invents 128 bit address
 * spaces.
 *
 * Assume these are all power of twos.
 * When 0 use the default page size.
 */
#define SHM_HUGE_SHIFT  26
#define SHM_HUGE_MASK   0x3f

#ifdef CONFIG_SYSVIPC
long do_shmat(int shmid, char __user *shmaddr, int shmflg, unsigned long *addr);
extern int is_file_shm_hugepages(struct file *file);
extern void exit_shm(struct task_struct *task);
#else
static inline long do_shmat(int shmid, char __user *shmaddr,
				int shmflg, unsigned long *addr)
{
	return -ENOSYS;
}
static inline int is_file_shm_hugepages(struct file *file)
{
	return 0;
}
static inline void exit_shm(struct task_struct *task)
{
}
#endif

int sysvipc_walk_shm(int (*func)(struct shmid_kernel*, void *), void *arg);
struct file * sysvipc_setup_shm(key_t key, int shmid, size_t size, int shmflg);
extern const struct file_operations shmem_file_operations;
extern const struct file_operations shm_file_operations;

extern struct file_system_type shmem_fs_type;
#endif /* __KERNEL__ */

#endif /* _LINUX_SHM_H_ */
