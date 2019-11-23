#ifndef _LINUX_KDEV_T_H
#define _LINUX_KDEV_T_H
#ifdef __KERNEL__
#define MINORBITS	20
#define MINORMASK	((1U << MINORBITS) - 1)

#define MAJOR(dev)	((unsigned int) ((dev) >> MINORBITS))
#define MINOR(dev)	((unsigned int) ((dev) & MINORMASK))
#define MKDEV(ma,mi)	(((ma) << MINORBITS) | (mi))

#define print_dev_t(buffer, dev)					\
	sprintf((buffer), "%u:%u\n", MAJOR(dev), MINOR(dev))

#define format_dev_t(buffer, dev)					\
	({								\
		sprintf(buffer, "%u:%u", MAJOR(dev), MINOR(dev));	\
		buffer;							\
	})

/* acceptable for old filesystems */
static inline int old_valid_dev(dev_t dev)
{
	return MAJOR(dev) < 256 && MINOR(dev) < 256;
}

static inline u16 old_encode_dev(dev_t dev)
{
	return (MAJOR(dev) << 8) | MINOR(dev);
}

static inline dev_t old_decode_dev(u16 val)
{
	return MKDEV((val >> 8) & 255, val & 255);
}

static inline int new_valid_dev(dev_t dev)
{
	return 1;
}

static inline u32 new_encode_dev(dev_t dev)
{
	unsigned major = MAJOR(dev);
	unsigned minor = MINOR(dev);
	return (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12);
}

static inline dev_t new_decode_dev(u32 dev)
{
	unsigned major = (dev & 0xfff00) >> 8;
	unsigned minor = (dev & 0xff) | ((dev >> 12) & 0xfff00);
	return MKDEV(major, minor);
}

static inline int huge_valid_dev(dev_t dev)
{
	return 1;
}

static inline u64 huge_encode_dev(dev_t dev)
{
	return new_encode_dev(dev);
}

static inline dev_t huge_decode_dev(u64 dev)
{
	return new_decode_dev(dev);
}

static inline int sysv_valid_dev(dev_t dev)
{
	return MAJOR(dev) < (1<<14) && MINOR(dev) < (1<<18);
}

static inline u32 sysv_encode_dev(dev_t dev)
{
	return MINOR(dev) | (MAJOR(dev) << 18);
}

static inline unsigned sysv_major(u32 dev)
{
	return (dev >> 18) & 0x3fff;
}

static inline unsigned sysv_minor(u32 dev)
{
	return dev & 0x3ffff;
}

#define UNNAMED_MAJOR_COUNT	16

#if UNNAMED_MAJOR_COUNT > 1

extern int unnamed_dev_majors[UNNAMED_MAJOR_COUNT];

static inline dev_t make_unnamed_dev(int idx)
{
	/*
	 * Here we transfer bits from 8 to 8+log2(UNNAMED_MAJOR_COUNT) of the
	 * unnamed device index into major number.
	 */
	return MKDEV(unnamed_dev_majors[(idx >> 8) & (UNNAMED_MAJOR_COUNT - 1)],
		     idx & ~((UNNAMED_MAJOR_COUNT - 1) << 8));
}

static inline int unnamed_dev_idx(dev_t dev)
{
	int i;
	for (i = 0; i < UNNAMED_MAJOR_COUNT &&
				MAJOR(dev) != unnamed_dev_majors[i]; i++);
	return MINOR(dev) | (i << 8);
}

static inline int is_unnamed_dev(dev_t dev)
{
	int i;
	for (i = 0; i < UNNAMED_MAJOR_COUNT &&
				MAJOR(dev) != unnamed_dev_majors[i]; i++);
	return i < UNNAMED_MAJOR_COUNT;
}

#else /* UNNAMED_MAJOR_COUNT */

static inline dev_t make_unnamed_dev(int idx)
{
	return MKDEV(0, idx);
}

static inline int unnamed_dev_idx(dev_t dev)
{
	return MINOR(dev);
}

static inline int is_unnamed_dev(dev_t dev)
{
	return MAJOR(dev) == 0;
}

#endif /* UNNAMED_MAJOR_COUNT */

#else /* __KERNEL__ */

/*
Some programs want their definitions of MAJOR and MINOR and MKDEV
from the kernel sources. These must be the externally visible ones.
*/
#define MAJOR(dev)	((dev)>>8)
#define MINOR(dev)	((dev) & 0xff)
#define MKDEV(ma,mi)	((ma)<<8 | (mi))
#endif /* __KERNEL__ */
#endif
