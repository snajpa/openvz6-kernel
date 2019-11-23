/* Interface to kernel vars which we had to _add_. */

#define PRIO_TO_NICE(prio)	((prio) - MAX_RT_PRIO - 20)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,9)
#define TASK_TRACED TASK_STOPPED
#define unix_peer(sk) ((sk)->sk_pair)
#define page_mapcount(pg) ((pg)->mapcount)
#else
#define unix_peer(sk) (unix_sk(sk)->peer)
#endif

#ifdef CONFIG_IA64
#define cpu_has_fxsr 1
#endif

#define CPT_SIG_IGNORE_MASK (\
        (1 << (SIGCONT - 1)) | (1 << (SIGCHLD - 1)) | \
	(1 << (SIGWINCH - 1)) | (1 << (SIGURG - 1)))

static inline void do_gettimespec(struct timespec *ts)
{
	struct timeval tv;
	do_gettimeofday(&tv);
	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = tv.tv_usec*1000;
}

int local_kernel_thread(int (*fn)(void *),
		void * arg,
		unsigned long flags,
		pid_t pid);
int asm_kernel_thread(int (*fn)(void *),
		void * arg,
		unsigned long flags,
		pid_t pid);

unsigned int test_cpu_caps_and_features(void);
int rst_image_acceptable(unsigned long version);
unsigned int test_kernel_config(void);

#define test_one_flag_old(src, dst, flag, message, ret) \
	if (src & (1 << flag)) \
		if (!(dst & (1 << flag))) { \
			wprintk("Destination cpu does not have " message "\n"); \
			ret = 1; \
	}

#define test_one_flag(src, dst, flag, message, ret) \
if (src & (1 << flag)) \
	if (!(dst & (1 << flag))) { \
		eprintk_ctx("Destination cpu does not have " message "\n"); \
		ret = VECAPS_NO_CPU_FEATURE; \
	}

static inline void
_set_normalized_timespec(struct timespec *ts, time_t sec, long nsec)
{
	while (nsec >= NSEC_PER_SEC) {
		nsec -= NSEC_PER_SEC;
		++sec;
	}
	while (nsec < 0) {
		nsec += NSEC_PER_SEC;
		--sec;
	}
	ts->tv_sec = sec;
	ts->tv_nsec = nsec;
}

static inline struct timespec
_ns_to_timespec(const s64 nsec)
{
	struct timespec ts;
	s32 rem;

	if (!nsec)
		return (struct timespec) {0, 0};

	ts.tv_sec = div_s64_rem(nsec, NSEC_PER_SEC, &rem);
	if (unlikely(rem < 0)) {
		ts.tv_sec--;
		rem += NSEC_PER_SEC;
	}
	ts.tv_nsec = rem;

	return ts;
}
