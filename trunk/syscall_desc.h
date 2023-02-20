#ifndef SYSCALL_DESC_H
#define SYSCALL_DESC_H

#include <linux/version.h>
#include <asm/unistd.h>

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,26)
#define SYSCALL_MAX     __NR_timerfd_gettime+1  /* max syscall number */
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27) && \
                LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,29)
#define SYSCALL_MAX     __NR_inotify_init1+1    /* max syscall number */
#elif LINUX_VERSION_CODE == KERNEL_VERSION(2,6,30)
#define SYSCALL_MAX     __NR_pwritev+1          /* max syscall number */
#elif LINUX_VERSION_CODE == KERNEL_VERSION(2,6,31)
#define SYSCALL_MAX     __NR_perf_counter_open+1/* max syscall number */
#elif LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32)
#define SYSCALL_MAX     __NR_perf_event_open+1  /* max syscall number */
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33) && \
                LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,35)
#define SYSCALL_MAX     __NR_recvmmsg+1         /* max syscall number */
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36) && \
                LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,38)
#define SYSCALL_MAX     __NR_prlimit64+1        /* max syscall number */
#else
#define SYSCALL_MAX     __NR_syncfs+1           /* max syscall number */
#endif

extern const struct syscall_desc sysdesc[SYSCALL_MAX];

/// Specifies that the number of bytes written to an argument is defined by 
/// the return value
#define INRETVAL	666

/// Maximum number of system call arguments
#define SYSARGS_MAX	6

/// System call should not be handled in any way
#define SYS_NONE	0
/// System call needs to be handled when in a checkpoint
#define SYS_CHCK	1
/// System call need to be handled when cascading RPs are used
#define SYS_CRPS	2 

typedef void (*pre_call_t)(struct thread_state *ts, CONTEXT *ctx, 
		SYSCALL_STANDARD std);
typedef void (*post_call_t)(struct thread_state *ts, CONTEXT *ctx, ADDRINT ret);

/* system call descriptor */
struct syscall_desc {
        unsigned handle:3;		/* Should this syscall be processed */
	unsigned save_args:3;		/* How many arguments to save */
	unsigned ret_args:3;		/* Max argument used to return data */
	/* Size of data returned in arguments. It can also be a negative number
	 * indicating the size of the data is specified by the value of another
	 * argument. E.g., -3 indicates that the size is specified by arguments
	 * 3. ARGLENINRETVAL specified that the syscall return value specifies
	 * the size. */
	int arglen[SYSARGS_MAX];
        pre_call_t pre;			/* pre-syscall callback */
        post_call_t post;		/* post-syscall callback */
};

#endif
