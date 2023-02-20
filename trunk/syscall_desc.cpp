#include <iostream>
#include <sstream>
#include <cassert>

/* Linux system calls handling */

extern "C" {
#include <sys/epoll.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <asm/fcntl.h>
#include <asm/stat.h>
#include <linux/sysctl.h>

#include <poll.h>
#include <string.h>
#include <unistd.h>

#include <linux/utsname.h>
#include <sys/times.h>
#include <ustat.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <asm/statfs.h>
#include <linux/net.h>
#include <asm/vm86.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/timex.h>
#include <linux/quota.h>
#include <asm/posix_types.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <linux/unistd.h>
#include <asm/ldt.h>
#include <linux/aio_abi.h>
#include <linux/mqueue.h>
#include <linux/perf_event.h>

#include <stdlib.h>
}

#include "pin.H"
#include "threadstate.hpp"
#include "libreassure.hpp"
#include "checkpoint_xchg.hpp"
#include "fork.h"

#define PAGE_SIZE	4096
#define F_DUPFD_CLOEXEC 1030

/* From asm/signal.h */
typedef unsigned long old_sigset_t;

typedef void (*__sighandler_t)(int); 

struct old_sigaction {
	__sighandler_t _sa_handler;
	old_sigset_t sa_mask;
	unsigned long sa_flags;
	void (*sa_restorer)(void);
};

/* From the kernel's fs/readdir.c */
struct old_linux_dirent {
        unsigned long   d_ino;
        unsigned long   d_offset;
        unsigned short  d_namlen;
        char            d_name[1];
};

struct linux_dirent {
	unsigned long	d_ino;
	unsigned long	d_off;
	unsigned short	d_reclen;
	char		d_name[1];
};

/* From linux/ipc.h */
#define SEMCTL	3
#define MSGRCV	12
#define MSGCTL	14
#define SHMAT	21
#define SHMDT	22
#define SHMCTL	24

/* This is needeed to fix some arguments of ipc() */
#define IPC_FIX  256

/* From linux/sem.h */
union semun {
	int		val;
	struct semid_ds	*buf;
	unsigned short	*array;
	struct seminfo	*__buf;
};

/* From xfm/xqm.h */
#define XQM_CMD(x)	(('X'<<8)+(x))
#define Q_XGETQUOTA     XQM_CMD(3)
#define Q_XGETQSTAT     XQM_CMD(5)

typedef struct fs_qfilestat {
	__u64 qfs_ino;
	__u64 qfs_nblks;
	__u32 qfs_nextents;
} fs_qfilestat_t;

struct fs_quota_stat {
	__s8		qs_version;
	__u16		qs_flag;
	__s8		qs_pad;
	fs_qfilestat_t	qs_uquota;
	fs_qfilestat_t	qs_gquota;
	__u32		qs_incoredqs;
	__s32		qs_btimelimit;
	__s32		qs_itimelimit;
	__s32		qs_rtbtimelimit;
	__u16		qs_bwarnlimit;
	__u16		qs_iwarnlimit;
};

struct fs_disk_quota {
	__s8	d_version;
	__s8	d_flags;
	__u16	d_fieldmask;
	__u32	d_id;
	__u64	d_blk_hardlimit;
	__u64	d_blk_softlimit;
	__u64	d_ino_hardlimit;
	__u64	d_ino_softlimit;
	__u64	d_bcount;
	__u64	d_icount;
	__s32	d_itimer;
	__s32	d_btimer;
	__u16	d_iwarns;
	__u16	d_bwarns;
	__s32	d_padding2;
	__u64	d_rtb_hardlimit;
	__u64	d_rtb_softlimit;
	__u64	d_rtbcount;
	__s32	d_rtbtimer;
	__u16	d_rtbwarns;
	__s16	d_padding3;
	char	d_padding4[8];
};

/* For older 16-bit syscalls */
typedef	__kernel_old_uid_t	old_uid_t;
typedef	__kernel_old_gid_t	old_gid_t;


/* From linux/getcpu.h */
struct getcpu_cache {
	unsigned long blob[128 / sizeof(long)];
};

#ifndef file_handle
struct file_handle {
	unsigned int handle_bytes;
	int handle_type;
	unsigned char handle[0];
};
#endif

#include "syscall_desc.h"


/* XXX: post hooks must check if we are in the right type of checkpoint before
 * marking memory */

/* __NR_fcntl post syscall hook */
static void post_fcntl_hook(struct thread_state *ts, CONTEXT *ctx, ADDRINT ret)
{
	unsigned long len;

	// fcntl() was not successful
	if ((long)ret < 0)
		return;

	// differentiate based on the cmd argument
	switch (ts->sysargs[1]) {
		// F_GETLK
		case F_GETLK:
			len = sizeof(struct flock);
			break;

		// F_GETLK64
		case F_GETLK64:
			len = sizeof(struct flock64);
			break;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
		// F_GETOWN_EX
		case F_GETOWN_EX:
			len = sizeof(struct f_owner_ex);
			break;
#endif

#ifdef CASCADING_RPS
		case F_DUPFD:
# if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
		case F_DUPFD_CLOEXEC:
# endif
			xchg_dupfd(ts, ret, ts->sysargs[2]);
#endif

		default:
			return;
	}

	if (len && ts->sysargs[2])
		FLOGMARK(&ts->memcheckp.flog->filter, ts->sysargs[2], len);
}

/* __NR_getgroups16 post syscall_hook */
static void post_getgroups16_hook(struct thread_state *ts, CONTEXT *ctx, 
		ADDRINT ret)
{
	/* getgroups16() was not successful */
	if ((long)ret > 0 && ts->sysargs[1])
		FLOGMARK(&ts->memcheckp.flog->filter, 
				ts->sysargs[1], ret * sizeof(gid_t));
}

/* Generic reception of an iovec */
static void do_recv_iovec(struct thread_state *ts, ADDRINT len, 
		struct iovec *iov, ADDRINT iovlen)
{
	ADDRINT i, iov_tot;

	// iterate the iovec structures
	for (i = 0; i < iovlen && len > 0; i++, len -= iov_tot) {
		// get the next I/O vector
		iov = iov + i;

		// get the length of the iovec
		iov_tot = (len > iov->iov_len)?  iov->iov_len : len;

		// Mark 
		FLOGMARK(&ts->memcheckp.flog->filter, 
				(ADDRINT)iov->iov_base, iov_tot);
	}

}

// Generic handling of recvmsg and recvmmsg
static void do_recvmsg(struct thread_state *ts, ADDRINT len,
		struct msghdr *msg)
{
	if (len == 0 || !msg) // No data received
		return;

	// Mark message
	FLOGMARK(&ts->memcheckp.flog->filter, (ADDRINT)msg, sizeof(msghdr));

	// Mark optional address
	if (msg->msg_name != NULL)
		FLOGMARK(&ts->memcheckp.flog->filter, (ADDRINT)msg->msg_name, 
				msg->msg_namelen);
	
	// mark ancillary data
	if (msg->msg_control != NULL)
		FLOGMARK(&ts->memcheckp.flog->filter, (ADDRINT)msg->msg_control, 
				msg->msg_controllen);

	do_recv_iovec(ts, len, msg->msg_iov, msg->msg_iovlen);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
/* Generic recvmmsg */
static void do_recvmmsg(struct thread_state *ts, struct mmsghdr *msgvec,
		struct timespec *tspec, ADDRINT ret)
{
	ADDRINT i;
	struct mmsghdr *msg;

	if (ret == 0)
		return;
	
	// iterate the mmsghdr structures
	for (i = 0; i < ret; i++) {
		// get the next mmsghdr structure
		msg = msgvec + i;
		// process a single message
		do_recvmsg(ts, msg->msg_len, &msg->msg_hdr);
	}

	// Mark timespec structure
	if (tspec)
		FLOGMARK(&ts->memcheckp.flog->filter, (ADDRINT)tspec, 
				sizeof(struct timespec));
}

/* __NR_recvmmsg post syscall hook */
static void post_recvmmsg_hook(struct thread_state *ts, CONTEXT *ctx, 
		ADDRINT ret)
{
	if ((long)ret < 0)
		return;

	do_recvmmsg(ts, (struct mmsghdr *)ts->sysargs[1], 
			(struct timespec *)ts->sysargs[4], ret);
}
#endif


/* __NR_socketcall post syscall hook */
static void pre_socketcall_hook(struct thread_state *ts, CONTEXT *ctx,
		SYSCALL_STANDARD std)
{
	// XXX: For future use
}

/* __NR_socketcall post syscall hook */
static void post_socketcall_hook(struct thread_state *ts, CONTEXT *ctx,
		ADDRINT ret)
{
	socklen_t len;
	int cmd;
	unsigned long *args;

#ifdef CASCADING_RPS
	if (ts->state != CHECKPOINTING || checkpoint_type != FORK_CHECKP)
		goto crps;
#endif

	cmd = (int)ts->sysargs[0]; /* socket call command */
	args = (unsigned long *)ts->sysargs[1]; /* socket call arguments */

	// Check that system call succeeded XXX
	if ((long)ret < 0) // Ignore failed calls
		return;

	/* demultiplex the socketcall */
	switch (cmd) {
		case SYS_ACCEPT:
		case SYS_ACCEPT4:
		case SYS_GETSOCKNAME:
		case SYS_GETPEERNAME:
			// Mark socket address argument
			if (args[1] && (len = *(socklen_t *)args[2]))
				FLOGMARK(&ts->memcheckp.flog->filter, 
						args[1], len);
			break;

		case SYS_SOCKETPAIR:
			// Mark socketpair as written
			FLOGMARK(&ts->memcheckp.flog->filter, 
					args[3], sizeof(int) * 2);
			break;

		case SYS_RECV:
			if (ret == 0) // No data received
				return;

			// Mark data received
			if (args[1])
				FLOGMARK(&ts->memcheckp.flog->filter, 
						args[1], ret);
			break;

		case SYS_RECVFROM:
			if (ret == 0) // No data received
				return;

			// Mark data received
			if (args[1])
				FLOGMARK(&ts->memcheckp.flog->filter, 
						args[1], ret);

			// Mark sockaddr
			if (args[4] && (len = *(socklen_t *)args[5])) {
				FLOGMARK(&ts->memcheckp.flog->filter, 
						args[4], len);
				FLOGMARK(&ts->memcheckp.flog->filter, 
						args[5], sizeof(socklen_t));
			}
			break;

		case SYS_GETSOCKOPT:
			// Mark sock option
			if (args[3] && (len = *(socklen_t *)args[4])) {
				FLOGMARK(&ts->memcheckp.flog->filter, 
						args[3], len);
				FLOGMARK(&ts->memcheckp.flog->filter, 
						args[4], sizeof(socklen_t));
			}
			break;

		case SYS_RECVMSG:
			do_recvmsg(ts, ret, (struct msghdr *)args[1]);
			break;

#ifdef CASCADING_RPS
		case SYS_SHUTDOWN:
			xchg_post_shutdown_hook(ts, ret);
			break;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
		case SYS_RECVMMSG:
			// invoke generic recvmmsg()
			do_recvmmsg(ts, (struct mmsghdr *)args[1],
					(struct timespec *)args[4], ret);
			break;
#endif
		default:
			/* nothing to do */
			return;
	}

#ifdef CASCADING_RPS
crps:
	xchg_post_socketcall_hook(ts, ctx, ret);
#endif
}

/* __NR_ipc post syscall hook */
static void
post_ipc_hook(struct thread_state *ts, CONTEXT *ctx, ADDRINT ret)
{
	union semun *su;
	ADDRINT second, third;

	// syscall failed, at least for the values that interest as
	if ((long)ret < 0)
		return;

	// ipc() is a demultiplexer for all SYSV IPC calls
	switch ((int)ts->sysargs[0]) {
		// msgctl()
		case MSGCTL:
			// fix the cmd parameter
			second = ts->sysargs[2] - IPC_FIX;

			// differentiate based on the cmd
			switch (second) {
				case IPC_STAT:
				case MSG_STAT:
					FLOGMARK(&ts->memcheckp.flog->filter, 
						ts->sysargs[4],
						sizeof(struct msqid_ds));
					break;

				case IPC_INFO:
				case MSG_INFO:
					FLOGMARK(&ts->memcheckp.flog->filter, 
						ts->sysargs[4],
						sizeof(struct msginfo));
					break;
			}
			break;

		// shmctl()
		case SHMCTL:
			// fix the cmd parameter
			second = ts->sysargs[2] - IPC_FIX;

			// differentiate based on the cmd
			switch (second) {
				case IPC_STAT:
				case SHM_STAT:
					FLOGMARK(&ts->memcheckp.flog->filter,
						ts->sysargs[4],
						sizeof(struct shmid_ds));
					break;

				case IPC_INFO:
				case SHM_INFO:
					FLOGMARK(&ts->memcheckp.flog->filter,
						ts->sysargs[4],
						sizeof(struct shminfo));
					break;
			}
			break;

		// semctl()
		case SEMCTL:
			// get the semun structure
			su = (union semun *)ts->sysargs[4];
			
			// fix the cmd parameter
			third = ts->sysargs[3] - IPC_FIX;

			// differentiate based on the cmd
			switch (third) {
				case IPC_STAT:
				case SEM_STAT:
					FLOGMARK(&ts->memcheckp.flog->filter, 
						(ADDRINT)su->buf, 
						sizeof(struct semid_ds));
					break;

				case IPC_INFO:
				case SEM_INFO:
					FLOGMARK(&ts->memcheckp.flog->filter, 
						(ADDRINT)su->buf, 
						sizeof(struct seminfo));
					break;
			}
			break;

		// msgrcv()
		case MSGRCV:
			// msgrcv() did not receive anything
			if ((long)ret == 0)
				return;
			
			FLOGMARK(&ts->memcheckp.flog->filter, ts->sysargs[4], 
					ret + sizeof(long));
			break;
	}
}

/* __NR_quotactl post syscall hook */
static void post_quotactl_hook(struct thread_state *ts, CONTEXT *ctx, 
		ADDRINT ret)
{
	size_t off;

	// quotactl() was not successful
	if ((long)ret < 0)
		return;
	
	// different offset ranges
	switch ((int)ts->sysargs[0]) {
		case Q_GETFMT:
			off = sizeof(__u32); 
			break;

		case Q_GETINFO:
			off = sizeof(struct if_dqinfo);
			break;

		case Q_GETQUOTA:
			off = sizeof(struct if_dqblk);
			break;

		case Q_XGETQSTAT:
			off = sizeof(struct fs_quota_stat);
			break;

		case Q_XGETQUOTA:
			off = sizeof(struct fs_disk_quota);
			break;

		default:
			return;
	}

	FLOGMARK(&ts->memcheckp.flog->filter, ts->sysargs[3], off);
}

/* __NR_readv post syscall hook */
static void post_readv_hook(struct thread_state *ts, CONTEXT *ctx, ADDRINT ret)
{
	if ((long)ret <= 0)
		return;

	do_recv_iovec(ts, ret, (struct iovec *)ts->sysargs[1], ts->sysargs[2]);

#ifdef CASCADING_RPS
	xchg_post_readv_hook(ts, ctx, ret, (struct iovec *)ts->sysargs[1], 
			ts->sysargs[2]);
#endif
}

/* __NR_preadv post syscall hook */
static void post_preadv_hook(struct thread_state *ts, CONTEXT *ctx, ADDRINT ret)
{
	if ((long)ret <= 0)
		return;

	do_recv_iovec(ts, ret, (struct iovec *)ts->sysargs[1], ts->sysargs[2]);
}

/* __NR__sysctl post syscall hook */
static void post__sysctl_hook(struct thread_state *ts, CONTEXT *ctx,
		ADDRINT ret)
{
	struct __sysctl_args *sa;

	// _sysctl() was not successful
	if ((long)ret < 0)
		return;

	// Mark_sysctl arguments
	sa = (struct __sysctl_args *)ts->sysargs[0];
	FLOGMARK(&ts->memcheckp.flog->filter, (ADDRINT)sa->newval, sa->newlen);

	// Mark old value
	if (sa->oldval != NULL) {
		FLOGMARK(&ts->memcheckp.flog->filter, 
				(ADDRINT)sa->oldval, *sa->oldlenp);
		FLOGMARK(&ts->memcheckp.flog->filter, 
				(ADDRINT)sa->oldlenp, sizeof(size_t));
	}
}

/* __NR_poll and __NR_ppoll post syscall hook */
static void post_poll_hook(struct thread_state *ts, CONTEXT *ctx, ADDRINT ret)
{
	size_t	i;
	struct	pollfd *pfd;

	// (p)poll() was not successful
	if ((long)ret <= 0)
		return;

	// iterate the pollfd structures
	for (i = 0; i < ts->sysargs[1]; i++) {
		// get pollfd
		pfd = ((struct pollfd *)ts->sysargs[0]) + i;
		FLOGMARK(&ts->memcheckp.flog->filter, 
				(ADDRINT)&pfd->revents, sizeof(short));
	}
}

/* __NR_prctl syscall hook */
static void post_prctl_hook(struct thread_state *ts, CONTEXT *ctx, ADDRINT ret)
{
	ADDRINT addr, len;

	// Did not complete successfully
	if ((long)ret < 0)
		return;

	switch (ts->sysargs[0]) {
# if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
	case PR_GET_ENDIAN:
# endif
# if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,18)
	case PR_GET_FPEMU:
# endif
# if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,21)
	case PR_GET_FPEXC:
# endif
# if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,15)
	case PR_GET_PDEATHSIG:
# endif
# if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
	case PR_GET_TSC:
# endif
	case PR_GET_UNALIGN:
		addr = ts->sysargs[1];
		len = sizeof(int);
		break;

# if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
	case PR_GET_NAME:
		addr = ts->sysargs[1];
		len = 16;
		break;
# endif
	default:
		return;
	}

	// Mark written locations
	FLOGMARK(&ts->memcheckp.flog->filter, addr, len);
}

/* __NR_getgroups post syscall_hook */
static void post_getgroups_hook(struct thread_state *ts, CONTEXT *ctx,
		ADDRINT ret)
{
	if ((long)ret <= 0 || ts->sysargs[1] == 0)
		return;
	// Mark written locations
	FLOGMARK(&ts->memcheckp.flog->filter, 
			ts->sysargs[1], ret * sizeof(gid_t));
}

/* __NR_mincore post syscall hook */
static void post_mincore_hook(struct thread_state *ts, CONTEXT *ctx,
		ADDRINT ret)
{
	// mincore() was not successful
	if ((long)ret < 0)
		return;
	// Mark written locations
	// Length is specified by man page
	FLOGMARK(&ts->memcheckp.flog->filter, ts->sysargs[2],
			(ts->sysargs[1] + PAGE_SIZE - 1) / PAGE_SIZE);
}

/* __NR_epoll_pwait post syscall hook */
static void post_epoll_wait_hook(struct thread_state *ts, CONTEXT *ctx, 
		ADDRINT ret)
{
	// epoll_pwait() was not successful
	if ((long)ret <= 0)
		return;

	// Mark written locations
	FLOGMARK(&ts->memcheckp.flog->filter, ts->sysargs[1], 
			sizeof(struct epoll_event) * ret);
}

/* __NR_read post syscall hook */
static void post_read_hook(struct thread_state *ts, CONTEXT *ctx, ADDRINT ret)
{
	// Mark written area
	if (ts->state == CHECKPOINTING && checkpoint_type == FORK_CHECKP) {
		DefaultSysExit(ts, ret, sysdesc + __NR_read);
	}

	// Default handler
#ifdef CASCADING_RPS
	xchg_post_read_hook(ts, ctx, ret);
#endif
}

/**
 * For pre-read, pre-write, post-write, post-close, and post-dup we only need to
 * do something if we are running with cascading RPs enabled.
 * */
#ifdef CASCADING_RPS
# define pre_read_hook xchg_pre_read_hook
# define pre_write_hook xchg_pre_write_hook
# define post_write_hook xchg_post_write_hook
# define post_close_hook xchg_post_close_hook
# define post_shutdown_hook xchg_post_shutdown_hook

/* __NR_writev post syscall hook */
static void post_writev_hook(struct thread_state *ts, CONTEXT *ctx, 
		ADDRINT ret)
{
	xchg_post_writev_hook(ts, ctx, ret, (struct iovec *)ts->sysargs[1], 
			ts->sysargs[2]);
}

/* __NR_dup family post syscall hook */
static void post_dup_hook(struct thread_state *ts, CONTEXT *ctx, ADDRINT ret)
{
	xchg_dupfd(ts, (int)ret, (int)ts->sysargs[0]);
}

#else
# define pre_read_hook NULL
# define pre_write_hook NULL
# define post_write_hook NULL
# define post_writev_hook NULL
# define post_close_hook NULL
# define post_shutdown_hook NULL
# define post_dup_hook NULL
#endif



/* syscall descriptors */
const struct syscall_desc sysdesc[SYSCALL_MAX] = {
	/* __NR_restart_syscall */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0}, NULL, NULL },
	/* __NR_exit */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_fork */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_read */
	{ SYS_CHCK|SYS_CRPS, 3, 0, { 0, 0, 0, 0, 0, 0 }, pre_read_hook, (post_call_t)post_read_hook},
	/* __NR_write */
	{ SYS_CHCK|SYS_CRPS, 3, 0, { 0, 0, 0, 0, 0, 0 }, pre_write_hook, (post_call_t)post_write_hook },
	/* __NR_open */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_close */
	{ SYS_CHCK|SYS_CRPS, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, (post_call_t)post_close_hook },
	/* __NR_waitpid */
	{ SYS_CHCK, 0, 2, { 0, sizeof(int), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_creat */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_link */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_unlink */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },	/* 10 */
	/* __NR_execve */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_chdir */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_time */
	{ SYS_CHCK, 0, 1, { sizeof(time_t), 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_mknod */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_chmod */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_lchown16 */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_break; not implemented */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_stat */
	{ SYS_CHCK, 0, 2, { 0, sizeof(struct __old_kernel_stat), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_lseek */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_getpid */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },	/* 20 */
	/* __NR_mount */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_oldumount */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setuid16 */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_getuid16 */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_stime */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_ptrace */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_alarm */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_fstat */
	{ SYS_CHCK, 0, 2, { 0, sizeof(struct __old_kernel_stat), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_pause */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_utime */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },	/* 30 */
	/* __NR_stty; not implemented */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_gtty; not implemented */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_access */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_nice */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_ftime; not implemented */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sync */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_kill */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_rename */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_mkdir */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_rmdir */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },	/* 40 */
	/* __NR_dup */
	{ SYS_CRPS, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_dup_hook },
	/* __NR_pipe */
	{ SYS_CHCK, 0, 1, { sizeof(int) * 2, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_times */
	{ SYS_CHCK, 0, 1, { sizeof(struct tms), 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_prof; not implemented */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_brk */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL }, // XXX
	/* __NR_setgid16 */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_getgid16 */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_signal */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_geteuid16 */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_getegid16 */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },	/* 50 */
	/* __NR_acct */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_umount */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_lock; not implemented */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_ioctl; TODO */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL }, // XXX
	/* __NR_fcntl */
	{ SYS_CHCK, 3, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_fcntl_hook },
	/* __NR_mpx; not implemented */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setpgid */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_ulimit; not implemented */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_olduname */
	{ SYS_CHCK, 1, 1, { sizeof(struct oldold_utsname), 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_umask */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },	/* 60 */
	/* __NR_chroot */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_ustat */
	{ SYS_CHCK, 2, 2, { 0, sizeof(struct ustat), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_dup2 */
	{ SYS_CRPS, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_dup_hook },
	/* __NR_getppid */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_getpgrp */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setsid */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sigaction */
	{ SYS_CHCK, 3, 3, { 0, 0, sizeof(struct old_sigaction), 0, 0, 0 }, NULL, NULL },
	/* __NR_sgetmask */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_ssetmask */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setreuid16 */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },	/* 70 */
	/* __NR_setregid16 */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sigsuspend */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sigpending*/
	{ SYS_CHCK, 1, 1, { sizeof(old_sigset_t), 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sethostname */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setrlimit */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_old_getrlimit */
	{ SYS_CHCK, 2, 2, { 0, sizeof(struct rlimit), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_getrusage */
	{ SYS_CHCK, 2, 2, { 0, sizeof(struct rusage), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_gettimeofday */
	{ SYS_CHCK, 2, 2, { sizeof(struct timeval), sizeof(struct timezone), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_settimeofday */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_getgroups */
	{ SYS_CHCK, 2, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_getgroups16_hook }, /* 80 */
	/* __NR_setgroups16 */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_select */
	{ SYS_CHCK, 4, 4, { 0, sizeof(fd_set), sizeof(fd_set), sizeof(fd_set), sizeof(struct timeval), 0 }, NULL, NULL },
	/* __NR_symlink */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_lstat */
	{ SYS_CHCK, 2, 2, { 0, sizeof(struct __old_kernel_stat), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_readlink */
	{ SYS_CHCK, 2, 2, { 0, INRETVAL, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_uselib; TODO */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL }, // XXX
	/* __NR_swapon */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_reboot */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_old_readdir */
	{ SYS_CHCK, 2, 2, { 0, sizeof(struct old_linux_dirent), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_old_mmap */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL }, /* 90 */
	/* __NR_munmap */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_truncate */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_ftruncate */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_fchmod */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_fchown16 */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_getpriority */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setpriority */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_profil; not implemented */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_statfs */
	{ SYS_CHCK, 2, 2, { 0, sizeof(struct statfs), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_fstatfs */
	{ SYS_CHCK, 2, 2, { 0, sizeof(struct statfs), 0, 0, 0, 0 }, NULL, NULL },
	/* 100 */
	/* __NR_ioperm */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_socketcall */
	{ SYS_CHCK|SYS_CRPS, 2, 0, { 0, 0, 0, 0, 0, 0 }, pre_socketcall_hook, (post_call_t)post_socketcall_hook },
	/* __NR_syslog */
	{ SYS_CHCK, 2, 2, { 0, INRETVAL, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setitimer */
	{ SYS_CHCK, 3, 3, { 0, 0, sizeof(struct itimerval), 0, 0, 0 }, NULL, NULL },
	/* __NR_getitimer */
	{ SYS_CHCK, 2, 2, { 0, sizeof(struct itimerval), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_newstat */
	{ SYS_CHCK, 2, 2, { 0, sizeof(struct stat), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_newlstat */
	{ SYS_CHCK, 2, 2, { 0, sizeof(struct stat), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_newfstat */
	{ SYS_CHCK, 2, 2, { 0, sizeof(struct stat), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_uname */
	{ SYS_CHCK, 1, 1, { sizeof(struct new_utsname), 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_iopl */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },	/* 110 */
	/* __NR_vhangup */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_idle; not implemented */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_vm86old */
	{ SYS_CHCK, 1, 1, { sizeof(struct vm86_struct), 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_wait4 */
	{ SYS_CHCK, 4, 4, { 0, sizeof(int), 0, sizeof(struct rusage), 0, 0 }, NULL, NULL },
	/* __NR_swapoff */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sysinfo */
	{ SYS_CHCK, 1, 1, { sizeof(struct sysinfo), 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_ipc */
	{ SYS_CHCK, 6, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_ipc_hook },
	/* __NR_fsync */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sigreturn */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_clone */
	{ SYS_CHCK, 3, 3, { 0, 0, sizeof(int), 0, 0, 0 }, NULL, NULL },
	/* 120 */
	/* __NR_setdomainname */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_newuname */
	{ SYS_CHCK, 1, 1, { sizeof(struct new_utsname), 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_modify_ldt */
	{ SYS_CHCK, 2, 0, { 0, INRETVAL, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_adjtimex */
	{ SYS_CHCK, 1, 1, { sizeof(struct timex), 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_mprotect */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL},
	/* __NR_sigprocmask */
	{ SYS_CHCK, 3, 3, { 0, 0, sizeof(old_sigset_t), 0, 0, 0 }, NULL, NULL },
	/* __NR_create_module; not implemented */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_init_module */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_delete_module */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_get_kernel_syms; not implemented */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },	/* 130 */
	/* __NR_quotactl */
	{ SYS_CHCK, 2, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_quotactl_hook },
	/* __NR_getpgid */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_fchdir */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_bdflush */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sysfs */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_personality */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_afs_syscall; not implemented */
        { 0, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setfsuid16 */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setfsgid16 */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR__llseek */
	{ SYS_CHCK, 4, 4, { 0, 0, 0, sizeof(loff_t), 0, 0 }, NULL, NULL },/* 140 */
	/* __NR_getdents */
	{ SYS_CHCK, 2, 2, { 0, sizeof(struct linux_dirent), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_select */
	{ SYS_CHCK, 5, 5, { 0, sizeof(fd_set), sizeof(fd_set), sizeof(fd_set), sizeof(struct timeval), 0 }, NULL, NULL },
	/* __NR_flock */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_msync */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_readv */
	{ SYS_CHCK|SYS_CRPS, 3, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_readv_hook },
	/* __NR_writev */
	{ SYS_CRPS, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_writev_hook },
	/* __NR_getsid */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_fdatasync */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR__sysctl */
	{ SYS_CHCK, 1, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post__sysctl_hook },
	/* __NR_mlock */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL }, /* 150 */
	/* __NR_munlock */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_mlockall */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_munlockall */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sched_setparam */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sched_getparam */
	{ SYS_CHCK, 2, 2, { 0, sizeof(struct sched_param), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sched_setscheduler */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sched_getscheduler*/
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sched_yield */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sched_get_priority_max */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sched_get_priority_min */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL }, /* 160 */
	/* __NR_sched_rr_get_interval */
	{ SYS_CHCK, 2, 2, { 0, sizeof(struct timespec), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_nanosleep */
	{ SYS_CHCK, 2, 2, { 0, sizeof(struct timespec), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_mremap; TODO */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL }, // XXX
	/* __NR_setresuid16 */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_getresuid16 */
	{ SYS_CHCK, 3, 3, { sizeof(old_uid_t), sizeof(old_uid_t), sizeof(old_uid_t), 0, 0, 0 }, NULL, NULL },
	/* __NR_ptregs_vm86 */
	{ SYS_CHCK, 2, 2, { 0, sizeof(struct vm86plus_struct), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_query_module; not implemented */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_poll */
	{ SYS_CHCK, 2, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_poll_hook },
	/* __NR_nfsservctl; TODO */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setresgid16 */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL }, /* 170 */
	/* __NR_getresgid16 */
	{ SYS_CHCK, 3, 3, { sizeof(old_gid_t), sizeof(old_gid_t), sizeof(old_gid_t), 0, 0, 0 }, NULL, NULL },
	/* __NR_prctl */
	{ SYS_CHCK, 2, 0, { 0, 0, 0, 0, 0, 0 }, NULL,  post_prctl_hook},
	/* __NR_rt_sigreturn */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_rt_sigaction */
	{ SYS_CHCK, 3, 3, { 0, 0, sizeof(struct sigaction), 0, 0, 0 }, NULL, NULL },
	/* __NR_rt_sigprocmask */
	{ SYS_CHCK, 3, 3, { 0, 0, sizeof(sigset_t), 0, 0, 0 }, NULL, NULL },
	/* __NR_rt_sigpending */
	{ SYS_CHCK, 2, 1, { -2, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_rt_sigtimedwait */
	{ SYS_CHCK, 2, 2, { 0, sizeof(siginfo_t), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_rt_sigqueueinfo */
	{ SYS_CHCK, 3, 3, { 0, 0, sizeof(siginfo_t), 0, 0, 0 }, NULL, NULL },
	/* __NR_rt_sigsuspend */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_pread64 */
	{ SYS_CHCK, 2, 2, { 0, INRETVAL, 0, 0, 0, 0 }, NULL, NULL }, /* 180 */
	/* __NR_pwrite64 */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_chown16 */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_getcwd */
	{ SYS_CHCK, 1, 1, { INRETVAL, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_capget */
	{ SYS_CHCK, 2, 2, { sizeof(cap_user_header_t), sizeof(cap_user_data_t), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_capset */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sigaltstack */
	{ SYS_CHCK, 2, 2, { 0, sizeof(stack_t), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sendfile */
	{ SYS_CHCK, 3, 4, { 0, 0, sizeof(off_t), 0, 0, 0 }, NULL, NULL },
	/* __NR_streams1; not implemented */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_streams2; not implemented */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_vfork */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL }, /* 190 */
	/* __NR_getrlimit */
	{ SYS_CHCK, 2, 2, { 0, sizeof(struct rlimit), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_mmap2 */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_truncate64 */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_ftruncate64 */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_stat64 */
	{ SYS_CHCK, 2, 2, { 0, sizeof(struct stat64), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_lstat64 */
	{ SYS_CHCK, 2, 2, { 0, sizeof(struct stat64), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_fstat64 */
	{ SYS_CHCK, 2, 2, { 0, sizeof(struct stat64), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_lchown */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_getuid */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_getgid */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL }, /* 200 */
	/* __NR_geteuid */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_getegid */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setreuid */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setregid */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_getgroups */
	{ SYS_CHCK, 2, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_getgroups_hook },
	/* __NR_setgroups */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_fchown */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setresuid */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_getresuid */
	{ SYS_CHCK, 3, 3, { sizeof(uid_t), sizeof(uid_t), sizeof(uid_t), 0, 0, 0 }, NULL, NULL },
	/* __NR_setresgid */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL }, /* 210 */
	/* __NR_getresgid */
	{ SYS_CHCK, 3, 4, { sizeof(gid_t), sizeof(gid_t), sizeof(gid_t), 0, 0, 0 }, NULL, NULL },
	/* __NR_chown */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setuid */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setgid */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setfsuid */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setfsgid */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_pivot_root */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_mincore */
	{ SYS_CHCK, 3, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_mincore_hook },
	/* __NR_madvise */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_getdents */
	{ SYS_CHCK, 2, 2, { 0, INRETVAL, 0, 0, 0, 0 }, NULL, NULL }, /* 220 */
	/* __NR_fcntl64 */
	{ SYS_CHCK, 3, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_fcntl_hook },
	/* __NR_TUX; not implemented */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_223 ; not implemented  */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_gettid */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_readahead */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_setxattr */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_lsetxattr */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_fsetxattr */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_getxattr */
	{ SYS_CHCK, 3, 3, { 0, 0, INRETVAL, 0, 0, 0 }, NULL, NULL },
	/* __NR_lgetxattr */
	{ SYS_CHCK, 3, 3, { 0, 0, INRETVAL, 0, 0, 0 }, NULL, NULL }, /* 230 */
	/* __NR_fgetxattr */
	{ SYS_CHCK, 3, 3, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_listxattr */
	{ SYS_CHCK, 2, 2, { 0, INRETVAL, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_llistxattr */
	{ SYS_CHCK, 2, 2, { 0, INRETVAL, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_flistxattr */
	{ SYS_CHCK, 2, 2, { 0, INRETVAL, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_removexattr */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_lremovexattr */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_fremovexattr */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_tkill */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sendfile64 */
	{ SYS_CHCK, 3, 3, { 0, 0, sizeof(loff_t), 0, 0, 0 }, NULL, NULL },
	/* __NR_futex */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL }, /* 240 */
	/* __NR_sched_setaffinity */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_sched_getaffinity */
	{ SYS_NONE, 3, 3, { 0, 0, sizeof(cpu_set_t), 0, 0, 0 }, NULL, NULL },
	/* __NR_set_thread_area */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_get_thread_area */
	{ SYS_CHCK, 1, 1, { sizeof(struct user_desc), 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_io_setup */
	{ SYS_CHCK, 2, 2, { 0, sizeof(aio_context_t), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_io_destroy */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_io_getevents */
	{ SYS_CHCK, 5, 5, { 0, 0, 0, sizeof(struct io_event), INRETVAL, 0 }, NULL, NULL },
	/* __NR_io_submit */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_io_cancel */
	{ SYS_CHCK, 3, 3, { 0, 0, sizeof(struct io_event), 0, 0, 0 }, NULL, NULL },
	/* __NR_fadvise64 */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL }, /* 250 */
	/* __NR_251; not implemented */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_exit_group */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_lookup_dcookie */
	{ SYS_CHCK, 2, 2, { 0, INRETVAL, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_epoll_create */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_epoll_ctl */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_epoll_wait */
	{ SYS_CHCK, 2, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_epoll_wait_hook },
	/* __NR_remap_file_pages; TODO */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_set_tid_address */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_timer_create */
	{ SYS_CHCK, 3, 3, { 0, 0, sizeof(timer_t), 0, 0, 0 }, NULL, NULL },
	/* __NR_timer_settime */
	{ SYS_CHCK, 4, 4, { 0, 0, 0, sizeof(struct itimerspec), 0, 0 }, NULL, NULL },
	/* 260 */
	/* __NR_timer_gettime */
	{ SYS_CHCK, 2, 2, { 0, sizeof(struct itimerspec), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_timer_getoverrun */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_timer_delete */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_clock_settime */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_clock_gettime */
	{ SYS_CHCK, 2, 2, { 0, sizeof(struct timespec), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_clock_getres */
	{ SYS_CHCK, 2, 2, { 0, sizeof(struct timespec), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_clock_nanosleep */
	{ SYS_CHCK, 4, 4, { 0, 0, 0, sizeof(struct timespec), 0, 0 }, NULL, NULL },
	/* __NR_statfs64 */
	{ SYS_CHCK, 3, 3, { 0, 0, sizeof(struct statfs64), 0, 0, 0 }, NULL, NULL },
	/* __NR_fstatfs64 */
	{ SYS_CHCK, 2, 2, { 0, 0, sizeof(struct statfs64), 0, 0, 0 }, NULL, NULL },
	/* __NR_tgkill */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL }, /* 270 */
	/* __NR_utimes */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_fadvise64_64 */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_vserver; not implemented */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_mbind */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_get_mempolicy */
	{ SYS_CHCK, 2, 2, { sizeof(int), sizeof(unsigned long), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_set_mempolicy */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_mq_open */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_mq_unlink */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_mq_timedsend */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },	
	/* __NR_mq_timedreceive */
	{ SYS_CHCK, 4, 4, { 0, INRETVAL, 0, sizeof(unsigned), 0, 0 }, NULL, NULL },
	/* 280 */
	/* __NR_mq_notify */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_mq_getsetattr */
	{ SYS_CHCK, 3, 3, { 0, 0, sizeof(struct mq_attr), 0, 0, 0 }, NULL, NULL },
	/* __NR_kexec_load */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_waitid */
	{ SYS_CHCK, 5, 5, { 0, 0, sizeof(siginfo_t), 0, sizeof(struct rusage), 0 }, NULL, NULL },
	/* __NR_285; not implemented */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_add_key */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_request_key */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_keyctl */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_ioprio_set */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_ioprio_get */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL }, /* 290 */
	/* __NR_inotify_init */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_inotify_add_watch */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_inotify_rm_watch */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_migrate_pages */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_openat */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_mkdirat */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_mknodat */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_fchownat */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_futimesat */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_fstatat64 */
	{ SYS_CHCK, 3, 3, { 0, 0, sizeof(struct stat64), 0, 0, 0 }, NULL, NULL },
	/* 300 */
	/* __NR_unlinkat */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_renameat */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_linkat */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_symlinkat */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_readlinkat */
	{ SYS_CHCK, 3, 3, { 0, 0, INRETVAL, 0, 0, 0 }, NULL, NULL },
	/* __NR_fchmodat */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_faccessat */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_pselect6 */
	{ SYS_CHCK, 4, 4, { 0, sizeof(fd_set), sizeof(fd_set), sizeof(fd_set), 0, 0 }, NULL, NULL },
	/* __NR_ppoll */
	{ SYS_CHCK, 2, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_poll_hook },
	/* __NR_unshare */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL }, /* 310 */
	/* __NR_set_robust_list */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_get_robust_list */
	{ SYS_CHCK, 3, 3, { 0, sizeof(struct robust_list_head *), sizeof(size_t), 0, 0, 0 }, NULL, NULL },
	/* __NR_splice */
	{ SYS_CHCK, 4, 4, { 0, sizeof(loff_t), 0, sizeof(loff_t), 0, 0 }, NULL, NULL },
	/* __NR_sync_file_range */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_tee */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_vmsplice */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_move_pages */
	{ SYS_CHCK, 5, 5, { 0, 0, 0, 0, sizeof(int), 0 }, NULL, NULL },
	/* __NR_getcpu */
	{ SYS_CHCK, 3, 3, { sizeof(unsigned), sizeof(unsigned), sizeof(struct getcpu_cache), 0, 0, 0 }, NULL, NULL },
	/* __NR_epoll_pwait */
	{ SYS_CHCK, 2, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_epoll_wait_hook },
	/* __NR_utimensat */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL }, /* 320 */
	/* __NR_signalfd */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_timerfd_create */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_eventfd */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_fallocate */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },

	/* __NR_timerfd_settime */
	{ SYS_CHCK, 4, 4, { 0, 0, 0, sizeof(struct itimerspec), 0, 0 }, NULL, NULL },
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
	/* __NR_timerfd_gettime  */
	{ SYS_CHCK, 2, 2, { 0, sizeof(struct itimerspec), 0, 0, 0, 0 }, NULL, NULL },
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	/* __NR_signalfd4 */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_eventfd2 */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_epoll_create1 */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_dup3 */
	{ SYS_CRPS, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_dup_hook }, /* 330 */
	/* __NR_pipe2 */
	{ SYS_CHCK, 1, 1, { sizeof(int) * 2, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_inotify_init1 */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
	/* __NR_preadv */
	{ SYS_CHCK, 3, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_preadv_hook },
	/* __NR_pwritev */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
#endif
#if LINUX_VERSION_CODE == KERNEL_VERSION(2,6,31)
	/* __NR_rt_tgsigqueueinfo */
	{ SYS_CHCK, 4, 4, { 0, 0, 0, sizeof(siginfo_t), 0, 0 }, NULL, NULL },
	/* __NR_perf_counter_open */
	{ SYS_CHCK, 1, 1, { sizeof(struct perf_counter_attr), 0, 0, 0, 0, 0 }, NULL, NULL },
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
	/* __NR_rt_tgsigqueueinfo */
	{ SYS_CHCK, 4, 4, { 0, 0, 0, sizeof(siginfo_t), 0, 0 }, NULL, NULL },
	/* __NR_perf_event_open */
	{ SYS_CHCK, 1, 1, { sizeof(struct perf_event_attr), 0, 0, 0, 0, 0 }, NULL,
	NULL },
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
	/* __NR_recvmmsg */
	{ SYS_CHCK, 5, 0, { 0, 0, 0, 0, 0, 0 }, NULL, post_recvmmsg_hook },
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
	/* __NR_fanotify_init */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_fanotify_mark */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_pnatedmlimit64 */
	{ SYS_CHCK, 4, 4, { 0, 0, 0, sizeof(struct rlimit64), 0, 0 }, NULL, NULL },
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
	/* __NR_name_to_handle_at */
	{ SYS_CHCK, 4, 4, { 0, 0, sizeof(struct file_handle), sizeof(int), 0, 0 }, NULL, NULL },
	/* __NR_open_by_handle_at */
	{ SYS_CHCK, 2, 2, { 0, sizeof(struct file_handle), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_clock_adjtime */
	{ SYS_CHCK, 2, 2, { 0, sizeof(struct timex), 0, 0, 0, 0 }, NULL, NULL },
	/* __NR_syncfs */
	{ SYS_NONE, 0, 0, { 0, 0, 0, 0, 0, 0 }, NULL, NULL },
#endif
};

