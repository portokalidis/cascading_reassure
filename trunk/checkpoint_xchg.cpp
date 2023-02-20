#include <iostream>
#include <cassert>
#include <sstream>
#include <vector>

extern "C" {
#include <sys/syscall.h>
#include <sys/socket.h>
#include <linux/net.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
}

#include "pin.H"
#include "log.hpp"
#include "libreassure.hpp"
#include "syscall.hpp"
#include "threadstate.hpp"
#include "checkpoint_xchg.hpp"
#include "fork.h"
#include "likely.h"


//#define DISABLE_XCHG
// XXX: Fix this to dynamically extend
//#define MAX_FD 1024
#define MAX_FD 65536

// How many milliseconds to sleep, if we cannot send a message because a socket
// would sleep
#define BLOCKING_SOCK_SLEEP 100

//! possible descriptor states
#define FD_UNHANDLED		0 //!< Unhandled
#define FD_NORMAL		1 //!< Socket in normal communications mode
#define FD_CHECKPOINTING	2 //!< Socket signaled to checkpoint
#define FD_CANCEL		3 //!< Socket that needs to be rolled back

//! Socket commands
#define CMD_INVALID		0 //!< 0 is not a valid command
#define CMD_NORMAL		1 //!< Normal protocol command
#define CMD_CHECKPOINT		2 //!< Checkpoint protocol command
#define CMD_COMMIT		3 //!< Commit protocol command
#define CMD_ROLLBACK		4 //!< Rollback protocol command
#define CMD_ROLLNCHECK		5 //!< Rollback and checkpoint protocol command

//! Enumeration for separating pre- and post-read() system call execution
typedef enum READ_POS_ENUM { PRE_READ_POS = 0, POST_READ_POS } read_pos_t;

typedef struct fd_info {
	UINT8 state;
	/* Protocol header for reads */
	hdr_data_t hdr;
	/* Number of bytes of header read */
	unsigned int hdr_cur;
	/* Read cursor, how many bytes have been read from the encapsulated 
	 * message */
	ADDRINT read_cur;
	/* How many bytes in total is the currently read encapsulated message */
	ADDRINT read_len;
	/* Buffer to store buffered read data */
	UINT8 *readbuf,
	      *rdbuf_cur; /* Pointer to read buffered data from */
	unsigned int rdbuf_size, /* Size of readbuf */
		     rdbuf_count; /* Number of bytes in readbuf */
	/* to be extended */
} fd_info_t;



/* global variables */
static fd_info_t *fd_info = NULL;


#if 0
#define SAVESYSARGS(ctx, std, ts, args) \
	do {\
		for (int i = 0; i < (args); i++)\
			(ts)->sysargs[i] = PIN_GetSyscallArgument(ctx, std, i);\
	} while (0)
#endif



/*****************************************
 * instrumented system calls in pre-phase 
 * ***************************************/

static inline int force_read(int fd, UINT8 *buf, size_t len)
{
#ifdef CXCHG_DEBUG
	stringstream ss;
#endif
	int ret;

	while (1) {
		ret = read(fd, buf, len);
		if (likely(ret == (int)len || ret == 0))
			break; // Done reading or EOF
		else if (ret < 0) {
			// Check the errno returned
			if(errno == EAGAIN || errno == EWOULDBLOCK) {
				PIN_Sleep(BLOCKING_SOCK_SLEEP);
				continue;
			}
			// Otherwise real error
#ifdef CXCHG_DEBUG
			ss << "read: failed for socket["<< fd << "]" << endl;
			ss << "read: emulate user's read failed.."<< endl;
			DBGLOG(ss);
#endif
			return errno;
		}
#ifdef CXCHG_DEBUG
		ss << "read less for tbuf_len ret=" << ret << endl;
		DBGLOG(ss);
#endif
		/* We have only read some of the data */
		buf += ret;
		len -= ret;
		/* Instead of sleeping, just be good to other threads */
		PIN_Yield();
	} /* while (1) */
	return 0;
}

/* Patch read system call to perform a readv() which will also read the
 * header */
static inline void patch_read(CONTEXT *ctx, struct thread_state *ts,
		SYSCALL_STANDARD std, fd_info_t *info)
{
	// Build iovec
	// Read remaining header in vector 1
	ts->vec[0].iov_base = (UINT8 *)&info->hdr + info->hdr_cur;
	ts->vec[0].iov_len = sizeof(hdr_data_t) - info->hdr_cur;
	// Read data in vector 2
	ts->vec[1].iov_base = (void *)ts->sysargs[1];
	ts->vec[1].iov_len = ts->sysargs[2];

	// Change system call to perform to readv
	PIN_SetSyscallNumber(ctx, std, SYS_readv);
	// Patch iovec
	PIN_SetSyscallArgument(ctx, std, 1, (ADDRINT)ts->vec);
	// Patch number of buffer in the iovec
	PIN_SetSyscallArgument(ctx, std, 2, 2);
}

static inline size_t read_buffered_data(fd_info_t *info, UINT8 *buf, size_t len)
{
	if (len > info->rdbuf_count) // We can read up to rdbuf_count
		len = info->rdbuf_count;
	memcpy(buf, info->rdbuf_cur, len);
	info->rdbuf_count -= len;
	if (info->rdbuf_count > 0)
		info->rdbuf_cur += len;
	else
		info->rdbuf_cur = 0;
	return len;
}

/**
 * Read header from data obtained by a previous read system call.
 *
 * @param info Pointer to file descriptor info
 */
static inline void read_buffered_hdr(fd_info_t *info)
{
	size_t len;

	len = sizeof(hdr_data_t) - info->hdr_cur;
	if (len > info->rdbuf_count) // We can read up to rdbuf_count
		len = info->rdbuf_count;
	memcpy((UINT8 *)&info->hdr + info->hdr_cur, 
			info->rdbuf_cur, len);
	info->hdr_cur += len;
	info->rdbuf_count -= len;
	if (info->rdbuf_count > 0)
		info->rdbuf_cur += len;
	else
		info->rdbuf_cur = 0;
}

/**
 * Process the command received during a read().
 *
 * @param fd File descriptor the command was received on
 * @param ts Pointer to thread state
 * @param ctx Pointer to Pin's execution context
 * @param position PRE_READ_POS if called before read() executes and
 * POST_READ_POS if after.
 */
static void process_read_cmd(int fd, struct thread_state *ts, 
		CONTEXT *ctx, read_pos_t position)
{
	struct f_owner_ex f_own;
	stringstream ss;

	// Process command and Perform state transitions
	switch (fd_info[fd].hdr.cmd) {
	 case CMD_NORMAL:
		break;

	case CMD_CHECKPOINT:
		// Should be ts->state == NORMAL
		if (ts->state == NORMAL) {
			// start checkpointing
#ifdef CXCHG_DEBUG
			ss << "process_read_cmd: checkpointing " << endl;
			DBGLOG(ss);
#endif
			ts->checkpoint_fd = fd;
			CheckpointCreate(ts, ctx);

			// but if cmd received in post-read
			// we should set the values of ts->checkpoint
			// to the values of registers EAX, EBX, ECX, EDX
			// saved in the pre-read phase
			if (position == POST_READ_POS) {
				PIN_SetContextReg(ts->checkpoint, 
						LEVEL_BASE::REG_EAX, 
						ts->in_syscall);
				PIN_SetContextReg(ts->checkpoint, 
						LEVEL_BASE::REG_EBX, 
						ts->sysargs[0]);
				PIN_SetContextReg(ts->checkpoint, 
						LEVEL_BASE::REG_ECX, 
						ts->sysargs[1]);
				PIN_SetContextReg(ts->checkpoint, 
						LEVEL_BASE::REG_EDX, 
						ts->sysargs[2]);
			}

			// Set code cache version
			PIN_SetContextReg(ctx, version_reg, CHECKPOINT_VERSION);
			
			// Save previous socket owner, and replace with currect
			// TID to receive SIGURG when OOB data arrives
			if (fcntl(fd, F_GETOWN_EX, &ts->previous_owner) != 0) {
				ss << "ERROR: fcntl(F_GETOWN_EX) failed" << 
					strerror(errno) << endl;
				OUTLOG(ss);
			}

			f_own.type = F_OWNER_TID;
			f_own.pid = ts->real_tid;

			if (fcntl(fd, F_SETOWN_EX, &f_own) != 0) {
				ss << "ERROR: fcntl(F_SETOWN_EX) failed" << 
					strerror(errno) << endl;
				ERRLOG(ss);
				PIN_ExitApplication(EXIT_FAILURE);
			}
		} else {
			// could be checkpointing or rolling back, in any way
			// ignore the request
			if (ts->checkpoint_fd != fd) {
				OUTLOG("WARNING: Received remote checkpoint"
						" request, but already "
						"checkpointing\n");
			}
		}
		break;

	case CMD_COMMIT:
		if (ts->state == CHECKPOINTING && ts->checkpoint_fd == fd) {
			// unexpected because we should do this with OOB
			// but we can still support it
			// XXX: Implement commit
			ts->checkpoint_fd = -1;
		} else {
			ss << "ERROR: Unexpected socket command (COMMIT) from "
				"socket " << fd << ". Checkpointing socket is " 
				<< ts->checkpoint_fd << endl;
			OUTLOG(ss);
		}
		break;

	case CMD_ROLLBACK:
		if (ts->state == CHECKPOINTING && ts->checkpoint_fd == fd) {
#ifdef CXCHG_DEBUG
			ss << "process_read_cmd: rolling back" << endl;
			DBGLOG(ss);
#endif
			// We are no longer checkpointing for any fd
			ts->checkpoint_fd = -1;

			reassure_rollback(ts, ctx, ts->saved_pc);

			// Mark sockets as cancelled
			xchg_remote_rollback(ts); 

			//PIN_ExecuteAt(ctx);
		} else {
			ERRLOG("ERROR: Cancel socket command but thread"
					" not checkpointing\n");
		}
		break;

	case CMD_ROLLNCHECK:
		// Should be ts->state == CHECKPOINTING
		// XXX: this is tricky, leave for later
		ERRLOG("ERROR: Unexpected socket rollback "
				"and checkpoint command\n");
		break;
	}
}

/*
 * if we are reading a new message, first read the message size(4 bytes)
 * then the state-flag(1 byte) for the socket, and finally let the application
 * get the actual data.
 *
 * Note: in pre-phase, for arg1 only the memory address where its
 * content will be stored is available, not the actual content 
 *
 */

void xchg_pre_read_hook(struct thread_state *ts, CONTEXT *ctx,
		SYSCALL_STANDARD std)
{
#ifdef DISABLE_TXCHG
	return;
#endif
	int fd, len, l;
	fd_info_t *info;
	bool patch_readv, patch_len;
#ifdef CXCHG_DEBUG
	stringstream ss;
#endif

	fd = ts->sysargs[0];
	info = fd_info + fd;

	if(info->state == FD_UNHANDLED)
		return;

	// If the thread is running normally save the EIP in case we are going
	// to start checkpointing
	if (ts->state == NORMAL)
		ts->saved_pc = PIN_GetContextReg(ctx, REG_INST_PTR);

	len = ts->sysargs[2];
	patch_len = patch_readv = false;

#ifdef CXCHG_DEBUG
	ss << "pre_read: len=" << len << ", read_cur=" << info->read_cur <<
		", read_len=" << info->read_len << endl;
	DBGLOG(ss);
#endif

	if (info->hdr_cur < sizeof(hdr_data_t)) { // Read new message header
		if (info->rdbuf_count > 0) { // Read from buffered data
#ifdef CXCHG_DEBUG
			ss << "pre_read: new message header from buffered "
				"data count=" << info->rdbuf_count << endl;
			DBGLOG(ss);
#endif
			read_buffered_hdr(info);
			// Not enough buffered data, setup readv to read header
			if (info->hdr_cur < sizeof(hdr_data_t)) {
				patch_readv = true;
			} else {
				// Process cmd in socket message
				process_read_cmd(fd, ts, ctx, PRE_READ_POS);
				// I know how much to read
				info->read_len = info->hdr.len;
				info->hdr_cur = sizeof(hdr_data_t);
			}
		} else { // Setup readv to read header
#ifdef CXCHG_DEBUG
			ss << "pre_read: new message read=" << 
				len + sizeof(hdr_data_t) << ", actual=" << 
				len << endl;
			DBGLOG(ss);
#endif
			patch_readv = true;
		}
		
		// We still need to read a header so we replace the read() with
		// a readv()
		if (patch_readv) {
#ifdef CXCHG_DEBUG
			DBGLOG("pre_read: replacing read() with readv()\n");
#endif
			patch_read(ctx, ts, std, info);
			return;
		}
	}

	/* We have a header for the message, 
	 * so we can fixup the read parameters */

	// We will not read past this message
	if ((info->read_cur + len) > info->read_len) {
		len = info->read_len - info->read_cur;
		patch_len = true;
	}

	// There is still buffered data
	if (info->rdbuf_count > 0) { 		
		l = read_buffered_data(info, (UINT8 *)ts->sysargs[1], len);
#ifdef CXCHG_DEBUG
		ss << "pre_read: reading buffered data l=" << l << endl;
		DBGLOG(ss);
#endif
		if (l < len) {
			// Setup the read to read the rest of the message
			len -= l;
			ts->already_read = l;
			patch_len = true;
			// Patch buf so that we combine the buffered data, with
			// newly read data
			PIN_SetSyscallArgument(ctx, std, 1, ts->sysargs[1] + l);
#ifdef CXCHG_DEBUG
			ss << "pre_read: reading remaining data from socket=" << 
				len << endl;
			DBGLOG(ss);
#endif
		} else {
			// We do not need to read anything
			PIN_SetSyscallNumber(ctx, std, SYS_getpid);
			ts->already_read = len;
			patch_len = false;
			ts->fake_read = true;
#ifdef CXCHG_DEBUG
			ss << "pre_read: everything is buffered len=" << len <<
				", user len=" << ts->sysargs[2] << endl;
			DBGLOG(ss);
#endif

		}
	} else // Nothing buffered
		ts->already_read = 0;
	
	// Patch the length of the read so we stay in the same message
	if (patch_len) {
#ifdef CXCHG_DEBUG
		ss << "pre_read: patching read length to " << len << endl;
		DBGLOG(ss);
#endif
		PIN_SetSyscallArgument(ctx, std, 2, len);
	}
}

/* Patch write system call to perform a writev() which will also write the
 * header */
static inline void patch_write(CONTEXT *ctx, struct thread_state *ts, 
		UINT8 cmd, SYSCALL_STANDARD std)
{
	// Build iovec
	ts->vec[0].iov_base = &ts->write_hdr;
	ts->vec[0].iov_len = sizeof(hdr_data_t);
	ts->vec[1].iov_base = (void *)ts->sysargs[1];
	ts->vec[1].iov_len = ts->sysargs[2];
	// Setup header
	//ts->write_hdr.id = 1;// XXX it should be (ts->id), for now we set it to 1; 
	ts->write_hdr.len = ts->sysargs[2];
	ts->write_hdr.cmd = cmd;

#ifdef CXCHG_DEBUG
	stringstream ss;
	ss << "pre_write: hdr.len="<< ts->write_hdr.len << 
		" , hdr.cmd = " << +ts->write_hdr.cmd <<endl;
	DBGLOG(ss);
#endif

	// Change system call to perform to writev
	PIN_SetSyscallNumber(ctx, std, SYS_writev);
	// Patch iovec
	PIN_SetSyscallArgument(ctx, std, 1, (ADDRINT)ts->vec);
	// Patch number of buffer in the iovec
	PIN_SetSyscallArgument(ctx, std, 2, 2);
}

/* Keep trying to write the buf until it is entirely written, or until an error
 * occurs.
 * Returns 0 on success, or errno in case of error */
static int force_write(int fd, UINT8 *buf, size_t len)
{
#ifdef CXCHG_DEBUG
	stringstream ss;
#endif
	int ret;

	/* Send the extra header, retry if cannot get it in one write() */
	while (1) {
		ret = write(fd, buf, len);
		if (likely(ret == (int)len))
			return 0; // Done writing
		else if (ret < 0) {
			// Non-blocking sockets may fail and set errno to these
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				PIN_Sleep(BLOCKING_SOCK_SLEEP);
				continue;
			}
#ifdef CXCHG_DEBUG
			ss << "force_write(): buf_len: ret=" << decstr(ret) << endl ;
			DBGLOG(ss);
#endif
			return errno;
		}
#ifdef CXCHG_DEBUG
		ss << "force_write(): buf_len: ret=" << decstr(ret) << endl ;
		DBGLOG(ss);
#endif
		/* We have only written some of the data */
		buf += ret;
		len -= ret;
		/* Instead of sleeping, just be good to other threads */
		PIN_Yield();
	}
	return 0;
}

/* Complete a failed write until the buffer is entirely written, or until an 
 * error occurs.
 * Returns 0 on success, or errno in case of error */
static inline int complete_write(struct thread_state *ts, size_t written)
{
#ifdef CXCHG_DEBUG
	stringstream ss;
#endif
	int ret;

	// Could not even write header
	if (written < sizeof(hdr_data_t)) {
		// Write the remainer of the header
		ret = force_write(ts->sysargs[0], 
				(UINT8 *)&ts->write_hdr + written, 
				sizeof(hdr_data_t) - written);
		if (ret < 0)
			return ret;
		// 0 bytes of data were written
		written = 0;
	} else {
		// Header was written successfully
		// Mark the header as written properly, 
		written -= sizeof(hdr_data_t);
	}

	return force_write(ts->sysargs[0], (UINT8 *)ts->sysargs[1], 
			ts->sysargs[2] - written);
}

/*
 * prepend each message with 1.the new total number of bytes to 
 * write to socket and 2. info (unsigned int) for updating the socket state at the
 * receiver
 */
void xchg_pre_write_hook(struct thread_state *ts, CONTEXT *ctx, 
		SYSCALL_STANDARD std)
{
#ifdef DISABLE_XCHG
	return;
#endif
	stringstream ss;
	int fd;
	fd_info_t *info;
	UINT8 mode = CMD_NORMAL;

	fd = ts->sysargs[0];
	info = fd_info + fd;
	if (info->state == FD_UNHANDLED)
		return;

	switch (ts->state) {
	case NORMAL: // Thread is in NORMAL
		if (likely(info->state == FD_NORMAL))
			mode = CMD_NORMAL;
		else if (info->state == FD_CANCEL) {
			mode = CMD_ROLLBACK;
			info->state = FD_NORMAL;
#ifdef CXCHG_DEBUG
			ss << "pre_write: update socket[" << fd << "].state=" << 
				(int)fd_info[fd].state << 
				" notify the receiver to rollback" << endl;
			DBGLOG(ss);
#endif
		} else {
			ss << "pre_write: Unexpected socket["<< fd << 
				"] state is " << (int)fd_info[fd].state << endl;
			ERRLOG(ss);
		}
		break;

	case CHECKPOINTING: // Thread is checkpointing
		if (info->state == FD_NORMAL) {
			// set socket state to FD_CHECKPOINTING
			info->state = FD_CHECKPOINTING;
			mode = CMD_CHECKPOINT;
			/*add socket to ts->fd_checkpointed vector */	
			ts->fd_checkpointed.push_back(fd);
#ifdef CXCHG_DEBUG
			ss << "pre_write: sd:N, updated socket[" << fd << "].mode: " << +fd_info[fd].state << endl;
			DBGLOG(ss);
#endif
		} else if (info->state == FD_CHECKPOINTING) {
			/* socket state remains CHECKPOINTING */
			mode = CMD_CHECKPOINT;
#ifdef CXCHG_DEBUG
			ss << "pre_write: sd:C, socket[" << fd << "].mode: " << +fd_info[fd].state << endl;
			DBGLOG(ss);
#endif
		} else if (info->state == FD_CANCEL) {
			/*need to notify receiver to rollback */
			fd_info[fd].state = FD_CHECKPOINTING;
			mode = CMD_ROLLNCHECK;
#ifdef CXCHG_DEBUG
			ss << "pre_write: sd:CC (or sd:CA), updated socket[" << fd << "].mode: " << +fd_info[fd].state << "needs to be updated" << endl;
			DBGLOG(ss);
#endif
		} else {
			ss << "pre_write: Unexpected socket["<< fd << "] state is "<< +fd_info[fd].state << endl;
			ERRLOG(ss);
		}
		break;

	default:
		ss << "pre_write: Unexpected thread state " << 
			ts->state << '!' << endl;
		ERRLOG(ss);
		break;
	}

	/* Send the extra header, patch write with writev */
	patch_write(ctx, ts, mode, std);
}

#if 0
static void xchg_pre_socketcall_hook(struct thread_state *ts) 
{
	/* Initialize the socketcall instance*/

//	unsigned long *args = (unsigned long *)ts->sysargs[1];
	stringstream ss;
	
	/* demultiplex the socketcall */
	switch((unsigned long)ts->sysargs[0]){
	
	case SYS_SOCKET:
#ifdef CXCHG_DEBUG
		ss << "pre_socketcall: sys_socket" << endl;
		DBGLOG(ss);
#endif
		break;
	case SYS_ACCEPT:
#ifdef CXCHG_DEBUG
		ss << "pre_socketcall: sys_accept" << endl; 
		DBGLOG(ss);
#endif
		break;
	case SYS_SEND:
#ifdef CXCHG_DEBUG
		ss << "pre_socketcall: sys_send\n" <<endl;
		DBGLOG(ss);
#endif
		break;
	case SYS_RECV:
#ifdef CXCHG_DEBUG
		ss << "pre_socketcall: sys_recv\n"<<endl;
		DBGLOG(ss);
#endif
		break;
	default:
		/* nothing to do */
		return;

	}
}
#endif

void xchg_post_connect_hook()
{
	//TODO
}

void xchg_post_accept_hook(thread_state *ts, int ret)
{
	unsigned long *args = (unsigned long *)ts->sysargs[1];
	fd_info_t *info;
	stringstream ss;

	if (ts->state == CHECKPOINTING)
		ERRLOG("WARNING: Socket accepted within RP!");

	info = &fd_info[(int)ret];

	memset(info, 0, sizeof(fd_info_t));
	if ((fd_info[args[0]].state != FD_UNHANDLED)) 
		info->state = FD_NORMAL;
}

/*
 * Add the returned sfd of the socket() system call
 * to the set of monitored sockets (fd_info structure)
 * and if it is in FD_CHECKPOINTING mode it is added in
 * the vector<> fd_checkpointed for the current thread
 *
 */

static void xchg_post_socket_hook(struct thread_state *ts, int ret)
{
	unsigned long *args = (unsigned long *)ts->sysargs[1];
	fd_info_t *info;

	if (ret < 0) {
#ifdef CXCHG_DEBUG
		DBGLOG("sys_socket() failed\n");
#endif
		return;
	}

	info = &fd_info[ret];
	//to be sure
	memset(info, 0, sizeof(fd_info_t));
		
	if(ts->state == CHECKPOINTING) {
		ERRLOG("WARNING: Socket created within RP!");
	}

	/* Handle only internet tcp sockets */
	if ((args[0] == PF_INET || args[0] == PF_INET6 || 
				args[0] == AF_INET || args[0] == AF_INET6) && 
			args[1] == SOCK_STREAM) {
		/*Initialize the state of new socket to FD_NORMAL*/
		info->state = FD_NORMAL;
#ifdef CXCHG_DEBUG
		stringstream ss;
		ss << "open sd " <<  ret << endl;
		DBGLOG(ss);
#endif
	}
}

/**
 * Close a file descriptor. It only does something if the fd is a socket, and it
 * was the socket that caused this tread to start checkpointing.
 * @param ts Pointer to thread state
 * @param fd File descriptor number
 */
static void xchg_close_fd(struct thread_state *ts, int fd)
{
	fd_info_t *info;
	stringstream ss;
	vector<unsigned int>::iterator it;

	info = &fd_info[fd];

#ifdef CXCHG_DEBUG
	if (info->state != FD_UNHANDLED) {
		ss << "close sd " << fd << endl;
		DBGLOG(ss);
	}
#endif

	// The fd is dead so free readbuf in all cases
	if (info->readbuf) {
		free(info->readbuf);
		info->readbuf = NULL;
		info->rdbuf_size = info->rdbuf_count = 0;
	}

	switch (ts->state) {
	case NORMAL: // Normal close 
		break;
	
	case CHECKPOINTING: // We are checkpointing
		if (ts->checkpoint_fd == fd) { 
			// We are closing the socket that caused us to
			// checkpoint. Let's commit
			
			// XXX: commit
		} else if (info->state == FD_CHECKPOINTING || 
				info->state == FD_CANCEL) {
			// Remove fd from fds that were signaled to 
			// checkpoint
			for (it = ts->fd_checkpointed.begin(); 
				it != (ts->fd_checkpointed.end()); ++it)
				ts->fd_checkpointed.erase(it);
		}
		break;

	default:
		ss << "Unexpected state while closing socket (state=" <<
			(int)ts->state << ')' << endl;
		PIN_ExitProcess(EXIT_FAILURE);
	}

	// Reset state
	info->state = FD_UNHANDLED;
}

void xchg_post_close_hook(struct thread_state *ts, int ret)
{
	int fd;

	fd = ts->sysargs[0];
	xchg_close_fd(ts, fd);
}

void xchg_post_shutdown_hook(struct thread_state *ts, int ret)
{
	int fd, how;

	how = ts->sysargs[1];
	if (how != SHUT_WR) { // We care only if cannot receive data any more
		fd = ts->sysargs[0];
		xchg_close_fd(ts, fd);
	}
}

void xchg_post_readv_hook(struct thread_state *ts, CONTEXT *ctx, int retval,
		struct iovec *iov, int iovcnt)
{
	ERRLOG("readv() family not implemented for exchange protocol\n");
}

void xchg_post_writev_hook(struct thread_state *ts, CONTEXT *ctx, int retval,
		struct iovec *iov, int iovcnt)
{
	ERRLOG("writev() family not implemented for exchange protocol\n");
}

static void xchg_post_send_hook(struct thread_state *ts, CONTEXT *ctx, int ret)
{
	if (ts->sysargs[3] != 0)
		ERRLOG("WARNING: send() flags are not supported\n");
	xchg_post_write_hook(ts, ctx, ret);
}

static void xchg_post_sendto_hook(struct thread_state *ts, 
		CONTEXT *ctx, int ret)
{
	xchg_post_send_hook(ts, ctx, ret);
}

static void xchg_post_sendmsg_hook(struct thread_state *ts, 
		CONTEXT *ctx, int ret)
{
	fd_info_t *info;
	int fd;

	fd = ts->sysargs[0];
	info = &fd_info[fd];
	if (info->state != FD_UNHANDLED) {
		ERRLOG("sendfrom() not implemented for exchange protocol\n");
	}
}

static void xchg_post_recv_hook(struct thread_state *ts,
		CONTEXT *ctx, int ret)
{
	fd_info_t *info;
	int fd;

	fd = ts->sysargs[0];
	info = &fd_info[fd];
	if (info->state != FD_UNHANDLED) {
		ERRLOG("recv() not implemented for exchange protocol\n");
	}
}

static void xchg_post_recvfrom_hook(struct thread_state *ts,
		CONTEXT *ctx, int ret)
{
	fd_info_t *info;
	int fd;

	fd = ts->sysargs[0];
	info = &fd_info[fd];
	if (info->state != FD_UNHANDLED) {
		ERRLOG("recvfrom() not implemented for exchange protocol\n");
	}
}

static void xchg_post_recvmsg_hook(struct thread_state *ts,
		CONTEXT *ctx, int ret)
{
	fd_info_t *info;
	int fd;

	fd = ts->sysargs[0];
	info = &fd_info[fd];
	if (info->state != FD_UNHANDLED) {
		ERRLOG("recvmsg() not implemented for exchange protocol\n");
	}
}

void xchg_post_socketcall_hook(struct thread_state *ts, 
		CONTEXT *ctx, int retval)
{
	stringstream ss;

	/*demultiplex the socketcall */
	switch((int)(ts->sysargs[0])){
		case SYS_CONNECT:
			xchg_post_connect_hook();
			break;

		case SYS_SOCKETPAIR:
			OUTLOG("socketpair() not implemented\n");
			break;

		case SYS_SOCKET:
			xchg_post_socket_hook(ts, retval);
			break;

		case SYS_ACCEPT:
			xchg_post_accept_hook(ts, retval);
			break;

		case SYS_SHUTDOWN:
			xchg_post_shutdown_hook(ts, retval);
			break;

		case SYS_SEND:
			xchg_post_send_hook(ts, ctx, retval);
			break;

		case SYS_SENDTO:
			xchg_post_sendto_hook(ts, ctx, retval);
			break;

		case SYS_SENDMSG:
			xchg_post_sendmsg_hook(ts, ctx, retval);
			break;

		case SYS_RECV:
			xchg_post_recv_hook(ts, ctx, retval);
			break;

		case SYS_RECVFROM:
			xchg_post_recvfrom_hook(ts, ctx, retval);
			break;

		case SYS_RECVMSG:
			xchg_post_recvmsg_hook(ts, ctx, retval);
			break;

		default:
			break;
	}
}

static inline void buffer_read(fd_info_t *info, UINT8 *buf, size_t len)
{
	// Check that there is enough space
	if (unlikely(len > info->rdbuf_size)) {
		if (info->readbuf)
			free(info->readbuf);
		info->readbuf = (UINT8 *)malloc(len);
		assert(info->readbuf);
		info->rdbuf_size = len;
	}

	// Buffer data
	memcpy(info->readbuf, buf, len);
	info->rdbuf_count = len;
	info->rdbuf_cur = info->readbuf;
}

void xchg_post_read_hook(struct thread_state *ts, CONTEXT *ctx, int ret) 
{
	int fd, orig_ret;
	fd_info_t *info;
	stringstream ss;
	size_t overread;
	
	fd = ts->sysargs[0];
	info = fd_info + fd;

	// Always check for unhandled sockets
	if(info->state == FD_UNHANDLED)
		return;

	orig_ret = ret;

#ifdef CXCHG_DEBUG
	ss << "post_read: read=" << ret << 
		", read_len=" << info->read_len << 
		", read_cur=" << info->read_cur <<
		", already_read=" << ts->already_read << endl;
	DBGLOG(ss);
#endif

	// I tried to read the header
	if (info->hdr_cur < sizeof(hdr_data_t)) {
		// We managed to receive the header
		if ((info->hdr_cur + ret) >= sizeof(hdr_data_t)) {
			// Actual data read without counting the header
			ret -= (sizeof(hdr_data_t) - info->hdr_cur);
			// Mark header as completed
			info->hdr_cur = sizeof(hdr_data_t);
			// Save size of actual message
			info->read_len = info->hdr.len;
			// Process cmd in socket message
			process_read_cmd(fd, ts, ctx, POST_READ_POS);

#ifdef CXCHG_DEBUG
			ss << "post_read: read header ret=" << ret <<
				", read_len=" << info->read_len << endl;
			DBGLOG(ss);
#endif
		} else {
			// We've only read part of the header
			info->hdr_cur += ret;
			// We need to force a read
			ret = force_read(fd, 
					(UINT8 *)&info->hdr + info->hdr_cur, 
					sizeof(hdr_data_t) - info->hdr_cur);
			if (ret != 0) // An error occurred
				goto do_ret;
			// ret = 0
		}
	}

	/* We have a header for the message, let's complete the read */

	if (ts->fake_read) {
		// This is a fake read, everything was buffered
		ret = ts->already_read;
		ts->fake_read = false;
#ifdef CXCHG_DEBUG
		ss << "post_read: fake read ret=" << ret << endl;
		DBGLOG(ss);
#endif
	} else { 
		// We actually wrote ts->already_read + ret
		ret += ts->already_read;
	}
	ts->already_read = 0;

	// Progress the read cursor
	info->read_cur += ret;

	// We completed the message
	if (info->read_cur >= info->read_len) {
		if (info->read_cur > info->read_len) { // We overread
			overread = info->read_cur - info->read_len;
			ret -= overread;
#ifdef CXCHG_DEBUG
			ss << "post_read: read into next message by " << 
				overread << endl;
			DBGLOG(ss);
#endif
			// Buffer overread data
			buffer_read(info, (UINT8 *)ts->sysargs[1] + ret, 
					overread);
		}

		info->hdr_cur = 0;
		info->read_cur = 0;
		info->read_len = 0;
	} else if (ret == 0) {
		// We cannot return 0, try reading some more
		cerr << "We cannot return 0, i need to return something" << endl;
		PIN_ExitProcess(1);
	}

	if (ret != orig_ret) {
do_ret:
		// Patch correct return value
		PIN_SetContextReg(ctx, LEVEL_BASE::REG_EAX, (ADDRINT)ret);
	}
}

void xchg_post_write_hook(struct thread_state *ts, CONTEXT *ctx, int ret)
{
	stringstream ss;

	// Always check for unhandled sockets
	if (fd_info[ts->sysargs[0]].state == FD_UNHANDLED)
		return;

#ifdef CXCHG_DEBUG
	ss << "post_write: write=" << ret << 
		", actual=" << ret - sizeof(hdr_data_t) << endl;
	DBGLOG(ss);
#endif
	
	// Correctly wrote all data
	if (likely(ret == (ts->sysargs[2] + sizeof(hdr_data_t))))
		ret -= sizeof(hdr_data_t); // Correct return value
	else if (ret < 0) // Actual error, just return
		return;
	else { // Try to write all data
		size_t len = ts->sysargs[2];
#ifdef CXCHG_DEBUG
		ss << "post_write: remaining bytes to write " <<
			len + sizeof(hdr_data_t) - ret << endl;
		DBGLOG(ss);
#endif
		// Try to send the whole message
		ret = complete_write(ts, (size_t)ret);
		if (ret == 0) // If all went ok, correct the length
			ret = len;
	}

	// Patch correct return value
	PIN_SetContextReg(ctx, LEVEL_BASE::REG_EAX, (ADDRINT)ret);
}


void xchg_dupfd(struct thread_state *ts, int dstfd, int srcfd)
{
	memcpy(fd_info + dstfd, fd_info + srcfd, sizeof(fd_info_t));
}

int xchg_init(void)
{
	/* TODO Handle resizing of the fd limit */
	fd_info = (fd_info_t*) calloc(MAX_FD, sizeof(fd_info_t));

	memset(fd_info, 0, MAX_FD * sizeof(fd_info_t));

	return EXIT_SUCCESS;	
}

/**
 * Commit a cascading checkpoint.
 *
 * @param ts Pointer to thread state
 * @param ctx Pointer to execution context
 */
void xchg_commit(struct thread_state *ts, CONTEXT *ctx)
		//THREADID tid, INT32 sig, CONTEXT *ctx, 
		//BOOL hasHandler, const EXCEPTION_INFO *pExceptInfo, VOID *v)
{
	unsigned char buf[1];
	int r;

	if (ts->state == CHECKPOINTING && ts->checkpoint_fd >= 0) {
#ifdef CXCHG_DEBUG
		DBGLOG("Cascading checkpoint commit\n");
#endif
		// Check that the right fd has sent the OOB data
		r = recv(ts->checkpoint_fd, buf, sizeof(buf), MSG_OOB);
		if (r != 1) {
			OUTLOG("WARNING: OOB data send by another socket"
				" and will be ignored\n");
			return;
		}

		ts->state = COMMITTING;

		// Revert owner of sockets
		xchg_remote_commit(ts);

		if (checkpoint_type == FORK_CHECKP) {
			CheckpointForkCommit(ts->memcheckp.flog);
		}
		CheckpointFree(ts);

#ifdef CXCHG_DEBUG
		ADDRINT version;
		version = PIN_GetContextReg(ctx, version_reg);
		stringstream ss;
		ss << "Version is " << version << " and will be switched to "
			<< NORMAL_VERSION << endl;
		DBGLOG(ss);
#endif
		PIN_SetContextReg(ctx, version_reg, NORMAL_VERSION);
		ts->checkpoint_fd = -1;

		ts->state = NORMAL;
	}
}

/**
 * Signal sockets that have been signaled to checkpoint to commit their state.
 *
 * @param ts Pointer to thread state
 */
void xchg_remote_commit(struct thread_state *ts)
{
	stringstream ss;
	vector<unsigned int>::iterator it;
	fd_info_t *info;
	unsigned int fd;

	for(it = ts->fd_checkpointed.begin(); 
			it != (ts->fd_checkpointed.end()); ++it) {
		fd = *it;
		info = &fd_info[fd]; // or (fd_info + *it)
		assert(info->state == FD_CHECKPOINTING);
		DBGLOG("SockStateExitCheckpoint: Sending OOB\n");
		//it won't really matter what we sent, 
		//as we are mostly interested to have
		//the signal SIGURG raised at the receiver
		send(fd, "3", 1, MSG_OOB);
		info->state = FD_NORMAL;
	}

	ts->fd_checkpointed.clear();
}

/**
 * Switch sockets that have been signaled to checkpoint to CANCEL state.
 * This will cause the next write to these sockets to signal them to rollback.
 *
 * @param ts Pointer to thread state
 */
void xchg_remote_rollback(struct thread_state *ts)
{
	vector<unsigned int>::iterator it;
	fd_info_t *info;

	for(it = ts->fd_checkpointed.begin(); 
			it != (ts->fd_checkpointed.end()); ++it)
	{
		info = fd_info + *it;
		assert(info->state == FD_CHECKPOINTING);
		info->state = FD_CANCEL;
	}
	ts->fd_checkpointed.clear();
}
