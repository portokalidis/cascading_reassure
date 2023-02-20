#ifndef __CHECKPOINT_XCHG_H__
#define __CHECKPOINT_XCHG_H__

/* Support for 
 * read, write, close, dup system calls
 * and
 * send, recv, accept, connect, socket
 * socketcalls */

#include "pin.H"
#include "threadstate.hpp"
#include "syscall.hpp"



void xchg_pre_read_hook(struct thread_state *, CONTEXT *, SYSCALL_STANDARD);

void xchg_pre_write_hook(struct thread_state *, CONTEXT *, SYSCALL_STANDARD );

void xchg_post_readv_hook(struct thread_state *ts, CONTEXT *ctx, int retval,
		struct iovec *iov, int iovcnt);

void xchg_post_writev_hook(struct thread_state *ts, CONTEXT *ctx, int retval,
		struct iovec *iov, int iovcnt);

//void xchg_pre_socketcall_hook(struct thread_state *, CONTEXT *, int);

void xchg_post_read_hook(struct thread_state *, CONTEXT *, int);

void xchg_post_write_hook(struct thread_state *, CONTEXT *, int);

void xchg_post_socketcall_hook(struct thread_state *, CONTEXT *, int);

void xchg_post_close_hook(struct thread_state *, int);

void xchg_post_shutdown_hook(struct thread_state *, int);

void xchg_dupfd(struct thread_state *, int, int);

int xchg_init(void);

void xchg_commit(struct thread_state *ts, CONTEXT *ctx);

void xchg_remote_commit(struct thread_state *ts);

void xchg_remote_rollback(struct thread_state *ts);

#endif 
