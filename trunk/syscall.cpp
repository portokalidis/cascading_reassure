#include <cassert>
#include <iostream>
#include <sstream>

extern "C" {
#include <sys/syscall.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
}

#include "pin.H"
#include "threadstate.hpp"
#include "syscall.hpp"
#include "libreassure.hpp"
#include "log.hpp"
#include "checkpoint_xchg.hpp"
#include "syscall_desc.h"
#include "fork.h"
#include "likely.h"


/**
 * Handler for system call enter. The handler uses system call metadata to
 * determine how to handle entering a system call. A sytem call is handled when
 * in a checkpoint (using fork) and when the metadata specify that it should be
 * handled. If the system call is to be handled, the arguments specified by the 
 * metadata are saved for use after the completion of the call.
 * If a custom handler exists it is called after saving the arguments.
 *
 * @param ts Pointer to thread state
 * @param ctx Pointer to processor context
 * @param std System call standard used by Pin 
 */
void HandleSysEnter(struct thread_state *ts, CONTEXT *ctx, SYSCALL_STANDARD std)
{
	const struct syscall_desc *desc;
	unsigned i;
	bool handle_call; 

#ifdef CASCADING_RPS
	bool save_args = false;

	// Check if we are restarting a system call
	if (ts->restart_syscall) {
		ts->in_syscall = ts->orig_eax;
		PIN_SetSyscallNumber(ctx, std, ts->in_syscall);
	} else
#endif
		// Ordinary system call
		ts->in_syscall = PIN_GetSyscallNumber(ctx, std);

	// Get system call meta data
	assert(ts->in_syscall <= SYSCALL_MAX);
	desc = sysdesc + ts->in_syscall;

	// We are checkpointing (using fork) and this syscall 
	// needs to be handled.
	handle_call = (ts->state == CHECKPOINTING && desc->handle && 
			checkpoint_type == FORK_CHECKP);

#ifdef CASCADING_RPS
	// Support for cascading rescue points requires that 
	// we handle some syscalls no matter what.
	handle_call = handle_call || (desc->handle & SYS_CRPS);

	// Check if we are restarting a system call
	if (ts->restart_syscall) {
		// Restore arguments
		for (i = 0; i < desc->save_args; i++)
			PIN_SetSyscallArgument(ctx, std, i, ts->sysargs[i]);

		cerr << "PIN [" << ts->tid << "] Restarting syscall " << 
			ts->in_syscall << endl;

		// reset state
		ts->orig_eax = -1;
		ts->restart_syscall = false;
	} else if (ts->state == CHECKPOINTING && ts->checkpoint_fd >= 0) {
		// We are in a cascading RP. Save arguments and PC in case 
		// we need to restart the syscall
		save_args = true;
		ts->last_syscall_pc = PIN_GetContextReg(ctx, REG_INST_PTR);
	} 
#endif

#ifdef CASCADING_RPS
	if (save_args || handle_call) {
#else
	if (handle_call) {
#endif
#ifdef SYSCALL_DEBUG
		stringstream ss;

		ss << "PIN [" << ts->tid << "] Enter syscall " << 
			ts->in_syscall << endl;
		DBGLOG(ss);
#endif
		// Save arguments
		for (i = 0; i < desc->save_args; i++)
			ts->sysargs[i] = PIN_GetSyscallArgument(ctx, std, i);

		// Custom pre-call handler runs after copying arguments
		if (handle_call && desc->pre != NULL) {
#ifdef SYSCALL_DEBUG
			ss << "PIN [" << ts->tid << 
				"] Enter syscall pre-handler" << endl;
			DBGLOG(ss);
#endif
			desc->pre(ts, ctx, std);
		}

#ifdef SYSCALL_DEBUG
		ss << "PIN [" << ts->tid << "] Enter syscall done" << endl;
		DBGLOG(ss);
#endif
	}
}

/**
 * Default handling of system call exiting when we checkpoint using fork() 
 * Mark memory written by system call for rollback as defined by metadata.
 *
 * @param ts Pointer to thread state
 * @param retval System call return value
 * @param desc System call metadata
 */
void DefaultSysExit(struct thread_state *ts, ADDRINT retval, 
		const struct syscall_desc *desc)
{
	unsigned i;
	ADDRINT len, *args;
#ifdef SYSCALL_DEBUG
	stringstream ss;

	ss << "PIN [" << ts->tid << "] Exit syscall default handling" << endl;
	DBGLOG(ss);
#endif
	
	// Alias to system call arguments
	args = ts->sysargs;

	for (i = 0; i < desc->ret_args; i++) {
		// Size of data copied in ...
		if (desc->arglen[i] == INRETVAL) {
			// ... return value
			len = retval;
		} else if (desc->arglen[i] > 0) {
			// ... metadata
			len = desc->arglen[i];
		} else if (desc->arglen[i] < 0) {
			// ... in syscall argument
			len = args[-desc->arglen[i]];
		} else
			len = 0;

		// If user pointer is valid, mark written data
		if (len && args[i])
			FLOGMARK(&ts->memcheckp.flog->filter, args[i], len);
	} // for ()
}

/**
 * Handler for system call exits. The handler uses system call metadata to
 * determine how to handle exit from a system call. A sytem call is handled when
 * in a checkpoint (using fork) and when the metadata specify that it should be
 * handled. If a custom handler exists that one is called, otherwise the default
 * handler is invoked if the system calls has succeeded (retval > 0). The
 * default handler marks written memory for rollback.
 *
 * @param ts Pointer to thread state
 * @param ctx Pointer to processor context
 * @param retval System call return value as supplied by Pin
 * @param errno System call error number as supplied by Pin, 0 on success 
 */
void HandleSysExit(struct thread_state *ts, CONTEXT *ctx, 
		ADDRINT retval, ADDRINT err)
{
	const struct syscall_desc *desc;
	bool handle_call;
#ifdef SYSCALL_DEBUG
	stringstream ss;
#endif

	// Get system call metadata
	desc = sysdesc + ts->in_syscall;

	// Check if system call requires some handling
	// We are checkpointing (using fork) and this syscall writes memory
	handle_call = (ts->state == CHECKPOINTING && desc->handle &&
				checkpoint_type == FORK_CHECKP);
#ifdef CASCADING_RPS
	// ... or cascading rescue points specific
	handle_call = handle_call || (desc->handle & SYS_CRPS);

	if (ts->state == CHECKPOINTING && ts->checkpoint_fd >= 0) {
		if (unlikely(err == EINTR)) {
			cerr << "System call interrupted" << endl;
			// Save which syscall we need to restart
			ts->orig_eax = ts->in_syscall;
			return;
		}
	}
#endif

	if (handle_call && err == 0) {
#ifdef SYSCALL_DEBUG
		ss << "PIN [" << ts->tid << "] Exit syscall " << 
			ts->in_syscall << endl;
		DBGLOG(ss);
#endif
		// Run custom handler first. If there is a custom handler we do not run 
		// the default one that follows
		if (desc->post) {
#ifdef SYSCALL_DEBUG
			ss << "PIN [" << ts->tid << 
				"] Exit syscall post handler" << endl;
			DBGLOG(ss);
#endif
			desc->post(ts, ctx, retval);
		} else {
			// Default handling marks written memory within
			// fork checkpoints 
#ifdef SYSCALL_DEBUG
			ss << "PIN [" << ts->tid << 
				"] Exit syscall default handling" << endl;
			DBGLOG(ss);
#endif
			DefaultSysExit(ts, retval, desc);
		}

#ifdef SYSCALL_DEBUG
		ss << "PIN [" << ts->tid << "] Exit syscall done" << endl;
		DBGLOG(ss);
#endif
	}
}



#if 0
VOID SyscallRollback(wlog_entry_t *entry)
{
	Syscall *syscall;
	stringstream ss;

	syscall = (Syscall *)entry->data.ptr;
	ss << "Rollback " << syscall << endl;
	OUTLOG(ss);

	switch (syscall->number()) {
	case SYS_mmap2:
		munmap((void *)syscall->returnValue(), syscall->argument(1));
		break;
	}
	delete syscall;
}

Syscall::Syscall(ADDRINT sysnr, ADDRINT sysret, const ADDRINT args[SYSARGS])
{
	this->sysnr = sysnr;
	this->sysret = sysret;
	memcpy(this->args, args, sizeof(args));
}

ostream & operator<<(ostream &out, Syscall *call)
{
	out << "syscall " << call->sysnr;
	return out;
}
#endif
