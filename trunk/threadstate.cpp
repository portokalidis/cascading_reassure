#include <iostream>
#include <sstream>
#include <cassert>

extern "C" {
#include <stdlib.h>
#include <syscall.h>
#include <fcntl.h>
}

#include "pin.H"
#include "threadstate.hpp"
#include "libreassure.hpp"
//#include "syscall.hpp"
#include "writeslog.h"
#include "fork.h"
#include "log.hpp"

#define gettid()        syscall(SYS_gettid)


/**
 * Create a checkpoint based on the currect context.
 *
 * @param ts Pointer to thread state
 * @param ctx Pointer to current execution context
 */
void CheckpointCreate(struct thread_state *ts, const CONTEXT *ctx)
{
	switch (checkpoint_type) {
	case FORK_CHECKP:
		ts->memcheckp.flog = FLogAlloc();
		break;

	case WLOG_CHECKP:
		ts->memcheckp.wlog = WLogAlloc(0); // XXX: Reinstate hint
		break;

	default:
		ERRLOG("Invalid checkpoint type " + checkpoint_type);
		PIN_ExitProcess(1);
		break;
	}

	assert(ts->checkpoint == NULL);
	ts->checkpoint = (CONTEXT *)calloc(1, sizeof(CONTEXT));
	assert(ts->checkpoint);

	PIN_SaveContext(ctx, ts->checkpoint);

	ts->state = CHECKPOINTING;

	if (checkpoint_type == FORK_CHECKP) {
		assert(CheckpointFork(ts->memcheckp.flog) == 0);
	}
}

void CheckpointRollback(struct thread_state *ts, CONTEXT *ctx)
{
	switch (checkpoint_type) {
	case FORK_CHECKP:
		CheckpointForkRollback(ts->memcheckp.flog);
		break;

	case WLOG_CHECKP:
		WLogRollback(ts->memcheckp.wlog);
		break;

	default:
		ERRLOG("Invalid checkpoint type " + checkpoint_type);
		PIN_ExitProcess(1);
		break;
	}

	PIN_SaveContext(ts->checkpoint, ctx);
}

void CheckpointFree(struct thread_state *ts)
{
	switch (checkpoint_type) {
	case FORK_CHECKP:
		FLogFree(ts->memcheckp.flog);
		ts->memcheckp.flog = NULL;
		break;

	case WLOG_CHECKP:
		WLogFree(ts->memcheckp.wlog);
		ts->memcheckp.wlog = NULL;
		break;

	default:
		ERRLOG("Invalid checkpoint type " + checkpoint_type);
		PIN_ExitProcess(1);
		break;
	}

        free(ts->checkpoint);
        ts->checkpoint = NULL;
}      

void ThreadstateInit(struct thread_state *ts, THREADID tid)
{       
        ts->real_tid = gettid();
        ts->in_syscall = 0;
        ts->blocked = 0;
        ts->checkpoint = NULL;
	ts->tid = tid;
#ifdef CASCADING_RPS
	ts->checkpoint_fd = -1;
	ts->orig_eax = -1;
	ts->restart_syscall = false;
#endif

        //SyscallStackAlloc(&ts->sstack);
}
                
void ThreadstateCleanup(struct thread_state *ts)
{               
        ts->real_tid = 0;
        if (ts->state == CHECKPOINTING)
                CheckpointFree(ts);

       //SyscallStackFree(&ts->sstack);
}

