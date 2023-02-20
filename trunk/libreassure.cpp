#include <set>
#include <map>
#include <cassert>
#include <iostream>
#include <sstream>

extern "C" {
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <fcntl.h>
#ifdef SYSEXIT_DECODE
# include "xed-interface.h"
# include "xed-decode.h"
#endif
}

#include "pin.H"
#include "RescuePoint.hpp"
#include "threadstate.hpp"
#include "utils.hpp"
#include "libreassure.hpp"
#include "syscall.hpp"
#include "watchdog.hpp"
#include "log.hpp"
#ifdef CASCADING_RPS
# include "checkpoint_xchg.hpp"
#endif
#include "cache.h"
#include "fork.h"
#include "writeslog.h"
#include "debug.h"

#define gettid()		syscall(SYS_gettid)
#define tkill(p, s)		syscall(SYS_tkill, (p), (s))
#define tgkill(pp, p, s)	syscall(SYS_tgkill, (pp), (p), (s))



//! Global holding type of checkpointing used
checkp_t checkpoint_type = UNKNOWN_CHECKP;

//! Pin scratch register for switching between execution versions 
REG version_reg;



// Thread state
// List head of thread states
static map<THREADID, struct thread_state *> tsmap;
// Lock for modifying list
static PIN_LOCK tsmap_lock;
// Register for holding per thread ts pointer
static REG tsreg;

// Lock to enforce only one active checkpoint at a time
static PIN_LOCK checkpoint_lock;

// Blocking checkpoint globals
static BOOL runtime_blocks = FALSE;
static THREADID blocking_tid = -1;
static ADDRINT block_threads = 0, running_threads = 0;
static PIN_LOCK blocking_checkpoint_lock;

// Do we have any blocking RPs
static bool has_blocking_rp = false;

// Traces that we should instrument with a block
// (needs ClientVM lock or Client lock )
static set<ADDRINT> block_traces; 
static PIN_LOCK block_traces_lock;

// Blocking checkpoint defines
#define TBLOCK_SIGNAL 		SIGUSR2

//! Hash map of rescue points, by name of routine
static map<string, RescuePoint *> rescue_points_byname;

//! Hash map of rescue points, by end address of routine
static map<ADDRINT, RescuePoint *> rescue_points_byaddr;


#ifdef CASCADING_RPS
static set<ADDRINT> postsyscall_ins;
#endif

#ifdef SYSEXIT_DECODE
static xed_state_t dstate;
#endif

// Statistics
#ifdef COLLECT_STATS
static unsigned long long stats_checkpoints, stats_commits, stats_rollbacks;
static unsigned long long cache_accesses = 0, cache_misses = 0;
#endif


//////////////////
// Helper
//////////////////

static inline VOID InvalidateRoutine(RTN rtn)
{
	ADDRINT start_addr, stop_addr;

	start_addr = RTN_Address(rtn);
	stop_addr = start_addr + RTN_Size(rtn) - 1;
#ifdef INVALIDATE_DEBUG
	{
		UINT32 traces;
		traces = CODECACHE_InvalidateRange(start_addr, stop_addr);
		stringstream ss;
		ss << " Invalidated range " << (void *)start_addr << '-' << 
			(void *)stop_addr << " = " << traces << endl;
		DBGLOG(ss);
	}
#else
	CODECACHE_InvalidateRange(start_addr, stop_addr);
#endif
}

static inline VOID InvalidateTraceAt(ADDRINT addr)
{
#ifdef INVALIDATE_DEBUG
	{
		
		UINT32 traces;

		traces = CODECACHE_InvalidateTraceAtProgramAddress(addr);
		stringstream ss;

		ss << " Invalidated PC " << (void *)addr << " = " << 
			traces << endl;
		DBGLOG(ss);
	}
#else
	CODECACHE_InvalidateTraceAtProgramAddress(addr);
#endif
}

static inline BOOL SignalThreads(struct thread_state *ts)
{
	map<THREADID, struct thread_state *>::iterator it;
	struct thread_state *tsit;
	stringstream ss;
	OS_THREAD_ID ptid;
	BOOL retry, still_running = FALSE;

	ptid = PIN_GetPid();

#ifdef THREAD_DEBUG
	ss << "PIN [" << ts->tid << "] thread is signaling thread " << endl;
	DBGLOG(ss);
#endif

sigall:
	retry = FALSE;
	GetLock(&tsmap_lock, ts->tid + 1);
	for (it = tsmap.begin(); it != tsmap.end(); it++) {
		tsit = (*it).second;

		if (tsit->real_tid > 0 && ts->tid != tsit->tid && 
				!tsit->in_syscall && !tsit->blocked) {
#ifdef THREAD_DEBUG
			ss << "PIN [" << ts->tid << "] thread " << 
				tsit->real_tid << " will be signaled to "
				"block " << endl;
			DBGLOG(ss);
#endif
			still_running = TRUE;
			if (tgkill(ptid, tsit->real_tid, TBLOCK_SIGNAL) != 0) {
				ss << "WARNING: there was a problem signaling"
					" thread " << tsit->real_tid << ' ' << 
					strerror(errno) << endl;
				OUTLOG(ss);
				retry = TRUE;
				break;
			} // tgkill
		} 
	} // for (it ..)
	ReleaseLock(&tsmap_lock);

	// If there was an error signaling, sleep and try again
	if (retry) {
		PIN_Sleep(1);
		goto sigall;
	}

#ifdef THREAD_DEBUG
	if (!still_running) {
		ss << "PIN [" << ts->tid << "] no threads to signal" << endl;
		DBGLOG(ss);
	}
#endif
	return still_running;
}

static inline BOOL WaitForThreads(struct thread_state *ts)
{
	map<THREADID, struct thread_state *>::iterator it;
	struct thread_state *tsit;
	BOOL ret = FALSE;
#ifdef THREAD_DEBUG
	stringstream ss;
#endif

	GetLock(&tsmap_lock, ts->tid + 1);
	for (it = tsmap.begin(); it != tsmap.end(); it++) {
		tsit = (*it).second;
		if (tsit->real_tid > 0 && ts->tid != tsit->tid && 
				!tsit->in_syscall && !tsit->blocked) {
#ifdef THREAD_DEBUG

			ss << "PIN [" << ts->tid << "] thread " << tsit->tid << 
				" still running" << endl;
			DBGLOG(ss);
#endif
			ret = TRUE;
			break;

		}
	}
	ReleaseLock(&tsmap_lock);

#ifdef THREAD_DEBUG
	if (!ret) {
		ss << "PIN [" << ts->tid << "] all threads blocked" << endl;
		DBGLOG(ss);
	}
#endif

	return ret;
}

static inline VOID RemoveAllBlocks(void)
{
	set<ADDRINT>::iterator it;

	// We don't acquire block_traces_lock because we already have
	// GetVmLock(). Check CheckpointReturn().
	
	// We invalidate all the block traces here
	while ((it = block_traces.begin()) != block_traces.end()) {
		InvalidateTraceAt(*it);
		block_traces.erase(it);
	}
}

static VOID InsertBlock(THREADID tid, ADDRINT pc)
{
	pair<set<ADDRINT>::iterator, bool> ret;

	//*log << "Marking " <<  (void *)pc << " for block trace" << endl;
	GetLock(&block_traces_lock, tid + 1);
	ret = block_traces.insert(pc);
	if (ret.second)
		InvalidateTraceAt(pc);
	ReleaseLock(&block_traces_lock);
}

#ifdef SYSEXIT_DECODE
static VOID DecodeInstruction(ADDRINT addr, void *buf, size_t size)
{
        xed_decoded_inst_t xedd;
        char xedbuf[1024];
        int r;
        size_t off;
	stringstream ss;

	off = 0;
        while (off < size) {
                xed_decoded_inst_zero_set_mode(&xedd, &dstate);
                r = xed_decode(&xedd, (const xed_uint8_t *)buf + off,
                                size - off);
                switch (r) {
                case XED_ERROR_NONE:
                        break;
                case XED_ERROR_BUFFER_TOO_SHORT:
                        ss << "XED: Not enough bytes to decode "
                                "instruction" << endl;
			DBGLOG(ss);
                        return;
                case XED_ERROR_GENERAL_ERROR:
                        ss << "XED: Unable to decode input" << endl;
			DBGLOG(ss);
                        return;
                default:
                        ss << "XED: Some error happened..." << endl;
			DBGLOG(ss);
                        return;
                }

                //xed_decoded_inst_dump(&xedd, xedbuf, sizeof(xedbuf));
                xed_format_att(&xedd, xedbuf, sizeof(xedbuf), addr + off);
                xedbuf[sizeof(xedbuf) - 1] = '\0';
                ss << "XED  " << (void *)(addr + off) << ": " << xedbuf << endl;
		DBGLOG(ss);
                off += xed_decoded_inst_get_length(&xedd);
        }
}
#endif



////////////////////////////////////////////////////
//	Analysis
////////////////////////////////////////////////////


/**
 * Cache statistics macros
 */
#ifdef COLLECT_STATS
# define CACHE_ACCESSED() do { cache_accesses++; } while (0)
# define CACHE_MISS() do { cache_misses++; } while (0)
#else
# define CACHE_ACCESSED() do { } while (0)
# define CACHE_MISS() do { } while (0)
#endif


/**
 * Bitmap filter analysis functions.
 */
#if FILTER_TYPE == FILTER_BITMAP

/**
 * ForkMarkB is always within the same bucket, so it is defined separately as
 * there in ForkMarkExtB.
 */
static VOID PIN_FAST_ANALYSIS_CALL ForkMarkB(struct thread_state *ts,
		ADDRINT addr)
{
	FLogMarkB(&ts->memcheckp.flog->filter, addr);
}


/**
 * Macro for defining ForkMark functions.
 * These functions return non-zero if the write spills to next bucket.
 */
#define FORKMARK_FUNCTION(W) \
static ADDRINT PIN_FAST_ANALYSIS_CALL ForkMark ## W (struct thread_state *ts, \
		ADDRINT addr)\
{\
	return FLogMark ## W(&ts->memcheckp.flog->filter, addr);\
}
FORKMARK_FUNCTION(W)
FORKMARK_FUNCTION(L)
FORKMARK_FUNCTION(Q)
FORKMARK_FUNCTION(DQ)
FORKMARK_FUNCTION(QQ)


/**
 * Macro for defining ForkMarkExt functions.
 */
#define FORKMARKEXT(W) \
static VOID PIN_FAST_ANALYSIS_CALL ForkMarkExt ## W (struct thread_state *ts, \
		ADDRINT addr)\
{\
	FLogMarkExt ## W (&ts->memcheckp.flog->filter, addr);\
}

FORKMARKEXT(W)
FORKMARKEXT(L)
FORKMARKEXT(Q)
FORKMARKEXT(DQ)
FORKMARKEXT(QQ)

/**
 * Write log filter analysis functions.
 */
#elif FILTER_TYPE == FILTER_WLOG
#define FORKMARK(W, bytes) \
static VOID PIN_FAST_ANALYSIS_CALL ForkMark ## W \
	(struct thread_state *ts, ADDRINT addr)\
{\
	FLOGMARK(&ts->memcheckp.flog->filter, addr, bytes);\
	WRITESCACHE_UPDATE(ts->memcheckp.flog->filter.cache, addr, bytes);\
	CACHE_MISS();\
}
FORKMARK(B, 1)
FORKMARK(W, 2)
FORKMARK(L, 4)
FORKMARK(Q, 8)
FORKMARK(DQ, 16)
FORKMARK(QQ, 32)

#endif

/* Analysis routines for write log that store overwritten memory contents */

static ADDRINT PIN_FAST_ANALYSIS_CALL LogNeedsExpansion(struct thread_state *ts)
{
	return WLogIsFull(ts->memcheckp.wlog);
}

static VOID LogExpand(struct thread_state *ts)
{
	WLogExtend(ts->memcheckp.wlog);
}

/**
 * Macro for defining CheckCache functions.
 */
#define CHECKCACHE_FUNCTION(suffix)\
static ADDRINT PIN_FAST_ANALYSIS_CALL CheckCache ## suffix \
	(struct thread_state *ts, ADDRINT addr) \
{\
	CACHE_ACCESSED();\
	return WritesCacheCheck ## suffix (ts->memcheckp.wlog->cache, addr);\
}
CHECKCACHE_FUNCTION(B)
CHECKCACHE_FUNCTION(W)
CHECKCACHE_FUNCTION(L)
CHECKCACHE_FUNCTION(Q)
CHECKCACHE_FUNCTION(DQ)
CHECKCACHE_FUNCTION(QQ)


/**
 * Generic macro for copying data to temporary variable
 */
#ifdef USE_SAFECOPY
# define COPY_DATA(data, addr, len) \
	do {\
		if (unlikely(PIN_SafeCopy(&(data), (VOID *)(addr),\
						(len)) < (len)))\
			return;\
	} while (0)
#else
# define COPY_DATA(data, addr, len, type) \
	do {\
		(data) = *(type *)addr;\
	} while (0)
#endif

/**
 * Macro for defining LogWrite functions.
 */
#define LOGWRITE_FUNCTION(suffix, len, type, umember) \
static VOID PIN_FAST_ANALYSIS_CALL LogWrite ## suffix \
	(struct thread_state *ts, ADDRINT addr)\
{\
	type data;\
	COPY_DATA(data, addr, len, type);\
	WLOG_WRITE(ts->memcheckp.wlog, addr, data, len, umember);\
	WRITESCACHE_UPDATE(ts->memcheckp.wlog->cache, addr, len);\
	CACHE_MISS();\
}
LOGWRITE_FUNCTION(B, 1, UINT8, byte)
LOGWRITE_FUNCTION(W, 2, UINT16, word)
LOGWRITE_FUNCTION(L, 4, UINT32, dword)
LOGWRITE_FUNCTION(Q, 8, UINT64, qword)

/**
 * Double quad-word writes use copy instead of direct assignment.
 */
static VOID PIN_FAST_ANALYSIS_CALL LogWriteDQ(struct thread_state *ts, 
		ADDRINT addr)
{
	WLOG_WRITE_COPY(ts->memcheckp.wlog, addr, 16, dqword);
	WRITESCACHE_UPDATE(ts->memcheckp.wlog->cache, addr, 16);
	CACHE_MISS();
}

/**
 * Quad quad-word writes use copy instead of direct assignment.
 */
static VOID PIN_FAST_ANALYSIS_CALL LogWriteQQ(struct thread_state *ts, 
		ADDRINT addr)
{
	WLOG_WRITE_COPY(ts->memcheckp.wlog, addr, 32, qqword);
	WRITESCACHE_UPDATE(ts->memcheckp.wlog->cache, addr, 32);
	CACHE_MISS();
}

// Block threads is global since we can only have one checkpoint at a time
static ADDRINT PIN_FAST_ANALYSIS_CALL ShouldBlock(void)
{
	return block_threads;
}

static VOID Block(struct thread_state *ts)
{
	if (ts->tid != blocking_tid) {
#ifdef CHECKPOINT_DEBUG
		stringstream ss;

		ss << "PIN [" << ts->tid << "] blocking" << endl;
		DBGLOG(ss);
#endif
		ts->blocked = true;
		GetLock(&blocking_checkpoint_lock, ts->tid + 1);
		ReleaseLock(&blocking_checkpoint_lock);
		ts->blocked = false;
#ifdef CHECKPOINT_DEBUG
		ss << "PIN [" << ts->tid << "] resuming" << endl;
		DBGLOG(ss);
#endif
	}
}

static VOID Block2(struct thread_state *ts)
{
	if (ts->tid != blocking_tid && block_threads) {
#ifdef CHECKPOINT_DEBUG
		stringstream ss;

		ss << "PIN [" << ts->tid << "] blocking2" << endl;
		DBGLOG(ss);
#endif
		ts->blocked = true; 
		GetLock(&blocking_checkpoint_lock, ts->tid + 1);
		ReleaseLock(&blocking_checkpoint_lock);
		ts->blocked = false; 
#ifdef CHECKPOINT_DEBUG
		ss << "PIN [" << ts->tid << "] resuming2" << endl;
		DBGLOG(ss);
#endif
	} 
}

static ADDRINT Checkpoint(struct thread_state *ts, const CONTEXT *ctx, 
		RescuePoint *rp)
{
	stringstream ss;

#ifdef CHECKPOINT_DEBUG
	ss << "PIN [" << ts->tid << "] enter checkpoint " << rp->Id() << endl;
	DBGLOG(ss);
#endif

#ifdef COLLECT_STATS
	stats_checkpoints++;
#endif

	switch (ts->state) {
	case NORMAL:
#ifdef CHECKPOINT_DEBUG
		ss << "PIN [" << ts->tid << "] setting up checkpoint " << endl;
		DBGLOG(ss);
#endif

		if (rp->Type() == RPBLOCKOTHERS) {
			// I may block due to multiple threads trying to 
			// enter a checkpoint
			ts->blocked = true;
			//assert(has_blocking_rp);
			// Initiate block of other threads
			GetLock(&blocking_checkpoint_lock, ts->tid + 1);
			ts->blocked = false;
#ifdef CHECKPOINT_DEBUG
			ss << "PIN [" << ts->tid << 
				"] blocking threads" << endl;
			DBGLOG(ss);
#endif
			block_threads = 1;
			blocking_tid = ts->tid;
			PIN_Yield(); // Allow other threads to block
			// Wait for all threads to be blocked
			if (runtime_blocks)
				while (SignalThreads(ts))
					PIN_Sleep(1);
			else
				while (WaitForThreads(ts))
					PIN_Sleep(1);
		}

		ts->rp = rp;
		CheckpointCreate(ts, ctx);

		break;

	case CHECKPOINTING:
		ss << "Checkpoint within checkpoint not supported" << endl;
		ERRLOG(ss);
		PIN_ExitProcess(1);
		break;

	default:
		ss << "Unexpected thread state " << ts->state <<
			" at checkpoint" << endl;
		ERRLOG(ss);
		PIN_ExitProcess(1);
		break;
	}

#ifdef CHECKPOINT_DEBUG
	ss << "PIN [" << ts->tid << "] checkpoint setup done" << endl;
	ERRLOG(ss);
#endif

	// Update current version
	return CHECKPOINT_VERSION;
}

// Exiting blocking RP, Remove blocks from threads.
// Assumes that the RP is of type RPBLOCKOTHERS
static VOID ExitBlockingRP(struct thread_state *ts, BOOL vmlock = FALSE)
{
#ifdef CHECKPOINT_DEBUG
	stringstream ss;

	ss << "PIN [" << ts->tid << "] resume threads" << endl;
	DBGLOG(ss);
#endif

	//assert(has_blocking_rp);
	block_threads = 0;
	blocking_tid = -1;
	if (runtime_blocks) {
		if (vmlock)
			GetVmLock();
		RemoveAllBlocks();
		if (vmlock)
			ReleaseVmLock();
	}

	ReleaseLock(&blocking_checkpoint_lock);
}

static ADDRINT CheckpointReturn(struct thread_state *ts,
		ADDRINT *ret_p, BOOL hasret, ADDRINT retval)
{
	stringstream ss;

#ifdef CHECKPOINT_DEBUG
	ss << "PIN [" << ts->tid << "] checkpoint return" << endl;
	DBGLOG(ss);
#endif

	switch (ts->state) {
	case CHECKPOINTING:
#ifdef CHECKPOINT_DEBUG
		ss << "PIN [" << ts->tid << "] committing" << endl;
		DBGLOG(ss);
#endif

#ifdef CASCADING_RPS
		/* Iterate through sockets in fd_checkpointed
		 * set their state to FD_COMMIT 
		 * and send MSG_OOB to each one of these sockets
		 * that were in FD_CHECKPOINTING state */
		xchg_remote_commit(ts);
#endif

		if (checkpoint_type == FORK_CHECKP) {
			// Let the forked process know that we have committed
			CheckpointForkCommit(ts->memcheckp.flog);
		}

#ifdef COLLECT_STATS
		stats_commits++;
#endif
		break;

	case ROLLINGBACK:
		// Rollback checkpoint
#ifdef CHECKPOINT_DEBUG
		ss << "PIN [" << ts->tid << "] rolling back and exiting "
			"checkpoint" << endl;
		DBGLOG(ss);
#endif
		// Checkpoint rollback is performed in the fault handler
		
		// Correct return value according to RP
		if (hasret)
			*ret_p = retval;

#ifdef COLLECT_STATS
		stats_rollbacks++;
#endif

#ifdef CASCADING_RPS
		xchg_remote_rollback(ts);
#endif

		break;

	default:
		ss << "Unexpected thread state " << ts->state << 
			" at checkpoint return" << endl;
		DBGLOG(ss);
		PIN_ExitProcess(EXIT_FAILURE);
	}


	// Remove blocks
	if (ts->rp->Type() == RPBLOCKOTHERS) {
		// TRUE for acquiring VMlock
		ExitBlockingRP(ts, TRUE);
	}

	// Free checkpoint memory
	CheckpointFree(ts);

	// Set state to normal
	ts->state = NORMAL;

	// Set instrumentation version to normal
	return NORMAL_VERSION;
}


////////////////////////////////////////////////////
//	Instrumentation
////////////////////////////////////////////////////

#if FILTER_TYPE == FILTER_BITMAP
/**
 * Instrument memory writes to update filter with the memory locations written
 * by a thread. This handler is for bitmap filters.
 *
 * @param ins Instrumented write instruction
 * @param width Width of write in bits
 */
static VOID ForkWritesHandler(INS ins, UINT32 width)
{
	stringstream ss;
	AFUNPTR logwrite_fptr, logwrite_ext_fptr;

        switch (width) {
        case 8:
		logwrite_fptr = (AFUNPTR)ForkMarkB;
		logwrite_ext_fptr = NULL;
		break;
        case 16:
                logwrite_fptr = (AFUNPTR)ForkMarkW;
		logwrite_ext_fptr = (AFUNPTR)ForkMarkExtW;
                break;
        case 32:
                logwrite_fptr = (AFUNPTR)ForkMarkL;
		logwrite_ext_fptr = (AFUNPTR)ForkMarkExtL;
                break;
        case 64:
                logwrite_fptr = (AFUNPTR)ForkMarkQ;
		logwrite_ext_fptr = (AFUNPTR)ForkMarkExtQ;
                break;
        case 128:
                logwrite_fptr = (AFUNPTR)ForkMarkDQ;
		logwrite_ext_fptr = (AFUNPTR)ForkMarkExtDQ;
                break;
        case 256:
                logwrite_fptr = (AFUNPTR)ForkMarkQQ;
		logwrite_ext_fptr = (AFUNPTR)ForkMarkExtQQ;
                break;
        default:
                ss << "[ERROR] reassure could not find width(" << width << 
                        ") to write operand" << endl;
                ERRLOG(ss);
                PIN_ExitProcess(1);
        }

	if (logwrite_ext_fptr) {
		INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE, 
				(AFUNPTR)logwrite_fptr,
				IARG_FAST_ANALYSIS_CALL,
				IARG_REG_VALUE, tsreg, 
				IARG_MEMORYWRITE_EA,
				IARG_END);
		INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, 
				(AFUNPTR)logwrite_ext_fptr,
				IARG_FAST_ANALYSIS_CALL,
				IARG_REG_VALUE, tsreg, 
				IARG_MEMORYWRITE_EA,
				IARG_END);
	} else {
		INS_InsertPredicatedCall(ins, IPOINT_BEFORE, 
				(AFUNPTR)logwrite_fptr,
				IARG_FAST_ANALYSIS_CALL,
				IARG_REG_VALUE, tsreg, 
				IARG_MEMORYWRITE_EA,
				IARG_END);
	}
}
#elif FILTER_TYPE == FILTER_WLOG
/**
 * Instrument memory writes to update filter with the memory locations written
 * by a thread. This handler is for writes log filters.
 *
 * @param ins Instrumented write instruction
 * @param width Width of write in bits
 */
static VOID ForkWritesHandler(INS ins, UINT32 width)
{
	stringstream ss;
	AFUNPTR logwrite_fptr, checkwrite_fptr;

	switch (width) {
	case 8:
		logwrite_fptr = (AFUNPTR)ForkMarkB;
		checkwrite_fptr = (AFUNPTR)CheckCacheB;
		break;
	case 16:
		logwrite_fptr = (AFUNPTR)ForkMarkW;
		checkwrite_fptr = (AFUNPTR)CheckCacheW;
		break;
	case 32:
		logwrite_fptr = (AFUNPTR)ForkMarkL;
		checkwrite_fptr = (AFUNPTR)CheckCacheL;
		break;
	case 64:
		logwrite_fptr = (AFUNPTR)ForkMarkQ;
		checkwrite_fptr = (AFUNPTR)CheckCacheQ;
		break;
	case 128:
		logwrite_fptr = (AFUNPTR)ForkMarkDQ;
		checkwrite_fptr = (AFUNPTR)CheckCacheDQ;
		break;
	case 256:
		logwrite_fptr = (AFUNPTR)ForkMarkQQ;
		checkwrite_fptr = (AFUNPTR)CheckCacheQQ;
		break;
	default:
		logwrite_fptr = (AFUNPTR)NULL;
		checkwrite_fptr = (AFUNPTR)NULL;
		ss << "[ERROR] reassure could not find width(" << width << 
			") to write operand" << endl;
		ERRLOG(ss);
		PIN_ExitProcess(1);
	}

#if 1
	INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE, 
			(AFUNPTR)checkwrite_fptr,
			IARG_FAST_ANALYSIS_CALL,
			IARG_REG_VALUE, tsreg, 
			IARG_MEMORYWRITE_EA,
			IARG_END);
	INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, 
			(AFUNPTR)logwrite_fptr,
			IARG_FAST_ANALYSIS_CALL,
			IARG_REG_VALUE, tsreg, 
			IARG_MEMORYWRITE_EA,
			IARG_END);
#else
	INS_InsertPredicatedCall(ins, IPOINT_BEFORE, 
			(AFUNPTR)logwrite_fptr,
			IARG_FAST_ANALYSIS_CALL,
			IARG_REG_VALUE, tsreg, 
			IARG_MEMORYWRITE_EA,
			IARG_END);
#endif
}

#else
# error "unsupported filter type for fork checkpointing"
#endif

// Handle memory writes when a writes log is used for checkpointing
static VOID WLogWritesHandler(INS ins, UINT32 width) 
{
	AFUNPTR logwrite_fptr, checkwrite_fptr;
	stringstream ss;

	switch (width) {
	case 8:
		logwrite_fptr = (AFUNPTR)LogWriteB;
		checkwrite_fptr = (AFUNPTR)CheckCacheB;
		break;
	case 16:
		logwrite_fptr = (AFUNPTR)LogWriteW;
		checkwrite_fptr = (AFUNPTR)CheckCacheW;
		break;
	case 32:
		logwrite_fptr = (AFUNPTR)LogWriteL;
		checkwrite_fptr = (AFUNPTR)CheckCacheL;
		break;
	case 64:
		logwrite_fptr = (AFUNPTR)LogWriteQ;
		checkwrite_fptr = (AFUNPTR)CheckCacheQ;
		break;
	case 128:
		logwrite_fptr = (AFUNPTR)LogWriteDQ;
		checkwrite_fptr = (AFUNPTR)CheckCacheDQ;
		break;
	case 256:
		logwrite_fptr = (AFUNPTR)LogWriteQQ;
		checkwrite_fptr = (AFUNPTR)CheckCacheQQ;
		break;
	default:
		logwrite_fptr = (AFUNPTR)NULL;
		checkwrite_fptr = (AFUNPTR)NULL;
		ss << "[ERROR] reassure could not find width(" << width << 
			") to write operand" << endl;
		ERRLOG(ss);
		PIN_ExitProcess(1);
	}

	// Expand writes log if necessary
        INS_InsertIfCall(ins, IPOINT_BEFORE, 
                        (AFUNPTR)LogNeedsExpansion, IARG_FAST_ANALYSIS_CALL,
                        IARG_REG_VALUE, tsreg, IARG_END);
        INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)LogExpand, 
			IARG_REG_VALUE, tsreg, IARG_END);

#if 1 // Check if we have logged this entry before using an associative cache
	INS_InsertIfCall(ins, IPOINT_BEFORE, checkwrite_fptr,
			IARG_FAST_ANALYSIS_CALL, IARG_REG_VALUE, tsreg, 
			IARG_MEMORYWRITE_EA, IARG_END);
	// Log it if necessary
	INS_InsertThenCall(ins, IPOINT_BEFORE, logwrite_fptr,
			IARG_FAST_ANALYSIS_CALL, IARG_REG_VALUE, tsreg, 
			IARG_MEMORYWRITE_EA, IARG_END);
#else // Log everything
	INS_InsertCall(ins, IPOINT_BEFORE, logwrite_fptr,
			IARG_FAST_ANALYSIS_CALL, IARG_REG_VALUE, tsreg, 
			IARG_MEMORYWRITE_EA, IARG_END);
#endif
}

#ifdef CASCADING_RPS
/**
 * Mark instruction following a system call instruction, so that we can 
 * instrument it when encountered.
 *
 * @param trace Pin's trace
 * @param ins Pin's instruction
 */
static VOID MarkPostSyscallIns(TRACE trace, INS ins)
{
	ADDRINT addr, trace_addr;
	pair<set<ADDRINT>::iterator, bool> res;

	// Address of instruction following syscall
	addr = INS_Address(ins) + INS_Size(ins);
	//cerr << "Marking post-syscall instruction at " << (void *)addr << endl;
	// Store the address so we can later instrument it
	res = postsyscall_ins.insert(addr);
	if (!res.second)
		return; // We've encoutered this before

	// If the instruction is located in this trace do not invalidate it
	// We can instrument it on the fly now
	trace_addr = TRACE_Address(trace);
	if (addr < trace_addr && addr >= (trace_addr + TRACE_Size(trace)))
		InvalidateTraceAt(addr);
}

/**
 * Instrument instructions following system calls, so that we can start
 * checkpointing when we receive the appropriate message
 *
 * @param trace Pin's trace
 */
static VOID CascadeNormalInstrument(TRACE trace)
{
	INS ins;
	BBL bbl;
	set<ADDRINT>::iterator res;
	bool next_is_syscall = false;

	// Check if the first instruction in the trace follows a system call
	bbl = TRACE_BblHead(trace);
	if (!BBL_Valid(bbl))
		return;
	ins = BBL_InsHead(bbl);
	if (!INS_Valid(ins))
		return;
	res = postsyscall_ins.find(INS_Address(ins));
	if (res != postsyscall_ins.end()) {
		// Instructions following a system call can switch to
		// checkpointing (i.e., cascading reassure)
		INS_InsertVersionCase(ins, version_reg, 
			CHECKPOINT_VERSION, CHECKPOINT_VERSION);
		//cerr << "Instrumenting post-syscall ins at " << (void *)INS_Address(ins) << endl;
	}

	// Process all instructions
	for (bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
		for (ins = BBL_InsHead(bbl); INS_Valid(ins); 
				ins = INS_Next(ins)) {
			if (INS_IsSyscall(ins)) {
				//cerr << "Instrumenting syscall ins at " << (void *)INS_Address(ins) << endl;
				INS_InsertVersionCase(ins, version_reg, 
					CHECKPOINT_VERSION, CHECKPOINT_VERSION);
				MarkPostSyscallIns(trace, ins);
				next_is_syscall = true;
			} else if (next_is_syscall) {
				next_is_syscall = false;
				// Instructions following a system call can 
				// switch to checkpointing 
				// (i.e., cascading reassure)
				//cerr << "Instrumenting post-syscall ins at " << (void *)INS_Address(ins) << endl;
				INS_InsertVersionCase(ins, version_reg, 
					CHECKPOINT_VERSION, CHECKPOINT_VERSION);
			}
		} // for (ins)
	} // for (bbl)
}

/**
 * SIGURG handler.
 */
static BOOL OobHandler(THREADID tid, INT32 sig, CONTEXT *ctx, 
		BOOL hasHandler, const EXCEPTION_INFO *pExceptInfo, VOID *v)
{
	stringstream ss;
	struct thread_state *ts;

#ifdef CXCHG_DEBUG
	ss << "PIN [" << tid << "] Received SIGURG signal" << endl;
	DBGLOG(ss);
#endif

	ts = (struct thread_state *)PIN_GetContextReg(ctx, tsreg);
	xchg_commit(ts, ctx);

	if ((int)ts->orig_eax > 0) {
#ifdef CXCHG_DEBUG
		DBGLOG("Need to restart system call\n");
#endif
		ts->restart_syscall = true;
		PIN_SetContextReg(ctx, REG_INST_PTR, ts->last_syscall_pc);
	}

	return FALSE;
}
#endif // CASCADING_RPS

static VOID MemWriteHandler(INS ins, VOID *v) 
{
	UINT32 i, width;

	if (!INS_IsMemoryWrite(ins))
		return;

	for (i = 0, width = 0; i < INS_OperandCount(ins); i++)
		if (INS_OperandIsMemory(ins, i) && INS_OperandWritten(ins, i)) {
			width = INS_OperandWidth(ins, i);
			break;
		}

	switch (checkpoint_type) {
	case FORK_CHECKP:
		ForkWritesHandler(ins, width);
		break;

	case WLOG_CHECKP:
		WLogWritesHandler(ins, width);
		break;

	default:
		ERRLOG("Invalid checkpoint type " + checkpoint_type);
		PIN_ExitProcess(1);
		break;
	}
}

static VOID CheckpointInstrument(TRACE trace, RescuePoint *rp)
{
	INS ins;
	BBL bbl;

	// XXX: For this to work accurately i also need to block signals
	// while in a rescue point
	
	for (bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
		for (ins = BBL_InsHead(bbl); INS_Valid(ins); 
				ins = INS_Next(ins)) {
			//*log << " >> " << INS_Disassemble(ins) << endl;
	
			// Memory writes need to be rolled backed
			// XXX: Optimize this
			if (INS_IsMemoryWrite(ins))
				MemWriteHandler(ins, NULL);
#ifdef CASCADING_RPS
			if (INS_IsSyscall(ins))
				INS_InsertVersionCase(ins, version_reg, 
						NORMAL_VERSION, NORMAL_VERSION);
#endif

			if (INS_IsRet(ins) && rp) {
				INS_InsertCall(ins, IPOINT_BEFORE, 
					(AFUNPTR)CheckpointReturn,
					IARG_REG_VALUE, tsreg, 
					IARG_FUNCRET_EXITPOINT_REFERENCE,
					IARG_BOOL, rp->HasReturnValue(),
					IARG_ADDRINT, rp->ReturnValue(),
					IARG_RETURN_REGS, version_reg,
					IARG_END);
				BBL_SetTargetVersion(bbl, NORMAL_VERSION);
			}
		}
	}
}

static VOID BlockInstrument(TRACE trace)
{
	set<ADDRINT>::iterator it;
	ADDRINT addr;

	addr = TRACE_Address(trace);

	GetLock(&block_traces_lock, 1);
	for (it = block_traces.begin(); it != block_traces.end(); it++) {
		if (*it >= addr && (*it - addr) < TRACE_Size(trace)) {
			TRACE_InsertCall(trace, IPOINT_BEFORE, (AFUNPTR)Block2,
					IARG_REG_VALUE, tsreg, IARG_END);
			break;
		}
	}
	ReleaseLock(&block_traces_lock);
}

/**
 * Instrument a trace to switch to the correct instrumentation version
 *
 * @param trace Pin trace to instrument
 */
static inline void AutocorrectVersion(TRACE trace)
{
	INS ins;
	BBL bbl;

	for (bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
		for (ins = BBL_InsHead(bbl); INS_Valid(ins); 
				ins = INS_Next(ins)) {
			INS_InsertVersionCase(ins, version_reg, 
					NORMAL_VERSION, NORMAL_VERSION);
			INS_InsertVersionCase(ins, version_reg, 
					CHECKPOINT_VERSION, CHECKPOINT_VERSION);
		} // for (ins)
	} // for (bbl)
}

/**
 * Find a rescue point (if it exists) for a given instruction or trace address
 *
 * @param addr Address to look for
 *
 * @return Pointer to a rescue point object
 */
static RescuePoint *FindRescuePoint(ADDRINT addr)
{
	map<ADDRINT, RescuePoint *>::iterator it;
	RescuePoint *rp;

	// Returns an iterator pointing to the first element in the container
	// whose key does not compare less than x (using the container's
	// comparison object), i.e. it is either equal or greater.
	// This should be a rescue point for the function containing the
	// address, since the map uses the routine end address as a key, or the
	// rescue point for a function following addr.
	it = rescue_points_byaddr.lower_bound(addr);
	if (it == rescue_points_byaddr.end())
		return NULL;

	rp = it->second;
	if (addr >= rp->Address() && addr <= rp->EndAddress())
		return rp;
	return NULL;
}

/**
 * Find a RET instruction in a routine
 *
 * @param rtn Pin routine
 * @param rp Pointer to rescue point 
 *
 * @return TRUE if a RET instruction was found, or FALSE otherwise
 */
static BOOL FindRoutineRetIns(RTN rtn, RescuePoint *rp)
{
	INS ins;

	// Iterate over all of the routines's instructions
	for (ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
		// Mark RET instructions
		if (INS_IsRet(ins)) {
			// Set and return
			rp->SetRetAddress(INS_Address(ins));
			return TRUE;
		}
	}
	return TRUE;
}

/**
 * Instrument a trace
 *
 * @param trace Pin trace to instrument
 */
static VOID TraceInstrument(TRACE trace, VOID *v)
{
	ADDRINT version, addr;
	stringstream ss;
	RescuePoint *rp = NULL;

	// Trace address
	addr = TRACE_Address(trace);

	// Current version we are instrumenting in
	version = TRACE_Version(trace);

#ifdef TRACE_DEBUG
	ss << "Instrumenting trace (v." << version << ") at " << 
		(void *)addr << endl;
	DBGLOG(ss);
#endif

	// Correct instrumentation version
	if (version == AUTOCORRECT_VERSION) {
		AutocorrectVersion(trace);
		return;
	}

	// We setup blocking RP stuff, only if one existed in the configuration
	// XXX: Debug
	if (has_blocking_rp) {
		if (runtime_blocks) { 
			// runtime blocks are inserted on demand
			if (block_threads)
				// We need to instruments traces with blocks
				// because a thread has entered a blocking RP
				BlockInstrument(trace);
		} else {
			// fixed blocks are inserted at the beginning of 
			// every trace
			TRACE_InsertIfCall(trace, IPOINT_BEFORE,
					(AFUNPTR)ShouldBlock,
					IARG_FAST_ANALYSIS_CALL, IARG_END);
			TRACE_InsertThenCall(trace, IPOINT_BEFORE,
					(AFUNPTR)Block, 
					IARG_REG_VALUE, tsreg,
					IARG_END);
		}
	}

	// Find a rescue point
	rp = FindRescuePoint(addr);

	if (rp && rp->RetAddress() == 0) {
		// If there is no RET instruction associated with the RP at this
		// point we try to find one or we ignore it
		bool ret_found = false;
		RTN rtn = TRACE_Rtn(trace);

		if (RTN_Valid(rtn)) {
			// We need to open the rtn before going through its
			// instructions
			RTN_Open(rtn);
			ret_found = FindRoutineRetIns(rtn, rp);
			RTN_Close(rtn);
		}
		// XXX: We can extend the search to other routines
		if (!ret_found) {
			ERRLOG("Found a RP but it is not associated with a RET "
				"and it will be ignored\n");
			return;
		}
	}

	// Instrument code not checkpointing
	if (version == NORMAL_VERSION) {
		// First trace in RP
		if (rp && rp->Address() == addr) {
			ss << "Installing rescue point for " << rp->Id() << 
				"()..." << endl;
			OUTLOG(ss);

			// Insert code to enter the checkpoint
			INS_InsertCall(BBL_InsHead(TRACE_BblHead(trace)), 
					IPOINT_BEFORE, (AFUNPTR)Checkpoint, 
					IARG_REG_VALUE, tsreg, 
					IARG_CONST_CONTEXT, IARG_PTR, rp,
					IARG_RETURN_REGS, version_reg,
					IARG_END);
			// Switch to checkpointing version
			BBL_SetTargetVersion(TRACE_BblHead(trace), 
					CHECKPOINT_VERSION);
			// The rest of the code should also be instrumented for
			// checkpointing
			CheckpointInstrument(trace, rp);
		} 
#ifdef CASCADING_RPS
		else {
			CascadeNormalInstrument(trace);
		}
#endif
	} else if (version == CHECKPOINT_VERSION) {
		// Instrument code with checkpointing code
		CheckpointInstrument(trace, rp);
	}
}

/**
 * Check if a rescue point is defined for a routine. 
 * Rescue points defined by name are identified and their address resolved here.
 * If the binary is stripped this information is probably not available, and RPs
 * need to be defined by address
 */
static VOID RoutineInstrument(RTN rtn, VOID *v)
{
	string rname, dname;
	ADDRINT addr;
	stringstream ss;
	map<string, RescuePoint *>::iterator rp_it;
	map<ADDRINT, RescuePoint *>::iterator rp_it2;

	// Check if a rescue point exists for the routine using its address
	addr = RTN_Address(rtn);
	rp_it2 = rescue_points_byaddr.find(addr);
	if (rp_it2 != rescue_points_byaddr.end()) {
		// Find a RET instruction for this routine
		if (!FindRoutineRetIns(rtn, rp_it->second)) {
			ss << "Could not find a RET instruction for "
				"routine at " << (void *)addr << endl;
			OUTLOG(ss);
			// Remove rescue point as it cannot be handled
			rescue_points_byaddr.erase(rp_it2);
		}
		// These rescue points already have an end address associated
		return;
	}
	
	// Then check by demangled name
	RTN_Open(rtn);
	rname = RTN_Name(rtn);
	dname = PIN_UndecorateSymbolName(rname, UNDECORATION_NAME_ONLY);
	rp_it = rescue_points_byname.find(dname);

	if (rp_it != rescue_points_byname.end()) {
		// Find a RET instruction for this routine
		if (!FindRoutineRetIns(rtn, rp_it->second)) {
			ss << "Could not find a RET instruction for "
				"routine " << rname << "() at " << 
				(void *)addr << endl;
			OUTLOG(ss);
			// Remove rescue point as it cannot be handled
			rescue_points_byname.erase(rp_it);
			return;
		}

		// Set the address range of the routine
		rp_it->second->SetAddress(addr);
		rp_it->second->SetEndAddress(addr + RTN_Size(rtn) - 1);

#ifdef RESCUE_POINT_DEBUG
		ss << "Found RP function " << rname << "() " << (void *)addr <<
			':' << (void *)rp_it->second->EndAddress() << endl;
		DBGLOG(ss);
#endif

		// Now that we know it's address, make sure we can find it
		// easily
		rescue_points_byaddr.insert(pair<ADDRINT, RescuePoint *>
				(rp_it->second->EndAddress(), rp_it->second));
	}
	RTN_Close(rtn);
}

static VOID ThreadStart(THREADID tid, CONTEXT *ctx, INT32 flags, VOID *v)
{
	struct thread_state *newts;
	stringstream ss;
	ADDRINT version;

	running_threads++;
	// PIN stops all threads while in this call
#ifdef THREAD_DEBUG
	ss << "PIN [" << tid << "] thread starting, real: " << 
		gettid() << ", total running = " << running_threads << endl;
	DBGLOG(ss);
#endif
	if (block_threads && runtime_blocks) {
		InsertBlock(tid, PIN_GetContextReg(ctx, REG_INST_PTR));
	}

	// Allocate new thread state
	newts = (struct thread_state *)calloc(1, sizeof(struct thread_state));
	assert(newts);
	// Initialize
	ThreadstateInit(newts, tid);
	// Assign it to the thread
	PIN_SetContextReg(ctx, tsreg, (ADDRINT)newts);

	// Set version of newly created thread
	version = PIN_GetContextReg(ctx, version_reg);
	if (version == AUTOCORRECT_VERSION) {
		PIN_SetContextReg(ctx, version_reg, NORMAL_VERSION);
#ifdef VERSION_DEBUG
		ss << "Thread " << tid << " switched to version " << 
			NORMAL_VERSION << endl;
		DBGLOG(ss);
#endif
	}

	// Add to global list of thread states
	GetLock(&tsmap_lock, tid + 1);
	tsmap[tid] = newts;
	ReleaseLock(&tsmap_lock);
}

static VOID ThreadFini(THREADID tid, const CONTEXT *ctx, INT32 code, VOID *v)
{
	struct thread_state *ts;

	--running_threads;

	ts = (struct thread_state *)PIN_GetContextReg(ctx, tsreg);
	assert(ts);

#ifdef THREAD_DEBUG
	{
		stringstream ss;

		ss << "PIN [" << tid << "] thread exiting, real: " << 
			ts->real_tid << ", remaining = " << 
			running_threads << endl;
		DBGLOG(ss);
	}
#endif

	if (ts->state == CHECKPOINTING) {
		if (checkpoint_type == FORK_CHECKP)
			CheckpointForkCommit(ts->memcheckp.flog);
		// Remove blocks
		if (ts->rp && ts->rp->Type() == RPBLOCKOTHERS) {
			ExitBlockingRP(ts);
		}
	}
	ThreadstateCleanup(ts);
	GetLock(&tsmap_lock, tid + 1);
	tsmap.erase(tid);
	ReleaseLock(&tsmap_lock);
	free(ts);
}

static BOOL BlockThreadHandler(THREADID tid, INT32 sig, CONTEXT *ctx, 
		BOOL hasHandler, const EXCEPTION_INFO *pExceptInfo, VOID *v)
{
	struct thread_state *ts;
#ifdef THREAD_DEBUG
	stringstream ss;
#endif

	ts = (struct thread_state *)PIN_GetContextReg(ctx, tsreg);

	if (block_threads && !ts->blocked) {
#ifdef THREAD_DEBUG
		ss << "PIN [" << ts->tid << "] block signal delivered" << endl;
		DBGLOG(ss);
#endif
		InsertBlock(tid, PIN_GetContextReg(ctx, REG_INST_PTR));
	} 
#ifdef THREAD_DEBUG
	else {
		ss << "PIN [" << tid << "] block signal ignored" << endl;
		DBGLOG(ss);
	}
#endif
	return FALSE;
}

static VOID SysEnter(THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD std, VOID *v)
{
	struct thread_state *ts;

	ts = (struct thread_state *)PIN_GetContextReg(ctx, tsreg);
	ts->in_syscall = PIN_GetSyscallNumber(ctx, std);
	HandleSysEnter(ts, ctx, std);
}

static VOID SysExit(THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD std, VOID *v)
{
	struct thread_state *ts;
	ADDRINT ret, err;

	ts = (struct thread_state *)PIN_GetContextReg(ctx, tsreg);
	ret = PIN_GetSyscallReturn(ctx, std);
	err = PIN_GetSyscallErrno(ctx, std);
	HandleSysExit(ts, ctx, ret, err);
	ts->in_syscall = 0;

	if (ts->state != CHECKPOINTING && runtime_blocks && block_threads) {
#ifdef THREAD_DEBUG
		stringstream ss;

		ss << "PIN [" << tid << "] just exited syscall and needs to "
			"be blocked" << endl;
		DBGLOG(ss);
#endif	
#ifdef SYSEXIT_DECODE
		char hbuf[20];
		ADDRINT eip;
		size_t copied;

		eip = PIN_GetContextReg(ctx, REG_INST_PTR);
		copied = PIN_SafeCopy(hbuf, (void *)eip, 20);
		DecodeInstruction(eip, hbuf, copied);
#endif
		InsertBlock(tid, PIN_GetContextReg(ctx, REG_INST_PTR));
	}
}

static VOID Fini(INT32 code, VOID *v)
{
	stringstream ss;

#ifdef COLLECT_STATS
	ss << "Process pid " << PIN_GetPid() << " exiting..." << endl;
	ss << "Number of checkpoints: " << stats_checkpoints << endl;
	ss << "Number of rollbacks  : " << stats_rollbacks << endl;
	ss << "Number of commits    : " << stats_commits << endl;
	ss << "Cache hit ratio      : " << ((float)(cache_accesses - 
				cache_misses) / cache_accesses) * 100;
	ss << " misses=" << cache_misses << " hits=" << 
		cache_accesses - cache_misses << endl;
	DBGLOG(ss);
#endif
}

// Free all thread states except the one forking
static VOID Fork(THREADID tid, const CONTEXT *ctx, VOID *v)
{
	map<THREADID, struct thread_state *>::iterator it;
	struct thread_state *ts, *tsit;

	ts = (struct thread_state *)PIN_GetContextReg(ctx, tsreg);

	if (ts->state != NORMAL) {
		ERRLOG("Fork while in checkpoint not supported\n");
		PIN_ExitProcess(1);
	}

	GetLock(&tsmap_lock, tid + 1);
	// Delete all other threads except myself
	for (it = tsmap.begin(); it != tsmap.end(); ) {
		tsit = (*it).second;
		if (tsit == ts) {
			it++;
		} else {
			ThreadstateCleanup(tsit);
			free(tsit);
			tsmap.erase(it++);
		}
	}
	ReleaseLock(&tsmap_lock);

	// Setup globals
	blocking_tid = -1;
	block_threads = 0;
	running_threads = 1;
#ifdef COLLECT_STATS
	stats_checkpoints = stats_rollbacks = stats_commits = 0;
	cache_accesses = cache_misses = 0;
#endif
}

// Return pointer to thread state structure based on thread id
static struct thread_state *ThreadstateFind(THREADID tid)
{
	map<THREADID, struct thread_state *>::iterator it;

	it = tsmap.find(tid);
	if (it != tsmap.end())
		return (*it).second;
	return NULL;
}

static bool GenericFaultHandler(struct thread_state *ts, CONTEXT *ctx, 
		const EXCEPTION_INFO *pExceptInfo, const char *desc) {
	stringstream ss;

	if (ts->state == ROLLINGBACK) {
		ss << "PIN [" << ts->tid << "] Received " << desc <<
			" while rolling back!" << endl <<
			"Submit a bug report!" << endl;
		ERRLOG(ss);
		return false;
	} else if (ts->state != CHECKPOINTING) {
#ifdef CASCADING_RPS
no_rp:
#endif
		ss << "PIN [" << ts->tid << "] Received " << desc <<
			" outside a rescue point" << endl;
		OUTLOG(ss);
		return false;
	}
#ifdef CASCADING_RPS
	if (!ts->rp)
		goto no_rp;;
#endif

#ifdef CHECKPOINT_DEBUG
	ss << "PIN [" << ts->tid << "] Received " << desc <<
		" within a rescue point" << endl;
	DBGLOG(ss);
#endif
	OUTLOG("!!!Fault within rescue point, rolling back!!!\n");

	// Redirect execution to the RET instruction associated with the RP
	reassure_rollback(ts, ctx, ts->rp->RetAddress());

	return true;
}

/**
 * Rollback execution of a thread by restoring memory and CPU state.
 *
 * @param ts Pointer to thread state
 * @param ctx Pointer to CPU context
 * @param new_pc New program counter, where execution will resume from
 */
void reassure_rollback(struct thread_state *ts, CONTEXT *ctx, ADDRINT new_pc)
{
	// Set state as rolling back
	ts->state = ROLLINGBACK;

	// Rollback memory changes. We can only update the context here, not
	// from CheckpointReturn() because analysis routines cannot update the
	// CONTEXT
	PIN_LockClient();
	CheckpointRollback(ts, ctx);
	PIN_UnlockClient();

	// Correct instrumentation version
	PIN_SetContextReg(ctx, version_reg, CHECKPOINT_VERSION);

	// Redirect execution
	PIN_SetContextReg(ctx, REG_INST_PTR, new_pc);
}

/**
 * Handle a fault such as a signal.
 *
 * @param tid Thread id that received the fault
 * @param sig Signal number
 * @param ctx Pointer to CPU state, can be also updated
 * @param hasHandler True if the application has its own handler for the fault
 * @param pExceptInfo Pointer to exception information
 * @return One of the types defined by the REASSURE_EHANDLING_RESULT
 */
reassure_ehandling_result_t reassure_handle_fault(THREADID tid, INT32 sig, 
		CONTEXT *ctx, BOOL hasHandler, const EXCEPTION_INFO *pExceptInfo)
{
	struct thread_state *ts;
	stringstream ss;

	ss << "signal " << strsignal(sig);

	ts = (struct thread_state *)PIN_GetContextReg(ctx, tsreg);
	assert(ts);

	if (GenericFaultHandler(ts, ctx, pExceptInfo, ss.str().c_str()))
		return RHR_RESCUED;
	return RHR_ERROR;
}

/**
 * Handle a internal fault.
 *
 * @param tid Thread id that received the fault
 * @param pExceptInfo Pointer to exception information
 * @param pctx Pointer to CPU physical state when the error occured
 * @param ctx Pointer to store CPU state, if we need to resume execution with
 * updated state (when returning RHR_UPDATESTATE).
 * @return One of the types defined by the REASSURE_EHANDLING_RESULT
 */
reassure_ehandling_result_t reassure_handle_internal_fault(THREADID tid, 
		EXCEPTION_INFO *pExceptInfo, PHYSICAL_CONTEXT *pctx, 
		CONTEXT *ctx)
{
	map<THREADID, struct thread_state *>::iterator it;
	struct thread_state *ts;

	ts = ThreadstateFind(tid);
	assert(ts);

#if FILTER_TYPE == FILTER_WLOG
	if (checkpoint_type == FORK_CHECKP) {
		if (filter_handle_internal_fault(&ts->memcheckp.flog->filter,
					pExceptInfo))
			return RHR_HANDLED;
		CheckpointForkBail(ts->memcheckp.flog);
		return RHR_ERROR;
	}
#endif

	if (GenericFaultHandler(ts, ctx, pExceptInfo, "internal fault"))
		return RHR_RESCUED;

	return RHR_ERROR;
}


int reassure_init(const char *conf_fn, BOOL rb, checkp_t ctype)
{
#ifdef SYSEXIT_DECODE
        xed_tables_init();
        xed_decode_init();

        xed_state_zero(&dstate);
        xed_state_init(&dstate, XED_MACHINE_MODE_LEGACY_32,
                        XED_ADDRESS_WIDTH_32b, XED_ADDRESS_WIDTH_32b);
#endif

	if (ParseConf(conf_fn, rescue_points_byname, rescue_points_byaddr, 
				&has_blocking_rp) != 0)
		return -1;

#ifdef CASCADING_RPS
	if(xchg_init() != 0)
	{
		perror("xchg_init: failed");
		return -1;
	}
	// Capture SIGURG signal for committing checkpoints
	PIN_UnblockSignal(SIGURG, TRUE);
	PIN_InterceptSignal(SIGURG, OobHandler, 0);
#endif

	// Allocate version register
	version_reg = PIN_ClaimToolRegister();
	assert(version_reg != REG_INVALID());

	// Thread state keeping
	tsreg = PIN_ClaimToolRegister();
	assert(tsreg != REG_INVALID());
	InitLock(&tsmap_lock);

	runtime_blocks = rb;
	InitLock(&blocking_checkpoint_lock);
	InitLock(&block_traces_lock);
	InitLock(&checkpoint_lock);

	checkpoint_type = ctype;

	PIN_AddThreadStartFunction(ThreadStart, 0);
	PIN_AddThreadFiniFunction(ThreadFini, 0);

	TRACE_AddInstrumentFunction(TraceInstrument, 0);
	RTN_AddInstrumentFunction(RoutineInstrument, 0);

	PIN_AddSyscallEntryFunction(SysEnter, 0);
	PIN_AddSyscallExitFunction(SysExit, 0);

	if (has_blocking_rp && runtime_blocks) {
		PIN_UnblockSignal(TBLOCK_SIGNAL, TRUE);
		PIN_InterceptSignal(TBLOCK_SIGNAL, BlockThreadHandler, 0);
	}

	PIN_AddFiniFunction(Fini, 0);
	PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, Fork, 0);

	return 0;
}
