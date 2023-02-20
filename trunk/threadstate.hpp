#ifndef THREADSTATE
#define THREADSTATE

extern "C" {
#include <sys/uio.h>
}

#include "syscall_desc.h"


// Thread states
// Thread executing normally (matches Pin NORMAL_VERSION)
#define NORMAL 		0
// Thread executing in checkpointing mode (matches Pin CHECKPOINT_VERSION)
#define CHECKPOINTING 	1
// Transient state to capture errors during rolling back
#define ROLLINGBACK	2 
// Transient state to capture errors during committing
#define COMMITTING	3


class RescuePoint;

/* Holds the header and data for read-like system calls */
typedef struct hdr_data {
	//UINT32 id;
	UINT32 len;
	UINT8 cmd;
} __attribute((__packed__)) hdr_data_t;

class RescuePoint;
struct writeslog;
struct forklog;

// XXX: Re-arrange for performance
struct thread_state {
	unsigned int state; //!< Thread state

	//! Structures to log necessary information to recover memory state
	union {
		struct writeslog *wlog; //!< For writes log
		struct forklog *flog; //!< For filter using fork()
	} memcheckp;

	CONTEXT *checkpoint; //!< CPU state on rescue point entry
	RescuePoint *rp; //!< Active rescue point

	//! Thread blocking stuff
	bool blocked; //!< Is thread blocked
	pid_t real_tid; //!< Read thread id of thread

	//! Syscall stuff
	ADDRINT in_syscall; //!< Syscall thread is in, or 0 if not in a syscall
	ADDRINT sysargs[SYSARGS_MAX]; //!< System call arguments

	THREADID tid; //!< Pin thread id

#ifdef CASCADING_RPS
	int checkpoint_fd; //!< Socket that caused us to start checkpointing
	struct f_owner_ex previous_owner; //!< Previous owner of checkpoint_fd
	//! Vector of pointers to structs type fd_info_t
	//! Used for the socket-descriptors set
	//! in CHECKPOINTING mode by this thread   
	vector<unsigned int> fd_checkpointed;

	//! iovec used for writing/reading header and data into one go
	struct iovec vec[2];
	//! Data that have been read from the buffered data of a socket before
	//! the read, and need to be accounted in the return value of the read
	//! syscall
	unsigned int already_read;
	hdr_data_t write_hdr; //!< Protocol header for writes
	bool fake_read; //!< Read syscall is fake
	ADDRINT saved_pc; //!< Address to return to if we rollback

	//! The id of the communicating party
	//! Might be the IP + random number
	UINT32 id;

	ADDRINT last_syscall_pc; //!< PC of last syscall instruction
	int orig_eax; //!< Used to restart syscalls
	bool restart_syscall; //!< Restart system call
#endif
};

void CheckpointCreate(struct thread_state *ts, const CONTEXT *ctx);
void CheckpointFree(struct thread_state *ts);
void CheckpointRollback(struct thread_state *ts, CONTEXT *ctx);

void ThreadstateInit(struct thread_state *ts, THREADID tid);
void ThreadstateCleanup(struct thread_state *ts);

#endif
