#include <iostream>
#include <sstream>
#include <cassert>

extern "C" {
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>

#include <sys/types.h>
#include <sys/wait.h>
}

#include "pin.H"
#include "cache.h"
#include "fork.h"
#include "log.hpp"
#include "debug.h"


// Main routine for checkpoint process
// Since this is a fork() off Pin, we only use cerr for logging to interfere the
// least possible with Pin
static void CheckpointChild(struct forklog *flog, int pipe)
{
	int r;
	stringstream ss;

#ifdef FLOG_DEBUG
	DBGLOG("Checkpoint process running\n");
#endif

retry:
	if  ((r = sem_wait(&flog->sem)) != 0) {
		if (errno == EINTR)
			goto retry;
		ss << "checkpoint child error while waiting: " << 
			strerror(errno) << endl;
		ERRLOG(ss);
	}

	switch (flog->state) {
	case FORK_COMMIT:
#ifdef FLOG_DEBUG
		DBGLOG("Checkpoint process committing\n");
#endif
		break;

	case FORK_BAIL:
#ifdef FLOG_DEBUG
		DBGLOG("Checkpoint process bailing out\n");
#endif
		break;

	case FORK_ROLLBACK:
#ifdef FLOG_DEBUG
		DBGLOG("Checkpoint process rolling back\n");
#endif
		filter_child_rollback(&flog->filter, pipe);
		break;

	default:
		ERRLOG("Unknown FORK state\n");
		break;
	}

	close(pipe);

#ifdef FLOG_DEBUG
	ERRLOG("Checkpoint process exiting\n");
#endif
	exit(0);
}

/**
 * Commit changes, the checkpoint process need to do nothing.
 *
 * @param flog Pointer to forklog structure
 */
void CheckpointForkCommit(struct forklog *flog)
{
#ifdef FLOG_DEBUG
	DBGLOG("Signaling checkpoint process to commit\n");
#endif
	flog->state = FORK_COMMIT;
	if (sem_post(&flog->sem) != 0) {
		stringstream ss;

		ss << "checkpoint fork commit error while signaling child: ";
		ss << strerror(errno) << endl;
		ERRLOG(ss);
	}
	close(flog->pipefd);
}

/**
 * Abandon checkpoint due to an error.
 * The checkpoint process is signaled to exit.
 *
 * @param flog Pointer to forklog structure
 */
void CheckpointForkBail(struct forklog *flog)
{
#ifdef FLOG_DEBUG
	DBGLOG("Signaling checkpoint process to bail out\n");
#endif
	flog->state = FORK_BAIL;
	if (sem_post(&flog->sem) != 0) {
		stringstream ss;

		ss << "checkpoint fork commit error while signaling child: ";
		ss << strerror(errno) << endl;
		ERRLOG(ss);
	}
	close(flog->pipefd);
}

/**
 * Rollback changes, we will receive the original memory contents from the
 * checkpoint process
 *
 * @param flog Pointer to forklog structure
 */
void CheckpointForkRollback(struct forklog *flog)
{

#ifdef FLOG_DEBUG
	DBGLOG("Signaling checkpoint process to rollback\n");
#endif

	flog->state = FORK_ROLLBACK;
	if (sem_post(&flog->sem) != 0) {
		stringstream ss;
		ss << "checkpoint fork rollback error while signaling child: ";
		ss << strerror(errno) << endl;
		ERRLOG(ss);
	}

	if (!filter_parent_rollback(flog->pipefd)) {
		ERRLOG("checkpoint fork rollback failed while recovering "
				"memory contents\n"); 
		PIN_ExitProcess(1);
	}
	close(flog->pipefd);

#ifdef FLOG_DEBUG
	DBGLOG("Rollback through checkpoint process completed \n");
#endif
}

/**
 * Perform a checkpoint by forking a process.
 * A filter shared between the real process and the checkpoint (assistant)
 * process is used to mark the memory areas that were written and need to be
 * rolled back in case of an error later on.
 *
 * @param flog Pointer to forklog structure
 */
int CheckpointFork(struct forklog *flog)
{
	int fds[2];
	pid_t p;
	stringstream ss;


	if (pipe(fds) != 0) {
		ss << "checkpoint fork() could not create pipe: ";
err:
		ss << strerror(errno) << endl;
		ERRLOG(ss);
		PIN_ExitProcess(EXIT_FAILURE);
		return -1;
	}

	// Initialize shared semaphore
	if (sem_init(&flog->sem, 1, 0) != 0) { // XXX: Needs to be destroyed
		ss << "checkpoint fork() could not initialize semaphore: ";
		goto err;
	}

	p = fork();
	if (p < 0) {
		ss << "checkpoint fork() could not create process: ";
		goto err;
	} else if (p == 0) { // Child
		close(fds[0]);
		CheckpointChild(flog, fds[1]);
		return 0; // Never return
	}

	// Parent
	close(fds[1]);
	flog->pipefd = fds[0];
	return 0;
}

struct forklog *FLogAlloc(void)
{
	struct forklog *flog;

	flog = (struct forklog *)mmap(NULL, sizeof(struct forklog),
			PROT_READ|PROT_WRITE, 
			MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	assert(flog != MAP_FAILED);
	filter_init(&flog->filter);

	return flog;
}

void FLogFree(struct forklog *flog)
{
	filter_cleanup(&flog->filter);
	munmap(flog, sizeof(struct forklog));
}

