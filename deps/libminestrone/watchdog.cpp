#include <iostream>
#include <sstream>
#include <cassert>

#ifdef TARGET_LINUX
extern "C" {
#include <stdlib.h>
#include <string.h>
#include <time.h>
}
#endif


#include "pin.H"
#include "libminestrone.hpp"


//! Get a rough estimate of the difference in seconds between two time specs
#define tsdiff(ts1, ts2) 	((ts2).tv_sec - (ts1).tv_sec)


//! Semaphore used for sleeping
static PIN_SEMAPHORE sem;
//! Creation time
static struct timespec epoch;
//! Timeout
static unsigned long long timeout;

//! For correct watchdog support for children
static struct command_line {
        int argc;
        char **argv;
} cmdln;


// Define command line options
#include "watchdog_opts.hpp"



/**
 * Stop the watchdog by setting the semaphore.
 * The call adheres to Pin's fini API.
 *
 * @param code	Exit code
 * @param v	Opaque pointer
 */
static void watchdog_stop(INT32 code, VOID *v)
{
	PIN_SemaphoreSet(&sem);
}

/**
 * Timeout. Log a message and exit.
 */
static void watchdog_timeout()
{
	 /* 
	 * emit the necessary XML message for the
	 * test harness and terminate the process
	 */
	minestrone_log_status(ES_TIMEOUT, EXIT_FAILURE);

	/* terminate */
	PIN_ExitProcess(EXIT_FAILURE);
}

/**
 * Watchdog thread main routine.
 * Wait until timeout elapses, or until process terminates.
 *
 * @param arg	Opaque pointer
 */
static VOID watchdog_run(void *arg)
{
	struct timespec nepoch;
	unsigned long long lifetime;

	clock_gettime(CLOCK_MONOTONIC, &nepoch);
	lifetime = tsdiff(epoch, nepoch);

	// Check that we have not already exceeded the allowed run time
	if (lifetime < timeout) {
		/* wait until the application is exiting or a timeout has 
		 * occurred */
		if (PIN_SemaphoreTimedWait(&sem, 
					1000 * (unsigned)(timeout - lifetime)))
			return; // Application is terminating
	}

	// If the process is exiting, don't consider this as a timeout
	if (!PIN_IsProcessExiting())
		watchdog_timeout();
}

/**
 * Save command line of the running process.
 *
 * @param argc	Number of command line arguments
 * @param argv	Array of command line arguments
 */
static inline void save_cmd_line(int argc, char **argv) 
{ 
        int i; 
        char *argv_copy; 
 
        cmdln.argc = argc; 
        cmdln.argv = (char **)malloc((argc + 1) * sizeof(char **)); 
        ASSERT(cmdln.argv, "Error allocating memory for command line "
			"arguments array\n"); 
 
        for (i = 0; i < argc; i++) {
                argv_copy = strdup(argv[i]); 
                ASSERT(argv_copy, "Error allocating memory for command line "
				" arguments\n");
                //cout << "ARG[" << i << "]=" << argv_copy << endl; 
                cmdln.argv[i] = argv_copy; 
        } 
        cmdln.argv[i] = NULL; 
}

/**
 * fork() handler to start minestrone watchdog process for child processes.
 *
 * @param TID	Pin's thread ID
 * @param ctx	Pointer to CPU context
 * @param v	Opague pointer
 */
static void fork_handler(THREADID tid, const CONTEXT *ctx, VOID *v)
{
	if (!minestrone_watchdog_start())
		PIN_ExitProcess(EXIT_FAILURE);
}

/**
 * exec() handler. 
 * Modifies command line arguments to reflect the remaining time.
 *
 * @param child	Pin's child process reference
 * @param v	Opaque pointer
 *
 * @return Always TRUE to inject Pin in the new process
 */
static BOOL exec_handler(CHILD_PROCESS child, VOID *v)
{
        int i;
	unsigned long long lifetime;
	struct timespec nepoch;
	stringstream ss;

        for (i = 0; i < cmdln.argc; i++) {
                // Stop looking if we reached the application's arguments
                if (strcmp(cmdln.argv[i], "--") == 0)
                        break;
                // Look for the timeout option
                if (strcmp(cmdln.argv[i], "-"TIMEOUT_OPTION) == 0) {
                        if (++i >= cmdln.argc) {
				ss << "No timeout option found in exec'ed "
					"child's command line" << endl;
				cerr << ss;
				LOG(ss.str());
                                PIN_ExitProcess(EXIT_FAILURE);
                        }

			clock_gettime(CLOCK_MONOTONIC, &nepoch);
			lifetime = tsdiff(epoch, nepoch);
			if (lifetime >= timeout)
				watchdog_timeout();
			ss << (timeout - lifetime); // Remaining lifetime

#ifdef TARGET_LINUX
                        cmdln.argv[i] = strdup(ss.str().c_str());
#endif
#ifdef TARGET_WINDOWS
			cmdln.argv[i] = _strdup(ss.str().c_str());
#endif
                        break;
                }
        }

        CHILD_PROCESS_SetPinCommandLine(child, cmdln.argc, cmdln.argv);
        return TRUE;
}



/**
 * Initialize watchdog with the given command line arguments and timeout value.
 *
 * @param argc	Number of command line arguments
 * @param argv	Array of command line arguments
 * @param tmout	Timeout in seconds
 */
void minestrone_watchdog_init(int argc, char **argv, unsigned long long tmout)
{
	save_cmd_line(argc, argv);
	PIN_SemaphoreInit(&sem);
	clock_gettime(CLOCK_MONOTONIC, &epoch);
	timeout = tmout;
	PIN_AddFiniUnlockedFunction(watchdog_stop, NULL);
#ifdef TARGET_LINUX
	PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, fork_handler, 0);
#endif
	PIN_AddFollowChildProcessFunction(exec_handler, NULL);
}

/**
 * Start watchdog thread.
 *
 * @return TRUE if successful, or FALSE on error
 */
BOOL minestrone_watchdog_start(void)
{
	THREADID watchdog_tid;
	
	watchdog_tid = PIN_SpawnInternalThread(watchdog_run, NULL, 0, NULL);
	if (watchdog_tid == INVALID_THREADID) {
		cerr << "cannot start watchdog thread" << endl;
		LOG("cannot start watchdog thread\n");
		return FALSE;
	}

	return TRUE;
}

