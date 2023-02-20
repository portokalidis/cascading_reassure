#include <iostream>
#include <sstream>

extern "C" {
#include <stdlib.h>
}
#include "pin.H"
#include "watchdog.hpp"
#include "log.hpp"
#include "reassure.h"

// Semaphore used for sleeping
static PIN_SEMAPHORE sem;
// Creation time
static time_t epoch;
// Timeout
static unsigned long long timeout;

unsigned long long WatchdogRemaining()
{
	time_t nepoch, lifetime;

	time(&nepoch);
	lifetime = nepoch - epoch;

	if ((unsigned long long)lifetime < timeout)
		return (timeout - lifetime);
	return 0;
}

// Wait until timeout elapses, or until process terminates
static VOID WatchdogRun(void *arg)
{
	time_t nepoch, lifetime;

	time(&nepoch);
	lifetime = nepoch - epoch;

	// Check that we have not already exceeded the allowed run time
	if ((unsigned long long)lifetime < timeout) {
		/* wait until the application is exiting or a timeout has 
		 * occurred */
		if (PIN_SemaphoreTimedWait(&sem, 1000 * (timeout - lifetime)))
			return; // Application is terminating
	}

	// If the process is exiting, don't consider this as a timeout
	if (!PIN_IsProcessExiting()) {
		  /* 
                 * emit the necessary XML message for the
                 * test harness and terminate the process
                 */
		LogExecuteStatus(ES_TIMEOUT, EXIT_FAILURE);

                /* terminate */
                PIN_ExitProcess(EXIT_FAILURE);
	}
}

// Stop the watchdog by setting the semaphore
static VOID WatchdogStop(INT32 code, VOID *v)
{
	PIN_SemaphoreSet(&sem);
}

VOID WatchdogInit(unsigned long long tmout)
{
	PIN_SemaphoreInit(&sem);
	time(&epoch);
	timeout = tmout;

	PIN_AddFiniUnlockedFunction(WatchdogStop, NULL);
}

BOOL WatchdogStart()
{
	THREADID watchdog_tid;
	
	watchdog_tid = PIN_SpawnInternalThread(WatchdogRun, NULL, 0, NULL);
	if (watchdog_tid == INVALID_THREADID) {
		ERRLOG("cannot start watchdog thread");
		return FALSE;
	}

	return TRUE;
}

