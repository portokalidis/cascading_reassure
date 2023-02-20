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
#include <fcntl.h>
}

#include "pin.H"
#include "threadstate.hpp"
#include "utils.hpp"
#include "libreassure.hpp"
#include "watchdog.hpp"
#include "log.hpp"
#include "reassure.h"
#include "debug.h"


#define gettid()		syscall(SYS_gettid)
#define tkill(p, s)		syscall(SYS_tkill, (p), (s))
#define tgkill(pp, p, s)	syscall(SYS_tgkill, (pp), (p), (s))


#define TIMEOUT_OPTION "timeout"

// For correct watchdog support for children
static struct command_line {
        int argc;
        char **argv;
} cmdln;


// Rescue points configuration 
static KNOB<string> ConfigFile(KNOB_MODE_WRITEONCE, "pintool", "c", 
		"reassure.conf", "REASSURE configuration file.");

// Set type of blocking rescue points
static KNOB<BOOL> RuntimeBlock(KNOB_MODE_WRITEONCE, "pintool", "rb", 
		"1", "Use runtime blocks for blocking rescue points. Faster "
		"for non-rescue point code, but slower when blocking rescue "
		"points occur extremely often.");

// Use fork() to perform checkpoints and simply mark the written memory
// addresses
static KNOB<BOOL> ForkCheckpoint(KNOB_MODE_WRITEONCE, "pintool", "f", "1",
		"Use fork to perform checkpoints. Faster for most "
		"types of checkpoints.");

// Original name
static KNOB<string> OriginalName(KNOB_MODE_WRITEONCE, "pintool",
    "n", "", "Specify executable's original name. For reporting errors.");

// Timeout in seconds (we exit if execution takes more than this value)
KNOB<unsigned long long> ExecTimeout(KNOB_MODE_WRITEONCE, "pintool",
                TIMEOUT_OPTION, "0", "Timeout in seconds. Stop executing "
                "after specified amount of seconds). 0 disables timeout.");

// Reference Id
static KNOB<string> ReferenceId(KNOB_MODE_WRITEONCE, "pintool",
    "ref", "", "Specify reference-id. For reporting errors.");

// Notification messages to stderr
static KNOB<bool> NotifyStderr(KNOB_MODE_WRITEONCE, "pintool",
    "notify", "0", "Notification messages are also written to stderr.");


// Add signal that causes exit to this base and exit process with this code
#define SIGEXITCODE_BASE 128



//////////////////
// Helper
//////////////////

static VOID Usage(void)
{
	cout << "This is the RE-ASSURE tool, implementing Rescue Points for"
		" binaries" << endl;
	cout << KNOB_BASE::StringKnobSummary() << endl;
}

#if 0
static void ReportDoS(stringstream &ss)
{
        ss << "<structured_message>" << endl;
        ss << "\t<message_type>technical_impact" << "</message_type>" << endl;
        ss << "\t<impact>" << "DOS_INSTABILITY" << "</impact>" << endl;
        ss << "\t<test_case>" << OriginalName.Value() << "</test_case>" 
		<< endl;
        ss << "</structured_message>" << endl;
}
#endif

static VOID AppendTestCase(stringstream &ss)
{
	ss << "\t<test_case>" << OriginalName.Value() << "</test_case>" << endl;
	ss << "\t<ref_id>" << ReferenceId.Value() << "</ref_id>" << endl;
}

static inline VOID notify(stringstream &ss)
{
	if (NotifyStderr.Value()) {
		ERRLOG(ss);
	} else {
		OUTLOG(ss);
	}
	ss.str("");
}

static void MinestroneNotify(THREADID tid, const EXCEPTION_INFO *pExceptInfo)
{
	stringstream ss;
	EXCEPTION_CODE code; 
	ADDRINT fault_addr;

#if 0
        if (reassure_threadstate(tid) == ROLLINGBACK) {
                // Something went terribly wrong during recovery
                ss << "<structured_message>" << endl;
                ss << "\t<message_type>controlled_exit" <<
                        "</message_type>" << endl;
                ss << "\t<test_case>" << OriginalName.Value() << 
			"</test_case>" << endl;
                ss << "</structured_message>" << endl;

                ReportDoS(ss);

                ss << "MINESTRONE LOG STOP" << endl <<
                        "Recovery failed!" << endl;
		NOTIFY(ss);

                PIN_ExitProcess(1);
        }
#endif

        if (!pExceptInfo)
                goto noinfo;

        code = PIN_GetExceptionCode(pExceptInfo);
        if (PIN_GetExceptionClass(code) != EXCEPTCLASS_ACCESS_FAULT) {
                goto noinfo;
        }

        if (!PIN_GetFaultyAccessAddress(pExceptInfo, &fault_addr)) {
                goto noinfo;
        }

	// Report null pointer dereference
        if (fault_addr == 0) {
                ss << "<structured_message>" << endl;
                ss << "\t<message_type>found_cwe</message_type>" << endl;
		AppendTestCase(ss);
                // CWE-476 NULL Pointer Dereference
                ss << "\t<cwe_entry_id>476</cwe_entry_id>" << endl;
                ss << "</structured_message>" << endl;
        }

noinfo:
	// Report technical_impact
        ss << "<structured_message>" << endl;
        ss << "\t<message_type>technical_impact" << "</message_type>" << endl;
        ss << "\t<impact>" << "DOS_INSTABILITY" << "</impact>" << endl;
	AppendTestCase(ss);
        ss << "\t<test_case>" << OriginalName.Value() << "</test_case>" << endl;
        ss << "</structured_message>" << endl;
	notify(ss);
}

void LogExecuteStatus(exis_status_t status, INT32 code)
{
	stringstream ss;

	// Execute status
	ss << "<return_status_message>" << endl;
	ss << "\t<message_type>execute_status" << "</message_type>" << endl;
	AppendTestCase(ss);
	switch (status) {
	case ES_SUCCESS:
		ss << "\t<status>success</status>" << endl;
		ss << "\t<status_code>" << code << "</status_code>" << endl;
		break;

	case ES_TIMEOUT:
		ss << "\t<status>timeout</status>" << endl;
		break;

	case ES_SKIP:
		ss << "\t<status>skip</status>" << endl;
		break;

	}
	ss << "</return_status_message>" << endl;
	notify(ss);
}

static BOOL GenericFaultHandler(THREADID tid, INT32 sig, CONTEXT *ctx, 
		BOOL hasHandler, const EXCEPTION_INFO *pExceptInfo, 
		BOOL internal, reassure_ehandling_result_t res)
{
	BOOL handled;

	switch (res) {
	case RHR_HANDLED:
		handled = TRUE;
		break;
	
	case RHR_RESCUED:
		MinestroneNotify(tid, pExceptInfo);
		if (internal)
			PIN_ExecuteAt(ctx);
		handled = TRUE;
		break;

	case RHR_ERROR:
	default:
		handled = FALSE;
		if (!internal && hasHandler)
			break;
		INT32 code = sig + SIGEXITCODE_BASE;
		LogExecuteStatus(ES_SUCCESS, code);
		cerr << strsignal(sig) << endl;
		PIN_ExitProcess(code);
	}

	return handled;
}

static EXCEPT_HANDLING_RESULT InternalFaultHandler(THREADID tid, 
		EXCEPTION_INFO *pExceptInfo, PHYSICAL_CONTEXT *pctx, VOID *v)
{
	CONTEXT ctx;
	reassure_ehandling_result_t res;

	res = reassure_handle_internal_fault(tid, pExceptInfo, pctx, &ctx);
	if (GenericFaultHandler(tid, SIGSEGV, &ctx, FALSE, 
				pExceptInfo, TRUE, res))
		return EHR_HANDLED;
	return EHR_UNHANDLED;
}

static BOOL FaultHandler(THREADID tid, INT32 sig, CONTEXT *ctx, 
		BOOL hasHandler, const EXCEPTION_INFO *pExceptInfo, VOID *v)
{
	reassure_ehandling_result_t res;

	res = reassure_handle_fault(tid, sig, ctx, hasHandler, pExceptInfo);
	if (GenericFaultHandler(tid, sig, ctx, hasHandler, 
				pExceptInfo, FALSE, res))
		return FALSE; // Handled
	return TRUE; // Not handled, deliver
}

// Linked to ThreadStart and global variable initialization
static VOID Fork(THREADID tid, const CONTEXT *ctx, VOID *v)
{
        // Start watchdog for new process, if necessary
        if (ExecTimeout.Value() > 0) {
                if (!WatchdogStart())
                        PIN_ExitProcess(EXIT_FAILURE);
        }

#ifdef FORK_DEBUG
	{
		stringstream ss;

		ss << "Forked process pid " << PIN_GetPid() << endl;
		DBGLOG(ss);
	}
#endif
}

static VOID SaveCmdLine(int argc, char **argv) 
{ 
        int i; 
        char *argv_copy; 
 
        cmdln.argc = argc; 
        cmdln.argv = (char **)malloc((argc + 1) * sizeof(char **)); 
        assert(cmdln.argv); 
 
        for (i = 0; i < argc; i++) { 
                argv_copy = strdup(argv[i]); 
                assert(argv_copy); 
                //cout << "ARG[" << i << "]=" << argv_copy << endl; 
                cmdln.argv[i] = argv_copy; 
        } 
        cmdln.argv[i] = NULL; 
}

static BOOL ChildExec(CHILD_PROCESS child, VOID *v)
{
        int i;
        CHAR timeout[128];

        if (ExecTimeout.Value() == 0)
                return TRUE;

        for (i = 0; i < cmdln.argc; i++) {
                // Stop looking if we reached the application's arguments
                if (strcmp(cmdln.argv[i], "--") == 0)
                        break;
                // Look for the timeout option
                if (strcmp(cmdln.argv[i], "-"TIMEOUT_OPTION) == 0) {
                        if (++i >= cmdln.argc) {
				stringstream ss;

				ss << "No timeout option found in exec'ed "
					"child's command line" << endl;
				ERRLOG(ss);
                                PIN_ExitProcess(EXIT_FAILURE);
                        }
                        snprintf(timeout, sizeof(timeout), "%llu",
                                        WatchdogRemaining());
                        cmdln.argv[i] = timeout;
                        break;
                }
        }

        CHILD_PROCESS_SetPinCommandLine(child, cmdln.argc, cmdln.argv);
        return TRUE;
}

static VOID Fini(INT32 code, VOID *v)
{
	LogExecuteStatus(ES_SUCCESS, code);
}


int main(int argc, char **argv)
{
	checkp_t ctype;

	// This is needed to access functions by name
	PIN_InitSymbols();

	// Initialize pin
	if (PIN_Init(argc, argv)) {
		Usage();
		return EXIT_FAILURE;
	}

	ctype = (ForkCheckpoint.Value())? FORK_CHECKP : WLOG_CHECKP;

	if (reassure_init(ConfigFile.Value().c_str(),
				RuntimeBlock.Value(), ctype) != 0)
		return EXIT_FAILURE;

	PIN_UnblockSignal(SIGSEGV, TRUE);
	PIN_InterceptSignal(SIGSEGV, FaultHandler, 0);
	PIN_UnblockSignal(SIGILL, TRUE);
	PIN_InterceptSignal(SIGILL, FaultHandler, 0);
	PIN_UnblockSignal(SIGABRT, TRUE);
	PIN_InterceptSignal(SIGABRT, FaultHandler, 0);
	PIN_UnblockSignal(SIGFPE, TRUE);
	PIN_InterceptSignal(SIGFPE, FaultHandler, 0);
	PIN_UnblockSignal(SIGPIPE, TRUE);
	PIN_InterceptSignal(SIGPIPE, FaultHandler, 0);
	PIN_AddInternalExceptionHandler(InternalFaultHandler, 0);

	// If a timeout has been specified, setup and start the watchdog
        if (ExecTimeout.Value() > 0) {
                SaveCmdLine(argc, argv);
                WatchdogInit(ExecTimeout.Value());
		PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, Fork, 0);
                PIN_AddFollowChildProcessFunction(ChildExec, NULL);
                if (!WatchdogStart())
                        return EXIT_FAILURE;
        }
	
	PIN_AddFiniFunction(Fini, 0);

	// Start the program, never returns
	PIN_StartProgram();

	return 0;
}
