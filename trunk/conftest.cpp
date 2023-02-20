#include <iostream>
#include <map>
#include <cassert>
#include <fstream>

#include "pin.H"

extern "C" {
#include <string.h>
#include <errno.h>
#include <stdlib.h>
}

#include "RescuePoint.hpp"
#include "utils.hpp"

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)


// Log file
ostream *log;

// Hash map of rescue points
static map<string, RescuePoint *> rescue_points_byname;
static map<ADDRINT, RescuePoint *> rescue_points_byaddr;

// Configuration options
static KNOB<string> ConfigFile(KNOB_MODE_WRITEONCE, "pintool", "c", 
		"reassure.conf", "REASSURE configuration file.");
static KNOB<string> LogFile(KNOB_MODE_WRITEONCE, "pintool", "o", 
		"reassure.log", "REASSURE log file.");


//////////////////
// Helper
//////////////////

static VOID Usage(void)
{
	cout << "This is the RE-ASSURE tool, implementing Rescue Points for"
		" binaries" << endl;
	cout << KNOB_BASE::StringKnobSummary() << endl;
}

static VOID TraceInstrument(TRACE trace, VOID *v)
{
	*log << "Tracing begins, i'm exiting" << endl;
	PIN_ExitProcess(0);
}

static VOID RoutineInstrument(RTN rtn, VOID *v)
{
	string rname, dname;
	ADDRINT addr;
	map<string, RescuePoint *>::iterator rp_it;
	map<ADDRINT, RescuePoint *>::iterator rp_it2;

	// Check if a rescue point exists for the routine using its address
	addr = RTN_Address(rtn);
	rp_it2 = rescue_points_byaddr.find(addr);
	if (rp_it2 != rescue_points_byaddr.end()) {
		*log << "Rescue point found at " << (void *)addr << endl;
		return;
	}

	// Then check by demangled name
	RTN_Open(rtn);
	rname = RTN_Name(rtn);
	dname = PIN_UndecorateSymbolName(rname, UNDECORATION_NAME_ONLY);

	rp_it = rescue_points_byname.find(dname);
	if (rp_it != rescue_points_byname.end())
		*log << "Rescue point " << dname << " found at " << 
			(void *)addr << endl;
	RTN_Close(rtn);
}


int main(int argc, char **argv)
{
	const char *logfn;

	// This is needed to access functions by name
	PIN_InitSymbols();

	// Initialize pin
	if (PIN_Init(argc, argv)) {
		Usage();
		PIN_ExitProcess(1);
	}

	if (LogFile.Value().compare(0) == 0)
		logfn = NULL;
	// Do this first so everybody else can log properly
	if (!(log = SetupLogging(logfn))) {
		perror("Could not setup logging");
		return -1;
	}

	if (ParseConf(ConfigFile.Value().c_str(), rescue_points_byname,
				rescue_points_byaddr) != 0)
		return 1;

	TRACE_AddInstrumentFunction(TraceInstrument, 0);
	RTN_AddInstrumentFunction(RoutineInstrument, 0);

	// Start the program, never returns
	PIN_StartProgram();

	return 0;
}
