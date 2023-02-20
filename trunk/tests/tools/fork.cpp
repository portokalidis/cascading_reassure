#include <assert.h>
#include "pin.H"
#include <iostream>

static unsigned long long stats_trace = 0;


static VOID Trace(TRACE trace, VOID *v)
{
	stats_trace++;
}

static VOID Fork(THREADID tid, const CONTEXT *ctx, VOID *v)
{
	cout << "Fork callback for " << PIN_GetPid() << ":" << tid << 
		" number of traces instrumented " << stats_trace << endl;
}

static VOID Thread(THREADID tid, CONTEXT *ctx, INT32 flag, VOID *v)
{
	cout << "Thread callback for " << PIN_GetPid() << ":" << tid <<
		" number of traces instrumented " << stats_trace << endl;
}


int main(int argc, char * argv[])
{
    PIN_InitSymbols();

    // Initialize pin
    PIN_Init(argc, argv);

    cout << "Tool just started as " << PIN_GetPid() << 
	    " number of traces instrumented " << stats_trace << endl;

    PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, Fork, 0);
    PIN_AddThreadStartFunction(Thread, 0);

    // Register Instruction to be called to instrument instructions
    TRACE_AddInstrumentFunction(Trace, 0);

    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
