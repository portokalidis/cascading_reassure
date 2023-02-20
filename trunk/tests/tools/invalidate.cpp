#include <assert.h>
#include "pin.H"
#include <iostream>

static ADDRINT step3_enter;
static int count = 0;

static VOID Emit1(void)
{
	UINT32 removed;

	cerr << "Step3 1!" << endl;
	GetVmLock();
	removed = CODECACHE_InvalidateTraceAtProgramAddress(step3_enter);
	cerr << "Removed traces " << removed << endl;
	ReleaseVmLock();
}

static VOID Emit2(void)
{
	cerr << "Step3 2!" << endl;
}

VOID Trace(TRACE trace, VOID *v)
{
	if (TRACE_Address(trace) == step3_enter) {
		cerr << "Instrumenting count " << ++count << endl;

		if (count == 1)
			BBL_InsertCall(TRACE_BblHead(trace), IPOINT_BEFORE, 
					AFUNPTR(Emit1), IARG_END);
		else if (count == 2)
			BBL_InsertCall(TRACE_BblHead(trace), IPOINT_BEFORE, 
					AFUNPTR(Emit2), IARG_END);
	}
}

VOID ImageLoad(IMG img, VOID *v)
{
    RTN r = RTN_FindByName(img, "step3");
    if (RTN_Valid(r))
        step3_enter = RTN_Address(r);
}

int main(int argc, char * argv[])
{
    PIN_InitSymbols();

    // Initialize pin
    PIN_Init(argc, argv);

    // Register Instruction to be called to instrument instructions
    TRACE_AddInstrumentFunction(Trace, 0);

    IMG_AddInstrumentFunction(ImageLoad, 0);

    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
