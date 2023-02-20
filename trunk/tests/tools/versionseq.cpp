#include <assert.h>
#include "pin.H"
#include <iostream>

static ADDRINT test1_enter, test2_enter;
const char testname[][10] = { "test1",  "test2" };

VOID Emit(const char *string, ADDRINT ver)
{
	cerr << string << "() v" << (ver + 1) << endl;
}

VOID Trace(TRACE trace, VOID *v)
{
	int version = TRACE_Version(trace);
	ADDRINT addr = TRACE_Address(trace);
	INS ins = BBL_InsHead(TRACE_BblHead(trace));
	int stridx;

	if (addr == test1_enter)
		stridx = 0;
	else if (addr == test2_enter)
		stridx = 1;
	else
		stridx = -1;

	if (stridx < 0)
		return;

	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)Emit, 
			IARG_PTR, testname[stridx],
			IARG_ADDRINT, version, IARG_END);

	if (addr == test1_enter && version == 0) {
		BBL_SetTargetVersion(TRACE_BblHead(trace), 1);
	} else if (addr == test2_enter && version == 1) {
		BBL_SetTargetVersion(TRACE_BblHead(trace), 0);
	}
}

VOID ImageLoad(IMG img, VOID *v)
{
    RTN r = RTN_FindByName(img, "test1");
    if (RTN_Valid(r))
        test1_enter = RTN_Address(r);

    r = RTN_FindByName(img, "test2");
    if (RTN_Valid(r))
        test2_enter = RTN_Address(r);
}

int main(int argc, char * argv[])
{
    PIN_InitSymbols();

    cout << "Run with versionseq_app. Function name and "
	    "version should match" << endl;

    // Initialize pin
    PIN_Init(argc, argv);

    // Register Instruction to be called to instrument instructions
    TRACE_AddInstrumentFunction(Trace, 0);

    IMG_AddInstrumentFunction(ImageLoad, 0);

    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
