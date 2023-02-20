#include <assert.h>
#include "pin.H"
#include <iostream>

static ADDRINT step3_enter;

VOID Emit(char *string)
{
	cerr << string << endl;
}

VOID Trace(TRACE trace, VOID *v)
{
	int version = TRACE_Version(trace);

	//cout << "Trace version " << version << endl;

	if (TRACE_Address(trace) == step3_enter) {
		if (version == 0) {
			cerr << "Instrumenting step3()" << endl;
			BBL_SetTargetVersion(TRACE_BblHead(trace), 1);
			BBL_InsertCall(TRACE_BblHead(trace), IPOINT_BEFORE, 
					AFUNPTR(Emit), 
					IARG_PTR, "Enter 3!", IARG_END);
		} else {
			cerr << "Do something for version " << 
				version << endl;
			for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); 
					bbl = BBL_Next(bbl)) {
				INS tail = BBL_InsTail(bbl); 
				if (INS_Valid(tail) && INS_IsRet(tail)) {
					BBL_SetTargetVersion(bbl, 0);
				}
			}
		}
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
