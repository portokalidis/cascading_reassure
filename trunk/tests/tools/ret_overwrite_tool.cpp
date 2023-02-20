#include <iostream>

#include "pin.H"

extern "C" {
#include <stdlib.h>
}


//IARG_FUNCRET_EXITPOINT_REFERENCE 


static VOID MakeEvil(ADDRINT *retp)
{
	*retp = 666;
}

static VOID NoGood(CONTEXT *ctx, ADDRINT ret_addr)
{
	PIN_SetContextReg(ctx, REG_INST_PTR, ret_addr);
	PIN_ExecuteAt(ctx);
}

static VOID Usage(void)
{
	cerr << "This is a test tool." << endl;
	cerr << KNOB_BASE::StringKnobSummary() << endl;
}


static inline ADDRINT InstrumentFunction(RTN rtn)
{
        INS ins;

        // For this to work accurately i also need to block signals and 
        // system calls
        for (ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
                if (INS_IsRet(ins))
			return INS_Address(ins);
	}
	return 0;
}

static VOID InstrumentFunctions(RTN rtn, VOID *v)
{
	const string *rname;
	ADDRINT ret_addr;
	
	RTN_Open(rtn);
	rname = new string(RTN_Name(rtn));

	ret_addr = InstrumentFunction(rtn);

	if (rname->find("good_function") != string::npos) {
		cout << "Found good_function()" << endl;
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)NoGood,
				IARG_CONTEXT,
				IARG_ADDRINT, ret_addr,
				IARG_END);
		RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MakeEvil,
				IARG_FUNCRET_EXITPOINT_REFERENCE, IARG_END);
	}

	delete rname;
	RTN_Close(rtn);
}


int main(int argc, char **argv)
{
	// This is needed to access functions by name
	PIN_InitSymbols();

	// Initialize pin
	if (PIN_Init(argc, argv)) {
		Usage();
		exit(1);
	}

	RTN_AddInstrumentFunction(InstrumentFunctions, 0);

	// Start the program, never returns
	PIN_StartProgram();

	return 0;
}
