#include <map>
#include <iostream>
#include <fstream>
#include <algorithm>
#include "pin.H"

extern "C" {
#include <signal.h>
}

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)
#define gettid()	syscall(SYS_gettid)
#define tkill(p, s)	syscall(SYS_tkill, (p), (s))


// Log file
ofstream log;


// Configuration options
static KNOB<string> LogFile(KNOB_MODE_WRITEONCE, "pintool", "o", 
		"reassure.log", "REASSURE log file.");


class Function {
public:
	unsigned long long calls;
	string *name;

	Function(string *name);
	~Function();
	bool operator() (Function *first, Function *second) { return false; }
	
};

typedef pair<ADDRINT, Function*> mypair;

class Compare {
public:
	bool operator() (const mypair &left, const mypair &right) {
		return left.second->calls > right.second->calls;
	}
};

Function::Function(string *name) {
	this->name = name;
	this->calls = 0;
}

Function::~Function()
{
	delete this->name;
}


static map<ADDRINT, Function *> function_stats;

static VOID Usage(void)
{
	log << "This is the call profiling tool" << endl;
	log << KNOB_BASE::StringKnobSummary() << endl;
}

static VOID PIN_FAST_ANALYSIS_CALL FunctionCalled(Function *func)
{
	//cout << (void *)func << endl;
	func->calls++;
}

static VOID TraceInstrument(TRACE trace, VOID *v)
{
	RTN rtn;	
	ADDRINT addr;
	map<ADDRINT, Function *>::iterator funcit;
	Function *func;
	
	rtn = TRACE_Rtn(trace);
	if (!RTN_Valid(rtn)) {
		log << "[WARNING] Code does not belong to any "
			"routine at " << (void *)TRACE_Address(trace) << endl; 
		return;
	}

	if (TRACE_Address(trace) == RTN_Address(rtn)) {
		RTN_Open(rtn);
		addr = RTN_Address(rtn);
		funcit = function_stats.find(addr);
		if (funcit == function_stats.end()) {
			func = new Function(new string(PIN_UndecorateSymbolName(
				RTN_Name(rtn), UNDECORATION_NAME_ONLY)));
			function_stats.insert(pair<ADDRINT, Function *>
				(addr, func));
#if 0
			log << "New function " << func->name << 
				" at " << (void *)addr << 
				" stored at " << func << endl;
#endif
		} else {
			func = funcit->second;
#if 0
			log << "Existing function " << func->name << " at " << 
				(void *)addr << endl;
#endif
		}
		INS_InsertCall(BBL_InsHead(TRACE_BblHead(trace)), IPOINT_BEFORE,
				AFUNPTR(FunctionCalled), 
				IARG_FAST_ANALYSIS_CALL,
				IARG_PTR, func, IARG_END);
		RTN_Close(rtn);
	}
}

static VOID PrintStats(void)
{
	vector<mypair> myvec(function_stats.begin(),
			function_stats.end());
	fstream fout;
	size_t i;

	fout.open("stats.out", fstream::out);
	fout << "Printing stats" << endl;

	sort(myvec.begin(), myvec.end(), Compare());

	for (i = 0; i < myvec.size(); i++) {
		fout << *myvec[i].second->name << ":" << myvec[i].second->calls << endl;
	}
	fout.close();
}

static  VOID Fini(INT32 code, VOID *v)
{
	PrintStats();
}

static BOOL FaultHandler(THREADID tid, INT32 sig, CONTEXT *ctx, 
		BOOL hasHandler, const EXCEPTION_INFO *pinfo, VOID *v)
{
	PrintStats();
	return TRUE;
}


int main(int argc, char **argv)
{
	// This is needed to access functions by name
	PIN_InitSymbols();

	// Initialize pin
	if (PIN_Init(argc, argv)) {
		Usage();
		PIN_ExitProcess(1);
	}

	log.open(LogFile.Value().c_str());
	if (!log.is_open()) {
		perror("Error opening log file");
		return 1;
	}

	PIN_UnblockSignal(SIGINT, TRUE); 
	PIN_InterceptSignal(SIGINT, FaultHandler, 0);
	PIN_UnblockSignal(SIGQUIT, TRUE); 
	PIN_InterceptSignal(SIGQUIT, FaultHandler, 0);


	TRACE_AddInstrumentFunction(TraceInstrument, 0);
	PIN_AddFiniFunction(Fini, 0);

	// Start the program, never returns
	PIN_StartProgram();

	return 0;
}
