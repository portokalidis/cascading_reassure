#include <iostream>
#include <sstream>
#include <fstream>
#include <cassert>

#include "pin.H"

extern "C" {
#include <time.h>
}

static BUFFER_ID bufId;
static ofstream logfile;
static PIN_LOCK filelock;

struct memwrite {
	ADDRINT ea;
	UINT32 size;
};

static VOID Usage(void)
{
	cerr << "This is a test tool." << endl;
	cerr << KNOB_BASE::StringKnobSummary() << endl;
}


static VOID MemWriteHandler(INS ins, VOID *v)
{
	UINT32 memops, i, len;

	memops = INS_MemoryOperandCount(ins);
	for (i = len = 0; i < memops; i++)
		if (INS_MemoryOperandIsWritten(ins, i)) {
			len = INS_MemoryOperandSize(ins, i);
			break;
		}
	assert(len > 0);

	INS_InsertFillBufferPredicated(ins, IPOINT_BEFORE, bufId,
			IARG_MEMORYOP_EA, i, offsetof(struct memwrite, ea),
			IARG_UINT32, len, offsetof(struct memwrite, size),
			IARG_END);
}

static VOID TraceInstrument(TRACE trace, VOID *v)
{
	BBL bbl;
	INS ins;

	for (bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
		for (ins = BBL_InsHead(bbl); INS_Valid(ins); 
				ins = INS_Next(ins)) {
			if (!INS_IsMemoryWrite(ins))
				continue;
			MemWriteHandler(ins, v);
		}
	}
}

static VOID *BufferFull(BUFFER_ID id, THREADID tid, const CONTEXT *ctx, 
		VOID *buf, UINT64 numElements, VOID *v)
{
	time_t tm;

	tm = time(NULL);

	GetLock(&filelock, tid);
	logfile << "FLUSH " << tid << ' ' << numElements << 
		' ' << ctime(&tm) << endl;
	logfile.write((const char *)buf, 
			numElements * sizeof(struct memwrite));
	ReleaseLock(&filelock);

	return buf;
}

static VOID ThreadStart(THREADID tid, CONTEXT *ctx, INT32 flags, VOID *v)
{
	GetLock(&filelock, tid);
	logfile << "NEW " << tid << endl;
	ReleaseLock(&filelock);
}

static VOID ThreadFini(THREADID tid, const CONTEXT *ctx, INT32 code, VOID *v)
{
	GetLock(&filelock, tid);
	logfile << "FINI " << tid << endl;
	ReleaseLock(&filelock);
}

static VOID Fini(INT32 code, VOID *v)
{
	cout << "Exiting" << endl;
	logfile.close();
}


int main(int argc, char **argv)
{
	// This is needed to access functions by name
	PIN_InitSymbols();

	// Initialize pin
	if (PIN_Init(argc, argv)) {
		Usage();
		PIN_ExitApplication(1);
	}

	logfile.open("memwrite.log");
	InitLock(&filelock);

	bufId = PIN_DefineTraceBuffer(sizeof(struct memwrite), 1024, 
			BufferFull, 0);

	TRACE_AddInstrumentFunction(TraceInstrument, 0);

	PIN_AddThreadStartFunction(ThreadStart, 0);
	PIN_AddThreadFiniFunction(ThreadFini, 0);

	PIN_AddFiniFunction(Fini, 0);

	// Start the program, never returns
	PIN_StartProgram();

	return 0;
}
