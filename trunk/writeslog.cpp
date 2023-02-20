#include <iostream>
#include <cassert>
#include <sstream>

extern "C" {
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
}

#include "pin.H"
#include "libreassure.hpp"
//#include "syscall.h"
#include "writeslog.h"
#include "log.hpp"


void WLogFree(struct writeslog *wlog)
{
	wlog_seg_t *s, *prev;
#ifdef WLOG_DEBUG
	unsigned int segs = 0;
#endif

	for (s = wlog->segs; s != NULL; s = prev) {
		prev = s->prev;
		free(s);
#ifdef WLOG_DEBUG
		segs++;
#endif
	}

	free(wlog->cache);
	free(wlog);

#ifdef WLOG_DEBUG
	stringstream ss;
	ss << "Freeing writes log of " << segs << " segments" << endl;
	DBGLOG(ss);
#endif
}

struct writeslog *WLogAlloc(UINT32 hint)
{
	UINT32 len;
	struct writeslog *wlog;

	wlog = (struct writeslog *)calloc(1, sizeof(struct writeslog));
	assert(wlog);

	// Apply hint for size if not zero
	len = (hint > 0)? hint : WLOG_BLOCK_SIZE_MIN;
	wlog->block = wlog->size = len;

	// Allocate a segment
	WLogSegAlloc(wlog, len);

	// Allocate cache
	wlog->cache = (cache_entry_t *)calloc(CACHE_BUCKETS, 
			sizeof(cache_entry_t));
	assert(wlog->cache);
	//memset(wlog->cache, 0, CACHE_BUCKETS * sizeof(cache_entry_t));

#ifdef WLOG_DEBUG
	stringstream ss;
	ss << "Allocating writes log of size " << wlog->size << " at " <<
		(void *)wlog << endl;
	DBGLOG(ss);
#endif

	return wlog;
}

static inline void WLogSegRollback(wlog_entry_t *idx, wlog_entry_t *start)
{
	wlog_entry_t *entry;
	stringstream ss;
#ifdef SAFECOPY_RESTORE
	VOID *srcptr;
#endif

	// We reverse the logged write operations
	for (; idx > start; idx--) {
		entry = idx - 1;

		switch (entry->len) {
#ifdef SAFECOPY_RESTORE
			case 1:
				srcptr = &entry->data.byte;
				WLogDebugDataRollback(entry->addr, 1,
						entry->data.byte);
				break;
			case 2:
				srcptr = &entry->data.word;
				WLogDebugDataRollback(entry->addr, 2,
						entry->data.word);
				break;
			case 4:
				srcptr = &entry->data.dword;
				WLogDebugDataRollback(entry->addr, 4,
						entry->data.dword);
				break;
			case 8:
				srcptr = &entry->data.qword;
				WLogDebugDataRollback(entry->addr, 8,
						entry->data.qword);
				break;
			case 16:
				srcptr = entry->data.dqword;
				break;
			case 32:
				srcptr = entry->data.qqword;
				break;
#else
			case 1:
				*(UINT8 *)entry->addr = entry->data.byte;
				break;
			case 2:
				*(UINT16 *)entry->addr = entry->data.word;
				break;
			case 4:
				*(UINT32 *)entry->addr = entry->data.dword;
				break;
			case 8:
				*(UINT64 *)entry->addr = entry->data.qword;
				break;
			case 16:
				memcpy((void *)entry->addr, 
						entry->data.dqword, 16);
				break;
			case 32:
				memcpy((void *)entry->addr, 
						entry->data.qqword, 32);
				break;
#endif
#if 0
			case SYSCALL_ENTRY:
				SyscallRollback(entry);
			break;
#endif
			default:
				ss << "Illegal writes log entry length " <<
					entry->len << endl;
				ERRLOG(ss);
				return;
		} // switch (entry->len)
#ifdef SAFECOPY_RESTORE
		if (PIN_SafeCopy((VOID *)entry->addr, srcptr, 
					entry->len) != entry->len) {
			ss << "WARNING: " << entry->len << " bytes(s) at " <<
				(void *)entry->addr << 
				" could not be restored" << endl;
			OUTLOG(ss);
		}
#endif
	} // for ()
}

void WLogRollback(struct writeslog *wlog)
{
	wlog_seg_t *s;

#ifdef WLOG_DEBUG
	DBGLOG("Rolling back writes log\n");
#endif

	s = wlog->segs;
	WLogSegRollback(wlog->idx, s->start);
	s = s->prev;

	for (; s != NULL; s = s->prev)
		WLogSegRollback(s->end, s->start);
}

