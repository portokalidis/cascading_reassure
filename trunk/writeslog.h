#ifndef WRITESLOG_HPP
#define WRITESLOG_HPP

extern "C" {
#include <sys/user.h>
#include <string.h>
}

#include "cache.h"
#include "log.hpp"
#include "debug.h"

// Magic number that can by assigned to wlog_entry_t->len to store a pointer
// to a reversible system call
#define SYSCALL_ENTRY 128

// We start increasing the writes log by this number of entries 
#define WLOG_BLOCK_SIZE_MIN	10000
// This is the maximum block we increase the writes log by
#define WLOG_BLOCK_SIZE_MAX	1000000

// Writes log entry structure
typedef struct wlog_entry_struct {
	ADDRINT len;
	ADDRINT addr;
	union {
		UINT8 byte;
		UINT16 word;
		UINT32 dword;
		UINT64 qword;
		UINT8 dqword[16];
		UINT8 qqword[32];
		unsigned int sstack_idx;
	} data;
} __attribute((__packed__)) wlog_entry_t;

// Writes log segment
typedef struct wlog_seg_struct {
	struct wlog_seg_struct *prev;
	wlog_entry_t *end;
	wlog_entry_t start[1];
} __attribute((__packed__)) wlog_seg_t;

/**
 * Writes log structure.
 */
struct writeslog {
	/** * Associative cache.
	 * Moving this to a different location can apparently reduce performace.
	 */
	//cache_entry_t cache[CACHE_BUCKETS];
	cache_entry_t *cache;
	wlog_entry_t *idx, *end;
	wlog_seg_t *segs;
	UINT32 block, size;
};


struct writeslog *WLogAlloc(UINT32 hint);

void WLogFree(struct writeslog *log);

void WLogRollback(struct writeslog *wlog);


static inline UINT32 WLogSize(const struct writeslog *wlog)
{
	return wlog->size;
}

static inline bool WLogIsFull(const struct writeslog *wlog)
{
	return (wlog->idx >= wlog->end);
}

static inline void WLogSegAlloc(struct writeslog *wlog, UINT32 sz)
{
	stringstream ss;
	wlog_seg_t *seg;

#ifdef WLOG_DEBUG
	ss << "Allocating new writes log segment of size " << sz << endl;
	DBGLOG(ss);
#endif

	seg = (wlog_seg_t *)malloc(sizeof(wlog_seg_t) + 
			(sz - 1) * sizeof(wlog_entry_t));
	assert(seg);

	seg->prev = wlog->segs;
	seg->end = seg->start + sz;

	wlog->segs = seg;
	wlog->idx = seg->start;
	wlog->end = seg->start + sz;

#ifdef WLOG_DEBUG
	ss << "Segment at " << (void *)seg->start << " to " << 
		(void *)wlog->end <<  endl;
	DBGLOG(ss);
#endif
}

static inline void WLogExtend(struct writeslog *wlog)
{	
	// Increase the block size for the next expansion
	if (wlog->block < WLOG_BLOCK_SIZE_MAX)
		wlog->block *= 2;

	WLogSegAlloc(wlog, wlog->block);
	wlog->size += wlog->block;
}

#ifdef WLOG_DEBUG_EXTENDED
# define WLogDebugDataInner(addr, len, val, str) \
	do {\
		stringstream ss;\
		ss << "Log " << (str) << " addr:" << (void *)(addr) << \
		" len:" << (len) << " data:" << (void *)(val) << endl;\
		DBGLOG(ss);\
	} while (0)
# define WLogDebugDataRollback(addr, len, val) \
	WLogDebugDataInner(addr, len, val, "rollback")

# define WLOG_DEBUG_DATA(addr, len, val) \
	WLogDebugDataInner(addr, len, val, "store")
#else
# define WLogDebugData(addr, len, val) do { } while (0)
# define WLogDebugDataRollback(addr, len, val) do { } while (0)

# define WLOG_DEBUG_DATA(addr, len, val) do { } while (0)
#endif


/**
 * Macro for common operations when logging an overwritten memory location
 */
#define WLOGWRITE_COMMON(ent, wlog, length, address) \
do {\
	(ent) = (wlog)->idx++;\
	(ent)->len = (length);\
	(ent)->addr = (address);\
} while (0)


/**
 * Generic macro for logging an overwritten memory location
 */
#define WLOG_WRITE(wlog, addr, val, len, umember)\
	do {\
		wlog_entry_t *ent;\
		WLOGWRITE_COMMON(ent, wlog, len, addr);\
		ent->data.umember = val;\
		WLOG_DEBUG_DATA(addr, 4, val);\
	} while (0)


/**
 * Generic macro for logging an overwritten memory location using memcpy()
 * instead of direct assignment. For writes larger than 64-bits.
 */
#define WLOG_WRITE_COPY(wlog, addr, len, umember)\
	do {\
		wlog_entry_t *ent;\
		WLOGWRITE_COMMON(ent, wlog, len, addr);\
		memcpy(ent->data.umember, (void *)addr, len);\
	} while (0)


#if 0

static inline void WLogWriteSyscall(struct writeslog *wlog, unsigned int idx)
{
	wlog_entry_t *ent;

	// Check that we have space in the WLog
	if (WLogFull(wlog))
		WLogExtend(wlog);

	ent = wlog->wlog_idx;
	ent->len = SYSCALL_ENTRY; // Use this magic value to indicate a syscall
	ent->data.sstack_idx = idx;
	wlog->wlog_idx++;
}
#endif
#endif
