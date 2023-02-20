#include <iostream>
#include <cassert>
#include <sstream>

extern "C" {
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
}

#include "pin.H"
#include "libreassure.hpp"
#include "cache.h"
#include "filter.hpp"
#include "shared_cbuf.h"
#include "log.hpp"
#include "debug.h"



/********************************/
/*       BITMAP FILTER          */
/********************************/
#if FILTER_TYPE == FILTER_BITMAP

/**
 * Structure used for communicating memory contects between the forked
 * checkpoint process and the real process.
 */
struct memval {
	ADDRINT addr;	//!< Memory address
	UINT32 val;	//!< Memory contents
} __attribute__ ((__packed__));



/**
 * Copy the the original values of memory contained in the forked process, over 
 * the pipe, for a bucket of the bitmap (currrently 4 bytes).
 *
 * @param addr Memory address
 * @param pipe Pipe descriptor
 */
static inline void rollback_bucket(ADDRINT addr, int pipe)
{
	int r;
	struct memval entry;

	//cerr << "Reinstate bucket " << (void *)addr << endl;

	// Addresses should always be aligned by design, so this should always
	// succeed or fail entirely
	r = PIN_SafeCopy(&entry.val, (VOID *)addr, BITMAP_BUCKET_LEN);
	if (r != BITMAP_BUCKET_LEN)
		return;
	entry.addr = addr;

	// Write data to pipe
	r = write(pipe, &entry, sizeof(entry));
	if (r < (int)sizeof(entry))
		cerr << "checkpoint process error writing to pipe" << endl;
}

/**
 * Check a byte in the bitmap for buckets of the memory that need to be rolled
 * back (currently 1 byte in the bitmap represents 32 bytes).
 *
 * @param bitmap Pointer to bitmap
 * @param idx Pointer to the byte of the bitmap that we are currently processing
 * @param pipe Pipe descriptor
 */
static inline void rollback_byte(unsigned char *bitmap, 
		unsigned char *idx, int pipe)
{
	UINT8 mask;
	ADDRINT bucket, bucket_idx, addr;

	for (mask = 0x1, bucket_idx = 0; mask; mask <<= 1, bucket_idx++) {
		if (*idx & mask) {
			// Calculate number of bucket
			bucket = ((idx - bitmap) << 3) + bucket_idx;
			// Calculate address
			addr = bucket << BITMAP_BUCKET_SHIFT;
			rollback_bucket(addr, pipe);
		}
	}
}

/** Rollback the contents of memory marked in the filter, by sending the
 * original contents of memory in the forked process to the real process over a
 * pipe.
 *
 * @param fp Pointer to filter
 * @param pipe Pipe descriptor
 */
void filter_child_rollback(filter_t *fp, int pipe)
{
	unsigned char *fstart, *fend;
	ADDRINT i;

	for (fstart = fp->bitmap, fend = fp->bitmap + BITMAP_ADDRESSABLE; 
			fstart < fend; fstart += 4) {
		// Check 4 filter bytes quickly
		if (*(UINT32 *)fstart) {
			// Check individual filter bytes
			for (i = 0; i < 4; i++) {
				if (*(fstart + i))
					rollback_byte(fp->bitmap, 
							fstart + i, pipe);
			} // for (i = 0; i < 4 ...
		} // *(UINT32 *)fstart != 0 check 4 bytes of filter
	} // for (fstart ... ) iterate over filter
}

/** Rollback the contents of memory in the real process, based on the data
 * received by the checkpointing process over a pipe.
 *
 * @param pipe Pipe descriptor
 * @return true on success. false otherwise.
 */
bool filter_parent_rollback(int pipe)
{
	struct memval entry;
	stringstream ss;
	int r;

	// Receive original memory values from child
	while ((r = read(pipe, &entry, sizeof(entry))) == sizeof(entry)) {
#ifdef SAFECOPY_RESTORE
		if ((r = PIN_SafeCopy((VOID *)entry.addr, &entry.val, 
				BITMAP_BUCKET_LEN)) != BITMAP_BUCKET_LEN) {
			// Failed to restore data
			ss << "WARNING: 4 bytes(s) at " << (void *)entry.addr <<
				" could not be restored" << endl;
			OUTLOG(ss);
		}
#else
		*(UINT32 *)entry.addr = entry.val;
#endif
	}

	if (r < 0) { // Error reading from pipe
		ss << "checkpoint fork rollback error receiving from pipe: ";
		ss << strerror(errno) << endl;
		ERRLOG(ss);
		return false;
	}
	return true;
}

/**
 * Bitmap does not require initialization
 *
 * @param fl Pointer to filter
 */
void filter_init(filter_t *fl)
{
}

/**
 * Bitmap does not require cleanup
 *
 * @param fl Pointer to filter
 */

void filter_cleanup(filter_t *fl)
{
}


/**
 * Bitmap does not require any special handling for internal faults.
 *
 * @param fl Pointer to filter
 * @param pExceptInfo Pointer to Pin exception information
 * @return Always return false
 */
bool filter_handle_internal_fault(filter_t *fl, 
		const EXCEPTION_INFO *pExceptInfo)
{
	return false;
}

/**
 * Mark len bytes starting from address addr in the filter.
 *
 * @param filter Pointer to filter
 * @param addr Address to start marking
 * @param len Number of bytes to mark
 */
void filter_mark(filter_t *filter, ADDRINT addr, size_t len)
{
	ADDRINT start, boff;

	// Calculate initial bucket corresponding to address
	start = addr >> BITMAP_BUCKET_SHIFT;
	// If the address is not aligned, we need to check an extra bucket
	if (addr & 0x3)
		++len;

	// Unaligned start bucket, mark individual bits
	boff = start >> 3;
	while (start & 0x3) {
		filter->bitmap[boff] |= 0x1 << (start++ & 0x7); 
		len -= BITMAP_BUCKET_LEN;
	}

	// Start has been aligned, attempt to mark 1 byte in the filter
	// 32 memory bytes
	boff = start >> 3;
	while (len >= 32) {
		filter->bitmap[boff++] = 0xff;
		len -= (BITMAP_BUCKET_LEN * 8);
		start += BITMAP_BUCKET_LEN;
	}

	// Mark remainder, 1 bit at a time
	// This also ensures we overflow to the next bucket 
	// if bytes < BITMAP_BUCKET_LEN need to be marked
	while (len > 0) {
		filter->bitmap[start >> 3] |= 0x1 << (start & 0x7); 
		start++;
		len -= BITMAP_BUCKET_LEN;
	}
}


#elif FILTER_TYPE == FILTER_WLOG

/**
 * Initialize the filter by mapping a circular buffer and
 * memory protecting a guard page to detect when the buffer is full.
 * Also allocates a cache.
 *
 * @param fl Pointer to filter
 */
void filter_init(filter_t *fl)
{
	ADDRINT guard;
	stringstream ss;

	// Allocate circular buffer
	fl->cbuf = (unsigned char *)mmap(NULL, WLOGFILTER_LEN, 
			PROT_READ|PROT_WRITE, 
			MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	assert(fl->cbuf != MAP_FAILED);

	// Calculate address of guard page
	guard = (ADDRINT)fl->cbuf + (WLOGFILTER_LEN - WLOGFILTER_PAGE_SIZE);
	assert((guard & (WLOGFILTER_PAGE_SIZE - 1)) == 0);
	assert(mprotect((void *)guard, WLOGFILTER_PAGE_SIZE, PROT_READ) == 0);
	fl->guard = (unsigned char *)guard;

	// Initialize index
	fl->idx = 0;

	// Initialize element counter
	//fl->cbuf_elemno = 0;

	// Initialize cache
	fl->cache = (cache_entry_t *)calloc(CACHE_BUCKETS, 
			sizeof(cache_entry_t));
	assert(fl->cache);

	// Initialize shared buffer
	//shared_cbuf_init(&fl->databuf, WLOGFILTER_DATABUF_SIZE);

	// Initialize fd to -1
	fl->fd = -1;
}

/**
 * Cleanup the filter by unmapping the circular buffer and freeing the cache.
 *
 * @param fl Pointer to filter
 */
void filter_cleanup(filter_t *fl)
{
	munmap(fl->cbuf, WLOGFILTER_LEN);
	free(fl->cache);
	//shared_cbuf_cleanup(&fl->databuf);
	if (fl->fd) {
		close(fl->fd);
		unlink(fl->tmpfn);
		fl->fd = -1;
	}
}

/**
 * Open a temporary file to store the writes log.
 *
 * @param fl Pointer to filter
 * @return True on success, and false on error
 */
static inline bool open_temp_file(filter_t *fl)
{
	strcpy(fl->tmpfn, WLOGFILTER_FN_TEMPLATE);
	fl->fd = mkstemp(fl->tmpfn);
	return (fl->fd >= 0);
}

/**
 * Write an buffer to the temporary file. On error it closes and deletes the
 * temporary file.
 *
 * @param fl Pointer to filter
 * @param buf Pointer to buffer
 * @param len Number of bytes to write
 * @return true on success, or false on error
 */
static bool write_to_file(filter_t *fl, void *buf, size_t len)
{
	int r;

	r = write(fl->fd, buf, len);
	if (r < 0) {
err:
		stringstream ss;
		ss << "cannot write to disk: " << strerror(errno) << endl;
		ERRLOG(ss);
		close(fl->fd);
		unlink(fl->tmpfn);
		fl->fd = -1;
		return false;
	} else if ((size_t)r != len)
		goto err;
	return true;
}

/**
 * Flush the circular buffer to a file.
 *
 * @param fl Pointer to filter
 * @return true on success, or false on error
 */
static bool flush_cbuf(filter_t *fl)
{
	unsigned char *idx, *guard_end, *cbuf_end;
	size_t len;
#ifdef FLOG_DEBUG
	stringstream ss;

	DBGLOG("Fault in wlogfilter guard page\n");
#endif

	// Check if a file has been already opened or open a new one
	if (fl->fd < 0)
		if (!open_temp_file(fl))
			return false;

	// Get pointers
	idx = (unsigned char *)WLOGFILTER_ENTRY(fl);
	guard_end = fl->guard + WLOGFILTER_PAGE_SIZE;
	cbuf_end = fl->cbuf + WLOGFILTER_LEN;


	// We need to flush from the end of the guard to idx
	// cbuf *** idx  guard ***
	assert(idx == fl->guard);

#ifdef FLOG_DEBUG
	ss << "flushing cbuf: " << (void *)fl->cbuf << 
		" *** idx: " << (void *)idx << 
		" --- guard:" << (void *)fl->guard << " ***" << endl;
	DBGLOG(ss);
#endif

	// Write guard - cbuf_end
	if (guard_end < cbuf_end) {
		len = cbuf_end - guard_end;
		if (!write_to_file(fl, guard_end, len))
			return false;
#ifdef FLOG_DEBUG
		DBGLOG("writing guard -- cbuf_end\n");
#endif
	}

	// Write cbuf - idx
	if (idx > fl->cbuf) {
		len = idx - fl->cbuf;
		if (!write_to_file(fl, fl->cbuf, len))
			return false;
#ifdef FLOG_DEBUG
		DBGLOG("writing cbuf -- idx\n");
#endif
	}

	// Unprotect guard page
	assert(mprotect(fl->guard, WLOGFILTER_PAGE_SIZE, 
				PROT_READ|PROT_WRITE) == 0);
	// Calculate new guard page address and protect it
	fl->guard = ((idx > fl->cbuf)? idx : cbuf_end) - WLOGFILTER_PAGE_SIZE;
#ifdef FLOG_DEBUG
	ss << "New guard page " << (void *)fl->guard << endl;
	DBGLOG(ss);
#endif
	assert(mprotect(fl->guard, WLOGFILTER_PAGE_SIZE, PROT_READ) == 0);
	
	return true;
}

/**
 * Check and attempt to handle an internal fault, if it is due to the circular
 * buffer being full.
 *
 * @param fl Pointer to filter
 * @param pExceptInfo Pointer to Pin exception information
 * @return true if the fault has successfully handled, false otherwise
 */
bool filter_handle_internal_fault(filter_t *fl, 
		const EXCEPTION_INFO *pExceptInfo)
{
	EXCEPTION_CODE code;
	ADDRINT guard, faddr;

	// Check the class of the exception
	code = PIN_GetExceptionCode(pExceptInfo);
	if (PIN_GetExceptionClass(code) != EXCEPTCLASS_ACCESS_FAULT)
		return false;

	// Retrieve faulty address
	if (!PIN_GetFaultyAccessAddress(pExceptInfo, &faddr))
		return false;

	// Check that it is in the guard page
	guard = (ADDRINT)fl->guard;
	if (faddr >= guard && faddr < (guard + 4096))
		return flush_cbuf(fl);

	return false;
}

/**
 * Send original memory contents to parent through a pipe.
 *
 * @param pipe Pipe descriptor
 * @param addr Address to be sent
 * @param len Number of bytes to send
 * @return true on success, or false on pipe error
 */
static inline bool send_contents_to_pipe(int pipe, ADDRINT addr, UINT32 len)
{
	unsigned char data[32];
	stringstream ss;
	struct wlogfilter_entry send_entry;
	size_t l;
	int r;
	bool ret;
	void *p;

	ret = true;

	// We may need to allocate a temp. buffer for long writes
	if (len <= 32)
		p = data;
	else {
		// Allocate temporary buffer
		p = malloc(len);
		assert(p);
	}

	// copy data
	l = PIN_SafeCopy(p, (VOID *)addr, len);

	// Write data to pipe
	if (l > 0) { 
		// XXX: Use writev
		send_entry.len = l;
		send_entry.addr = addr;
		r = write(pipe, &send_entry, sizeof(struct wlogfilter_entry));
		if (r < (int)sizeof(struct wlogfilter_entry))
			goto err;

		r = write(pipe, p, l);
		if (r < 0) {
	err:
			ss << "checkpoint process error writing to pipe: " << 
				strerror(errno) << endl;
			ERRLOG(ss);
			ret = false;
		} else if ((size_t)r < l)
			goto err;
	}

	// Free temp. buffer
	if (len > 32) 
		free(p);

	return ret;
}

static inline bool send_contents(filter_t *fp, int pipe, 
		ADDRINT addr, UINT32 len)
{
#if 0
	struct ring *r;


	// If the data cannot fit in the ring buffer send it over the pipe
	if (len > RING_BUFFER_SIZE) {
		//ret = send_contents_to_pipe(pipe, addr, len);
		//return ret;
	} else {
		//ret = ring_write_contents(fp->shared_ring, addr, len);
	}
#endif
	return send_contents_to_pipe(pipe, addr, len);
}

/**
 * Rollback memory defined by the entries in the supplied filter area.
 *
 * @param pipe Pipe descriptor
 * @param buf Pointer to an area in filter
 * @param len Number of bytes in the filter to rollback
 * @return true on success, or false on pipe error
 */
static bool rollback_buffer(filter_t *fp, int pipe, 
		unsigned char *ptr, size_t len)
{
	struct wlogfilter_entry *start, *end;

	start = (struct wlogfilter_entry *)ptr;
	end = (struct wlogfilter_entry *)(ptr + len);

#ifdef FLOG_DEBUG
	stringstream ss;
	ss << "rollback " << (void *)ptr << " to " << 
		(void *)(ptr + len) << endl;
	DBGLOG(ss);
#endif

	while (start < end) {
		if (!send_contents(fp, pipe, start->addr, start->len))
			return false;
		start++;
	}
	return true;
}

/**
 * Read entries previously flushed to the temporary file, and send their
 * original memory contents to the parent process over a pipe.
 *
 * @param fp Pointer to filter
 * @param pipe Pipe descriptor
 */
static inline void child_rollback_file(filter_t *fp, int pipe)
{
	int fd, r;

	// We need to open the file because it is only open in the parent
	if ((fd = open(fp->tmpfn, O_RDONLY)) < 0)
		goto err;

	// Read into the cbuf
	while ((r = read(fd, fp->cbuf, WLOGFILTER_LEN)) > 0) {
		if (!rollback_buffer(fp, pipe, fp->cbuf, r))
			break;
	}

	if (r < 0) {
err:
		stringstream ss;
		ss << "error reading wlog data from file: " << 
			strerror(errno) << endl;
		ERRLOG(ss);
	}

	close(fd);
}

/** Rollback the contents of memory marked in the filter, by sending the
 * original contents of memory in the forked process to the real process over a
 * pipe.
 *
 * @param fp Pointer to filter
 * @param pipe Pipe descriptor
 */
void filter_child_rollback(filter_t *fp, int pipe)
{
	unsigned char *idx, *guard_end, *cbuf_end;
	size_t len;
#ifdef FLOG_DEBUG
	stringstream ss;

	DBGLOG("Child process rolling back\n");
#endif

	// Get pointers
	idx = (unsigned char *)WLOGFILTER_ENTRY(fp);
	guard_end  = fp->guard + WLOGFILTER_PAGE_SIZE;
	cbuf_end = fp->cbuf + WLOGFILTER_LEN;

	// We need to rollback from the end of the guard to idx
	// cbuf *** idx --- guard ***
	if (guard_end > idx) {
#ifdef FLOG_DEBUG
		ss << "rollback cbuf: " << (void *)fp->cbuf << 
			" *** idx:" << (void *)idx << 
			" --- guard: " << (void *)fp->guard << " ***" << endl;
		DBGLOG(ss);
#endif

		// guard -- cbuf_end
		if (guard_end < cbuf_end) {
#ifdef FLOG_DEBUG
			DBGLOG("rolling back guard -- cbuf_end\n");
#endif
			len = cbuf_end - guard_end;
			if (!rollback_buffer(fp, pipe, guard_end, len))
				return;
		}

		// Write cbuf - idx
		if (idx > fp->cbuf) {
			len = idx - fp->cbuf;
			if (!rollback_buffer(fp, pipe, fp->cbuf, len))
				return;
		}

	} else { // cbuf --- guard *** idx ---
#ifdef FLOG_DEBUG
		ss << "rollback cbuf: " << (void *)fp->cbuf << 
			" --- guard:" << (void *)fp->guard << 
			" *** idx: " << (void *)idx << " ---" << endl;
		ss << "rolling back guard -- cbuf_end" << endl;
		DBGLOG(ss);
#endif

		// Write guard - idx
		len = idx - guard_end;
		if (!rollback_buffer(fp, pipe, guard_end, len))
			return;
	}
	
	// If a file was not opened by the parent we are done
	if (fp->fd < 0)
		return;
	
	// Unprotect guard page
	assert(mprotect(fp->guard, WLOGFILTER_PAGE_SIZE, 
				PROT_READ|PROT_WRITE) == 0);

	child_rollback_file(fp, pipe);
}

/**
 * Receive original memory contents from pipe, and copy them to process memory
 *
 * @param pipe Pipe descriptor
 * @param entry Pointer to filter entry
 * @return true on success, or false on pipe error
 */
static bool recv_contents(int pipe, struct wlogfilter_entry *entry)
{
	int r;
	size_t len;
	void *p;
#ifdef SAFECOPY_RESTORE
	unsigned char data[32];

	len = entry->len;

	if (len <= 32)
		p = data;
	else {
		// Allocate temporary buffer
		p = malloc(len);
		assert(p);
	}
#else
	len = entry->len;
	p = (void *)entry->addr;
#endif

	// Read original memory contents from pipe
	r = read(pipe, p, len);
	if (r < 0) {
err:
		// error
		stringstream ss;
		ss << "error reading from pipe: " << strerror(errno) << endl;
		ERRLOG(ss);
		return false;
	} else if ((size_t)r != len) {
		goto err;
	}

#ifdef SAFECOPY_RESTORE
	// Copy to memory
	if (PIN_SafeCopy((VOID *)entry->addr, p, len) != len) {
		// Failed to restore data
		stringstream ss;

		ss << "WARNING: " << len << " bytes(s) at " << 
			(void *)entry->addr << " could not be restored" << endl;
		OUTLOG(ss);
	}
#endif
	return true;
}

/** Rollback the contents of memory in the real process, based on the data
 * received by the checkpointing process over a pipe.
 *
 * @param pipe Pipe descriptor
 * @return true on success. false otherwise.
 */
bool filter_parent_rollback(int pipe)
{
	struct wlogfilter_entry entry;
	stringstream ss;
	int r;

	// Receive original memory values from child
	while ((r = read(pipe, &entry, sizeof(entry))) == sizeof(entry)) {
		if (!recv_contents(pipe, &entry))
			return false;
	}

	if (r != 0) {
		// error
		stringstream ss;
		ss << "error reading from pipe: " << strerror(errno) << endl;
		ERRLOG(ss);
		return false;
	}

	return true;
}

#endif // FILTER_TYPE = FILTER_WLOG
