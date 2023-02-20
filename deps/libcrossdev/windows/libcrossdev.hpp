#ifndef WINDOWS_LIBCROSSDEV_H
#define WINDOWS_LIBCROSSDEV_H


namespace WND {
# include <Windows.h>
}

//! Max path length that a generated temporary filename can have
#define TEMPFILE_MAXPATH MAX_PATH

//! Page protection is read/write
#define MEMORY_PAGE_RW		PAGE_READWRITE
//! Page protection is read only
#define MEMORY_PAGE_RO 		PAGE_READONLY
//! Memory map is anonymous (not backed by a file)
#define MEMORY_MAP_ANON		(0)
//! Memory map is shared
#define MEMORY_MAP_SHARED	0x00000001
//! Memory map is private
#define MEMORY_MAP_PRIVATE	(0)
//! Memory map should use large pages
#define MEMORY_MAP_HUGEPAGES	MEM_LARGE_PAGES

//! Returns the thread identifier of the calling thread
#define get_thread_id() WND::GetCurrentThreadId()

//! Character used for separating directories
#define DIRECTORY_SEP_CHAR '\\'

//! POSIX compliant strdup on windows
#define strdup _strdup

//! Macro for accessing the name of the enclosing function
#define FUNCTION_NAME		__FUNCTION__
//
//! Swaps the bytes of a 64-bit integer
#define byteswap64(v)		_byteswap_uint64(v)

//! Swaps the bytes of a 32-bit integer
#define byteswap32(v)		_byteswap_ulong(v)

//! Swaps the bytes of a 16-bit integer
#define byteswap16(v)		_byteswap_ushort(v)

#define __LITTLE_ENDIAN 0x41424344UL 
#define __BIG_ENDIAN    0x44434241UL
#define __ENDIAN_ORDER  ('ABCD') 

#if __ENDIAN_ORDER==__LITTLE_ENDIAN
//! Host to big-endian transformation for 16-bit values
#define htobe16(v)		byteswap16(v)
//! Host to big-endian transformation for 32-bit values
#define htobe32(v)		byteswap32(v)
//! Host to big-endian transformation for 64-bit values
#define htobe64(v)		byteswap64(v)
#else
//! Host to big-endian transformation for 16-bit values
#define htobe16(v)		(v)
//! Host to big-endian transformation for 32-bit values
#define htobe32(v)		(v)
//! Host to big-endian transformation for 64-bit values
#define htobe64(v)		(v)
#endif

//#define pause()			WND::Sleep(INFINITE)


#endif
