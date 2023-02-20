#ifndef LINUX_LIBCROSSDEV_H
#define LINUX_LIBCROSSDEV_H


extern "C" {
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <byteswap.h>
}

//! Max path length that a generated temporary filename can have
#define TEMPFILE_MAXPATH 256

//! Page protection is read/write
#define MEMORY_PAGE_RW		(PROT_READ|PROT_WRITE)
//! Page protection is read only
#define MEMORY_PAGE_RO		PROT_READ
//! Memory map is anonymous (not backed by a file)
#define MEMORY_MAP_ANON		MAP_ANONYMOUS
//! Memory map is shared
#define MEMORY_MAP_SHARED	MAP_SHARED
//! Memory map is private
#define MEMORY_MAP_PRIVATE	MAP_PRIVATE
//! Memory map should use large pages
#define MEMORY_MAP_HUGEPAGES	MAP_HUGETLB

//! Returns the thread identifier of the calling thread
#define get_thread_id()	syscall(SYS_gettid)

//! Character used for separating directories
#define DIRECTORY_SEP_CHAR '/'

//! Macro for accessing the name of the enclosing function
#define FUNCTION_NAME		__func__

//! Swaps the bytes of a 64-bit integer
#define byteswap64(v)		bswap_64(v)

//! Swaps the bytes of a 32-bit integer
#define byteswap32(v)		bswap_32(v)

//! Swaps the bytes of a 16-bit integer
#define byteswap16(v)		bswap_16(v)


#endif 
