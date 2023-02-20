#ifndef LIBCROSSDEV_H
#define LIBCROSSDEV_H

#include <fstream>


#ifdef TARGET_WINDOWS
# include "windows/libcrossdev.hpp"
#else
# include "linux/libcrossdev.hpp"
#endif


//! Default flags used for memory map
#define MEMORY_MAP_DEFAULTFLAGS	(MEMORY_MAP_PRIVATE | MEMORY_MAP_ANON)

//! Macro for accessing the line number
#define LINE_NO		__LINE__

bool memory_map(void **buf_p, size_t len, int prot,
		int flags = MEMORY_MAP_DEFAULTFLAGS);

bool memory_protect(void *buf, size_t len, int prot);

bool memory_unmap(void *buf, size_t len);

std::fstream *open_temp_file(const char *prefix, char *temp_fn);

void close_temp_file(std::fstream *fio, const char *temp_fn);

#endif //LIBCROSSDEV_H
