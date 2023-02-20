using namespace std;

#include "../libcrossdev.hpp"


#include <sys/mman.h>
#include <unistd.h>

#define TEMPDIR "/tmp"

/**
 * Map memory pages.
 *
 * @param map_p	Output pointer to store address of mapped area.
 * @param len	Length of memory map in bytes.
 * @param prot	Protection flag, can be one of MEMORY_PAGE_RW, and 
 * 		MEMORY_PAGE_RO.
 *
 * @return true if the call completed successfully, or false otherwise.
 */
bool memory_map(void **buf_p, size_t len, int prot, int flags)
{
	*buf_p = mmap(NULL, len, prot, flags, -1, 0);
	if (*buf_p == MAP_FAILED)
		return false;
	return true;
}

/**
 * Protect memory pages, so they are not accessible.
 *
 * @param map	Addess of map area to protect.
 * @param len	How many bytes to protect.
 * @param prot	Protection flag, can be one of MEMORY_PAGE_RW, and 
 * 		MEMORY_PAGE_RO.
 *
 * @return true if the call completed successfully, or false otherwise.
 */
bool memory_protect(void *buf, size_t len, int prot)
{
	if (mprotect(buf, len, prot) != 0)
		return false;
	return true;
}

/**
 * Unmap memory pages.
 *
 * @param map	Addess of area to unmap.
 * @param len	Length of area.
 *
 * @return true if the call completed successfully, or false otherwise.
 */
bool memory_unmap(void *buf, size_t len)
{
	if (munmap(buf, len) != 0)
		return false;
	return true;
}

/**
 * Create and open a temporary file.
 * The file will be created in the systems temp directory, and with use prefix.
 *
 * @param prefix	Prefix string to be used for the temporary file name.
 *
 * @return Pointer to fstream object.
 */
fstream *open_temp_file(const char *prefix, char *temp_fn)
{
	fstream *fout;

	snprintf(temp_fn, TEMPFILE_MAXPATH, "%s/%s-XXXXXX", TEMPDIR, prefix);
	fout = new fstream(temp_fn, ios_base::in|ios_base::out|ios_base::trunc);
	return fout;
}
