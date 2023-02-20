using namespace std;

#include "../libcrossdev.hpp"


using namespace WND;

//! Define unlink for windows
#define unlink _unlink

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
	DWORD tplen, tflen;
	TCHAR temp_path[MAX_PATH + 2];
	fstream *fio;

	tplen = GetTempPath(MAX_PATH + 2, temp_path);
	if (tplen == 0)
		return NULL;
	tflen = GetTempFileName(temp_path, (LPCTSTR)prefix, 0, (LPTSTR)temp_fn);
	if (tflen == 0)
		return NULL;

	fio = new fstream(temp_fn, ios_base::in|ios_base::out|ios_base::trunc);
	if (fio->fail()) {
		delete fio;
		fio = NULL;
	}
	return fio;
}

/**
 * Map memory pages.
 *
 * @param map_p Output pointer to store address of mapped area.
 * @param len	Length of memory map in bytes.
 * @param prot	Protection flag, can be one of MEMORY_PAGE_RW, and 
 * 		MEMORY_PAGE_RO.
 *
 * @return true if the call completed successfully, or false otherwise.
 */
bool memory_map(void **map_p, size_t len, int prot, int flags)
{
	if (flags & MEMORY_MAP_SHARED)
		// XXX: We do not know how to do shared at this point
		return false;

	*map_p = VirtualAlloc(NULL, len, MEM_RESERVE|MEM_COMMIT|flags, prot);
	if (*map_p == NULL)
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
bool memory_protect(void *map, size_t len, int prot)
{
	DWORD old_prot;

	if (!VirtualProtect(map, len, prot, &old_prot))
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
	if (!VirtualFree(buf, len, MEM_DECOMMIT|MEM_RELEASE))
		return false;
	return true;
}

