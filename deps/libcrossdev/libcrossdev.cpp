using namespace std;

#include "libcrossdev.hpp"


/**
 * Close and destroy tempory file.
 *
 * @param fio		fstream associated with file.
 * @param temp_fn	Filename of temporary file.
 */
void close_temp_file(fstream *fio, const char *temp_fn)
{
	delete fio;
	unlink(temp_fn);
}
