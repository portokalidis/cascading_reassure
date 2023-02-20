#include <iostream>
extern "C" {
#include <unistd.h>
#include <stdio.h>
}

#include "pin.H"
#include "demangle.hpp"

#define CPPFILTEXEC	"c++filt"
#define PARENT_READ	readpipe[0]
#define PARENT_WRITE	writepipe[1]
#define CHILD_READ	writepipe[0]
#define CHILD_WRITE	readpipe[1]

// C++FILT pipe
static int writepipe[2], readpipe[2];
static FILE *parent_readfl;



BOOL DemangleRoutine(string &name, string &dname)
{
	int c, w;

	name += '\n';
	//cout << "Unmangle function: " << rname.c_str();

	w = write(PARENT_WRITE, name.c_str(), name.length());
	if (w != (ssize_t)name.length())
		return FALSE;

	while ((c = fgetc(parent_readfl)) != EOF && c != '\n')
		dname += c;
	if (c == EOF)
		return FALSE;

	//cout << "Result " << dname << endl;
	return TRUE;
}

VOID DemangleProcLaunch(void)
{
	int r;

	if (pipe(writepipe) != 0 || pipe(readpipe) != 0) {
error:
		perror("Failed to start c++filt");
		PIN_ExitProcess(1);
	}

	if ((r = fork()) < 0)
		goto error;
	else if (r == 0) { // child
		close(PARENT_WRITE);
		close(PARENT_READ);

		if (dup2(CHILD_READ, 0) != 0)
			goto error;
		//close(CHILD_READ);
		if (dup2(CHILD_WRITE, 1) != 1)
			goto error;
		//close(CHILD_WRITE);
		
		// Possible drop privileges

		execlp(CPPFILTEXEC, CPPFILTEXEC, "-p", (char *)NULL);
		goto error;
	}
	// parent 
	close(CHILD_READ);
	close(CHILD_WRITE);
	
	parent_readfl = fdopen(PARENT_READ, "r");
	if (!parent_readfl)
		goto error;
}
