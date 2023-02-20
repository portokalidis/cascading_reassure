#include <iostream>
#include <fstream>
#include <sstream>
#include <cassert>

extern "C" {
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
}

#include "pin.H"
#include "RescuePoint.hpp"
#include "utils.hpp"
#include "libreassure.hpp"
#include "log.hpp"


static filebuf logfile;


int ParseConf(const char *str, map<string, RescuePoint *> &rpbyname,
		map<ADDRINT, RescuePoint *> &rpbyaddr,
		bool *has_blocking)
{
	ifstream infile;
	string line, word[CONF_OPTIONS];
	UINT32 lineno, w;
	RescuePoint *rp;
	pair<map<string, RescuePoint *>::iterator, bool> r;
	pair<map<ADDRINT, RescuePoint *>::iterator, bool> r2;
	stringstream ss;

	infile.open(str);
	if (!infile.is_open()) {
		ss << "Could not open configuration file " << str << ": "
			<< strerror(errno) << endl;
		ERRLOG(ss);
		return -1;
	}

	if (has_blocking)
		*has_blocking = false;
	lineno = 0;
	while (true) {
		line = ReadLine(infile, &lineno);
		if (line.empty())
			break;
		w = Tokenize(line, word, CONF_OPTIONS);
		if (w != CONF_OPTIONS) {
			goto conf_error;
		}
		rp = RescuePoint::CreateRescuePoint(word);
		if (!rp) {
conf_error:
			ss << "Invalid rescue point definition at lineno " <<
				lineno << endl << ">> " << line << endl;
			ERRLOG(ss);
			continue;
		}
		r.second = r2.second = true;
		if (rp->IdType() == RPBYFUNCNAME)
			r = rpbyname.insert(pair<string, RescuePoint *>
					(rp->Name(), rp));
		else {
			r2 = rpbyaddr.insert(pair<ADDRINT, RescuePoint *>
					(rp->EndAddress(), rp));
		}
		if (!r.second || !r2.second) {
			ss << "Duplicate rescue point for " << 
				rp->Id() << endl;
			ERRLOG(ss);
			delete rp;
			continue;
		}
		if (has_blocking && rp->Type() == RPBLOCKOTHERS)
			*has_blocking = true;
	}

	infile.close();

	return 0;
}

extern ostream *log;

ostream *SetupLogging(const char *fname)
{
	if (fname == NULL) {
		return &cerr;
	}

#if 0
	logfn << fname << "." << PIN_GetPid();
	*log << "Opening log " << logfn.str() << endl;
	if (logfile.is_open())
		logfile.close();
#else
	if (logfile.is_open())
		return log;
#endif
	logfile.open(fname, ios_base::out|ios_base::app);
	if (!logfile.is_open()) {
		perror("Error opening process log file");
		return FALSE;
	}
	return new ostream(&logfile);
}

