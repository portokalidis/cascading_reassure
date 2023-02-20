#ifndef PARSECONF_HPP
#define PARSECONF_HPP

#include <map>
#include <cstring>

class RescuePoint;

int ParseConf(const char *str, map<string, RescuePoint *> &rpbyname,
		map<ADDRINT, RescuePoint *> &rpbyaddr, 
		bool *has_blocking = NULL);

ostream *SetupLogging(const char *fname);

#endif
