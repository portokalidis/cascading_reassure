#ifndef LOG_HPP
#define LOG_HPP

#define DBGLOG ERRLOG

static inline VOID ERRLOG(stringstream &sstr)
{
	LOG(sstr.str());
	cerr << sstr.str();
	sstr.str("");
}

static inline VOID ERRLOG(const char *s)
{
	LOG(s);
	cerr << s;
}

static inline VOID OUTLOG(stringstream &sstr)
{
	LOG(sstr.str());
	sstr.str("");
}

static inline VOID OUTLOG(const char *s)
{
	LOG(s);
}

#endif
