#include "pin.H"
#include "RescuePoint.hpp"

extern "C" {
#include <stdlib.h>
#include <stdio.h>
}

RescuePoint *RescuePoint::CreateRescuePoint(const string w[CONF_OPTIONS])
{
	RescuePoint *rp = new RescuePoint();

	// How is the rescue point identified
	if (w[0].empty())
		goto fail;
	if (w[0].compare("SYM") == 0)
		rp->ftype = RPBYFUNCNAME;
	else if (w[0].compare("ADDR") == 0)
		rp->ftype = RPBYFUNCADDR;

	// Get rescue point id
	if (w[1].empty())
		goto fail;
	if (rp->ftype == RPBYFUNCNAME) {
		rp->fname = w[1];
	} else {
		// start_addr:end_addr in hex
		size_t sep_idx;
		string str;

		// find separator ':'
		sep_idx = w[1].find_first_of(':');
		if (sep_idx == string::npos) // ':' not found
			return NULL;

		// Read the two hex numbers (start and end addresses of the RP)
		str = w[1].substr(0, sep_idx);
		rp->faddr = strtoul(str.c_str(), NULL, 16);
		str = w[1].substr(sep_idx + 1);
		rp->faddr_end = strtoul(str.c_str(), NULL, 16);
	}

	if (w[2] == "N")
		rp->noret = true;
	else if (w[2] == "V")
		rp->noret = false;
	else
		goto fail;

	if (w[3].empty())
		goto fail;
	else 
		rp->retval = atoi(w[3].c_str());

	
	if (!w[4].empty()) {
		if (w[4] == "BlockOthers")
			rp->type = RPBLOCKOTHERS;
		else if (w[4] == "IgnoreOthers")
			rp->type = RPIGNOREOTHERS;
		else
			goto fail;
	} else {
fail:
		delete rp;
		rp = NULL;
	}

	rp->ret_addr = 0;

	return rp;
}

#if 0
rescuepoint_ftype RescuePoint::IdType(void)
{
	return ftype;
}

rescuepoint_type RescuePoint::Type(void)
{
	return type;
}

void RescuePoint::SetRetAddress(ADDRINT retaddr)
{
	this->retaddr = retaddr;
}

ADDRINT RescuePoint::RetAddress(void)
{
	return this->retaddr;
}

string RescuePoint::Name(void)
{
	return this->fname;
}

ADDRINT RescuePoint::ReturnValue(void)
{
	return retval;
}

ADDRINT RescuePoint::Address(void)
{
	return this->faddr;
}

bool RescuePoint::HasReturnValue(void)
{
	return !noret;
}
#endif

string RescuePoint::Id(void)
{
	char hex[24];

	if (ftype == RPBYFUNCNAME)
		return fname;
	else {
		snprintf(hex, 24, "%0x", faddr);
		return string(hex);
	}
}
