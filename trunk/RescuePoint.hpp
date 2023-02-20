#ifndef RESCUEPOINT_H
#define RESCUEPOINT_H

#define CONF_OPTIONS 5


typedef enum { RPBLOCKOTHERS, RPIGNOREOTHERS, } rescuepoint_type;
typedef enum { RPBYFUNCNAME, RPBYFUNCADDR, } rescuepoint_ftype;


class RescuePoint {
public:
	static RescuePoint *CreateRescuePoint(const string w[CONF_OPTIONS]);

	string & Name(void) { return fname; }
	ADDRINT Address(void) { return faddr; }
	void SetAddress(ADDRINT addr) { faddr = addr; }
	ADDRINT EndAddress(void) { return faddr_end; }
	void SetEndAddress(ADDRINT addr) { faddr_end = addr; }
	bool HasReturnValue(void) { return !noret; }
	rescuepoint_type Type(void) { return type; }
	rescuepoint_ftype IdType(void) { return ftype; }
	string Id();
	ADDRINT ReturnValue() { return retval; }
	void SetRetAddress(ADDRINT addr) { ret_addr = addr; }
	ADDRINT RetAddress(void) { return ret_addr; }

private:
	rescuepoint_type type;
	rescuepoint_ftype ftype;
	string fname;
	ADDRINT faddr, ret_addr, retval, faddr_end;
	bool noret;
};

#endif
