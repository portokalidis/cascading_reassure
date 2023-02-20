#include <iostream>
#include <sstream>

#include "pin.H"
#include "libminestrone.hpp"


// Define minestrone reporting command line options
#include "minestrone_opts.hpp"



/**
 * Append test case entries in string stream
 *
 * @param ss	Reference to string stream
 */
static void append_tc(stringstream &ss)
{
	ss << "\t<test_case>" << original_name.Value() << 
		"</test_case>" << endl;
	ss << "\t<ref_id>" << ref_id.Value() << "</ref_id>" << endl;
}

/**
 * Issue notification in pintool log file, and std err if we have been
 * configured this way.
 *
 * @param str	Reference to string that will be logged
 */
static inline void notify(const string &str)
{
	if (notify_stderr.Value()) {
		cerr << str;
		LOG(str);
	} else {
		LOG(str);
	}
}



/**
 * Return minestrone message for execution status.
 *
 * @param status	Exit status
 * @param code		Exit code
 *
 * @return string containing message
 */
string minestrone_status_message(exis_status_t status, INT32 code)
{
	stringstream ss;

	// Execute status
	ss << "<return_status_message>" << endl;
	ss << "\t<message_type>execute_status" << "</message_type>" << endl;
	append_tc(ss);
	switch (status) {
	case ES_SUCCESS:
		ss << "\t<status>success</status>" << endl;
		ss << "\t<status_code>" << code << "</status_code>" << endl;
		break;

	case ES_TIMEOUT:
		ss << "\t<status>timeout</status>" << endl;
		break;

	case ES_SKIP:
		ss << "\t<status>skip</status>" << endl;
		break;

	}
	ss << "</return_status_message>" << endl;

	return ss.str();
}

/**
 * Log execution status in pintool log file, and std err if we have been
 * configured this way.
 *
 * @param status	Exit status
 * @param code		Exit code
 */
void minestrone_log_status(exis_status_t status, INT32 code)
{
	notify(minestrone_status_message(status, code));
}

/**
 * Return minestrone message for a particular vulnerability/event.
 *
 * @param cwe		CWE number of detected vulnerability.
 * 			0 if not CWE was detected
 * @param impact	String describing the impact of the event
 *
 * @return string containing message
 */
string minestrone_message(UINT32 cwe, const char *impact)
{
	stringstream ss;

	// XML version
	ss << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" << endl;

	// Report CWE, if specified
        if (cwe > 0) {
                ss << "<structured_message>" << endl;
                ss << "\t<message_type>found_cwe</message_type>" << endl;
		append_tc(ss);
                ss << "\t<cwe_entry_id>" << cwe << "</cwe_entry_id>" << endl;
                ss << "</structured_message>" << endl;
        }

	// Report technical_impact
        ss << "<structured_message>" << endl;
        ss << "\t<message_type>technical_impact" << "</message_type>" << endl;
        ss << "\t<impact>" << impact << "</impact>" << endl;
	append_tc(ss);
        ss << "</structured_message>" << endl;

	return ss.str();
}

/**
 * Log minestrone message in pintool log file, and std err if we have been
 * configured this way.
 *
 * @param cwe		CWE number of detected vulnerability.
 * 			0 if not CWE was detected
 * @param impact	String describing the impact of the event
 */
void minestrone_notify(UINT32 cwe, const char *impact)
{
	// Finally log everything
	notify(minestrone_message(cwe, impact));
}

/**
 * Log a successful exit status message on process exit
 *
 * @param code	Exit code
 * @param v	Opaque pointer for use with Pin's API (unused)	
 */
void minestrone_fini_success(INT32 code, VOID *v)
{
	minestrone_log_status(ES_SUCCESS, code);
}
