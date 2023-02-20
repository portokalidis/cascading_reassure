//! Timeout option string
#define TIMEOUT_OPTION		"timeout"

//! Timeout in seconds (we exit if execution takes more than this value)
KNOB<unsigned long long> exec_timeout(KNOB_MODE_WRITEONCE, "pintool",
                TIMEOUT_OPTION, "0", "Timeout in seconds. Stop executing "
                "after specified amount of seconds. 0 disables timeout.");

