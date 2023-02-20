#ifndef LIBMINESTRONE_HPP
#define LIBMINESTRONE_HPP

//! Exit status enum for reporting minestrone style
typedef enum EXIT_STATUS_ENUM { ES_SUCCESS, ES_TIMEOUT, ES_SKIP } exis_status_t;

//! Execution timeout for watchdog
extern KNOB<unsigned long long> exec_timeout;


string minestrone_message(UINT32 cwe, const char *impact);

void minestrone_notify(UINT32 cwe, const char *impact);

void minestrone_fini_success(INT32 code, void *v);

string minestrone_status_message(exis_status_t status, INT32 code);

void minestrone_log_status(exis_status_t status, INT32 code);

void minestrone_watchdog_init(int argc, 
		char **argv, unsigned long long timeout);

bool minestrone_watchdog_start(void);

#endif
