#ifndef WATCHDOG_HPP
#define WATCHDOG_HPP

VOID WatchdogInit(unsigned long long timeout);

BOOL WatchdogStart();

unsigned long long WatchdogRemaining();

#endif
