#ifndef _LOGGING_H_
#define _LOGGING_H_

#include <syslog.h>

void logmsg(int prio, const char* format, ...);

#endif // _LOGGING_H_
