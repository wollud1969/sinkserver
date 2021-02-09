#define _DEFAULT_SOURCE

#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>

void logmsg(int prio, const char* format, ...) {
  va_list vl;
  
  // openlog("counter", 0, LOG_LOCAL0);
  va_start(vl, format);
  //vsyslog(prio, format, vl);
  vprintf(prio, format, vl);
  va_end(vl);
  // closelog();
}

