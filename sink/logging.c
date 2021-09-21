#define _DEFAULT_SOURCE

#include <syslog.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

extern bool verbose;
extern bool debug;

int facility = LOG_LOCAL0;

void setfacility(const char *facility_p) {
  if (! strcmp(facility_p, "LOCAL0")) {
    facility = LOG_LOCAL0;
  } else if (! strcmp(facility_p, "LOCAL1")) {
    facility = LOG_LOCAL1;
  } else if (! strcmp(facility_p, "LOCAL2")) {
    facility = LOG_LOCAL2;
  } else if (! strcmp(facility_p, "LOCAL3")) {
    facility = LOG_LOCAL3;
  } else if (! strcmp(facility_p, "LOCAL4")) {
    facility = LOG_LOCAL4;
  } else if (! strcmp(facility_p, "LOCAL5")) {
    facility = LOG_LOCAL5;
  } else if (! strcmp(facility_p, "LOCAL6")) {
    facility = LOG_LOCAL6;
  } else if (! strcmp(facility_p, "LOCAL7")) {
    facility = LOG_LOCAL7;
  } else if (! strcmp(facility_p, "USER")) {
    facility = LOG_USER;
  } else if (! strcmp(facility_p, "DAEMON")) {
    facility = LOG_DAEMON;
  }
}


void logmsg(int prio, const char* format, ...) {
  va_list vl;
  char buf[1024];

  va_start(vl, format);
  vsnprintf(buf, sizeof(buf), format, vl);
  va_end(vl);

  if (verbose && (debug || (prio != LOG_DEBUG))) {
    printf("%s\n", buf);
  }

  openlog("counter", 0, facility);
  syslog(prio, "%s", buf);
  closelog();
}

