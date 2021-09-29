#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <stdlib.h>

#include "trace.h"

/* Output trace log. */
void trace(const char *format, ...)
{
    fprintf(stderr, "Audisp-tacplus: ");
    syslog(LOG_INFO,"Audisp-tacplus: ");

    // convert log to a string because va args resoursive issue:
    // http://www.c-faq.com/varargs/handoff.html
    char logBuffer[MAX_LINE_SIZE];
    va_list args;
    va_start (args, format);
    vsnprintf(logBuffer, sizeof(logBuffer), format, args);
    va_end (args);

    fprintf(stderr, "%s", logBuffer);
    syslog(LOG_INFO, "%s", logBuffer);
}