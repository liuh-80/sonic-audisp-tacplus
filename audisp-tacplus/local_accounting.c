#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <stdlib.h>

#include "trace.h"

/* Accounting log format. */
#define ACCOUNTING_LOG_FORMAT "Accounting: user: %s, tty: %s, host: %s, command: %s, type: %d, task ID: %d"

/* Write the accounting information to syslog. */
void accounting_to_syslog(char *user, char *tty, char *host, char *cmdmsg, int type, uint16_t task_id)
{
    char accounting_buffer[MAX_LINE_SIZE];
    snprintf(accounting_buffer, sizeof(accounting_buffer), ACCOUNTING_LOG_FORMAT, user, tty, host, cmdmsg, type, task_id);
    syslog(LOG_INFO, "%s", accounting_buffer);
}