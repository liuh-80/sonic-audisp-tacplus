#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <stdlib.h>

#include "user_secret.h"
#include "trace.h"

#define min(a,b)            (((a) < (b)) ? (a) : (b))

/* 
 * Macros for user secret regex
 * These are BRE regex, please refer to: https://en.wikibooks.org/wiki/Regular_Expressions/POSIX_Basic_Regular_Expressions
 */
#define USER_SECRET_REGEX_WHITE_SPACE              "[[:space:]]*"
#define USER_SECRET_REGEX_SECRET                   "\\([^[:space:]]*\\)"

/* Regex match group count, 2 because only have 1 subexpression for user secret */
#define REGEX_MATCH_GROUP_COUNT      2

/* The user secret mask */
#define USER_SECRET_MASK                   '*'

/* Replace user secret with regex */
int remove_user_secret_by_regex(const char* command, char* result_buffer, size_t buffer_size, regex_t regex)
{
    regmatch_t pmatch[REGEX_MATCH_GROUP_COUNT];
    if (regexec(&regex, command, REGEX_MATCH_GROUP_COUNT, pmatch, 0) == REG_NOMATCH) {
        trace("User command not match.\n");
        return USER_SECRET_NOT_FOUND;
    }
    
    if (pmatch[1].rm_so < 0) {
        trace("User secret not found.\n");
        return USER_SECRET_NOT_FOUND;
    }
    
    /* Found user secret between pmatch[1].rm_so to pmatch[1].rm_eo, replace it. */
    trace("Found user secret between: %d -- %d\n", pmatch[1].rm_so, pmatch[1].rm_eo);
    
    /* Copy user command first. */
    snprintf(result_buffer, buffer_size, "%s", command);

    /* Replace user secret. */
    int secret_start_pos = min(pmatch[1].rm_so, buffer_size - 1);
    int secret_count = min(pmatch[1].rm_eo, buffer_size - 1) - secret_start_pos;
    memset(result_buffer + secret_start_pos, USER_SECRET_MASK, secret_count);

    return USER_SECRET_FIXED;
}

/* Convert user secret setting to regex. */
void convert_secret_setting_to_regex(char *buf, size_t buf_size, const char* secret_setting)
{
    int src_idx = 0;
    int last_char_is_whitespace = 0;

    /* Reset buffer, make sure following code in while loop can work. */
    memset(buf, 0, buf_size);

    while (secret_setting[src_idx]) {
        int buffer_used_space= strlen(buf);
        if (secret_setting[src_idx] == '*') {
            /* Replace * to USER_SECRET_REGEX_SECRET */
            snprintf(buf + buffer_used_space, buf_size - buffer_used_space,USER_SECRET_REGEX_SECRET);
        }
        else if (isspace(secret_setting[src_idx])) {
            /* Ignore mutiple input space */
            if (!last_char_is_whitespace) {
                /* Replace space to regex USER_SECRET_REGEX_WHITE_SPACE which match multiple space */
                snprintf(buf + buffer_used_space, buf_size - buffer_used_space,USER_SECRET_REGEX_WHITE_SPACE);
            }
        }
        else if (buffer_used_space < buf_size - 1){
            /* Copy none user secret characters */
            buf[buffer_used_space] = secret_setting[src_idx];
        }
        else {
            /* Buffer full, return here. */
            return;
        }

        last_char_is_whitespace = isspace(secret_setting[src_idx]);
        src_idx++;
    }
}