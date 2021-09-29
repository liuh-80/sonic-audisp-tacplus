#if !defined (USER_SECRED_H)
#define USER_SECRED_H

#include <string.h>
#include <regex.h>

/* Macros for initialize result */
#define INITIALIZE_SUCCESS                         0
#define INITIALIZE_OPEN_SETTING_FILE_FAILED        1
#define INITIALIZE_INCORRECT_REGEX                 2

/* Regex append result. */
#define REGEX_APPEND_SUCCESS              0
#define REGEX_APPEND_FAILED               1

/* Regex fix result. */
#define USER_SECRET_FIXED                 0
#define USER_SECRET_NOT_FOUND             1

/* Regex list node. */
typedef struct regex_node {
    struct regex_node *next;
    regex_t regex;
} REGEX_NODE;

/* Initialize user secret setting */
extern int initialize_user_secret_setting(const char *setting_path);

/* Release user secret setting */
extern void release_user_secret_setting();

/* Replace user secret with regex */
extern int remove_user_secret(const char* command, char* result_buffer, size_t buffer_size);

#endif /* USER_SECRED_H */