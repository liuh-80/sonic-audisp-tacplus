#if !defined (LOCAL_ACCOUNTING_H)
#define LOCAL_ACCOUNTING_H

/* Write accounting information to syslog. */
extern void accounting_to_syslog(char *user, char *tty, char *host, char *cmdmsg, int type, uint16_t task_id);

#endif /* LOCAL_ACCOUNTING_H */