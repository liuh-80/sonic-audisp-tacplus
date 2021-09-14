/*
 * Copyright 2014, 2015, 2016, 2017 Cumulus Networks, Inc.  All rights reserved.
 *   Based on audisp-example.c by Steve Grubb <sgrubb@redhat.com>
 *     Copyright 2009 Red Hat Inc., Durham, North Carolina.
 *     All Rights Reserved.
 *
 *   TACACS+ work based on pam_tacplus.c
 *     Copyright (C) 2010, Pawel Krawczyk <pawel.krawczyk@hush.com> and
 *     Jeroen Nijhof <jeroen@jeroennijhof.nl>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: olson@cumulusnetworks.com>
 *
 * This audisp plugin is used for TACACS+ accounting of commands
 * being run by users known to the TACACS+ servers
 * It uses libsimple_tacacct to communicate with the TACACS+ servers
 * It uses the same configuration file format as the libnss_tacplus
 * plugin (but uses the file /etc/audisp/audisp-tacplus.conf to
 * follow the audisp conventions).
 *
 * You can test it by running commands similar to:
 *   ausearch --start today --raw > test.log
 *   ./audisp-tacplus < test.log
 *
 * Excluding some init/destroy items you might need to add to main, the
 * event_handler function is the main place that you would modify to do
 * things specific to your plugin.
 *
 */

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/wait.h>
#include <pwd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <libaudit.h>
#include <auparse.h>
#include <unistd.h>
#include <limits.h>


#include <libtac/libtac.h>

/* Tacacs+ support lib */
#include <libtac/support.h>

#define _VMAJ 1
#define _VMIN 0
#define _VPATCH 0

/* Global Data */
static volatile int stop = 0;
static volatile int hup = 0;
static auparse_state_t *au = NULL;
static unsigned connected_ok;

/* Tacacs control flag */
int tacacs_ctrl;

/* Uniknown host name */
const char *unknown_hostname = "UNK";

/* Config file path */
const char *tacacs_config_file = "/etc/tacplus_servers";

/* Local declarations */
static void handle_event(auparse_state_t *au,
		auparse_cb_event_t cb_event_type, void *user_data);

/*
 * SIGTERM handler
 */
static void
term_handler(int sig __attribute__ ((unused)))
{
        stop = 1;
}

/*
 * SIGHUP handler: re-read config
 */
static void
hup_handler(int sig __attribute__ ((unused)))
{
        hup = 1;
}

static const char *progname = "audisp-tacplus"; /* for syslogs and errors */

static void
reload_config(void)
{
    hup = 0;

    connected_ok = 0; /*  reset connected state (for possible vrf) */

    /* load config file: tacacs_config_file */
    tacacs_ctrl = parse_config_file(tacacs_config_file);
}

/*
 * Get user name by UID, and return NULL when not found user name by UID.
 * The returned username should be free by caller.
 */
char *lookup_logname(uid_t auid)
{
    struct passwd *pws;
    pws = getpwuid(auid);
    if (pws == NULL) {
        /* Failed to get user information. */
        return NULL;
    }
    
    int new_buffer_size = strlen(pws->pw_name) + 1;
    char* username = malloc(new_buffer_size);
    if (username == NULL) {
        /* Failed to allocate new buffer. */
        return NULL;
    }
    
    memset(username, 0, new_buffer_size);
    strncpy(username, pws->pw_name, new_buffer_size);
    return username;
}

int
main(int argc, char *argv[])
{
	char tmp[MAX_AUDIT_MESSAGE_LENGTH+1];
	struct sigaction sa;
    
    /* initialize random seed*/
    srand(time(NULL));

    reload_config();

	/* Register sighandlers */
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	/* Set handler for the ones we care about */
	sa.sa_handler = term_handler;
	sigaction(SIGTERM, &sa, NULL);
	sa.sa_handler = hup_handler;
	sigaction(SIGHUP, &sa, NULL);

	/* Initialize the auparse library */
	au = auparse_init(AUSOURCE_FEED, 0);
	if(au == NULL) {
		syslog(LOG_ERR, "exitting due to auparse init errors");
		return -1;
	}
	auparse_add_callback(au, handle_event, NULL, NULL);
	do {
		/* Load configuration */
		if(hup) {
			syslog(LOG_NOTICE, "%s re-initializing configuration", progname);
			reload_config();
		}

		/*
		 * Now the event loop.  For some reason, audisp doesn't send
		 * us the ANOM_ABEND until flushed by another event. and it
		 * therefore has the timestamp of the next event.  I can't find
		 * any parameters to affect that.
		 */
		while(fgets(tmp, MAX_AUDIT_MESSAGE_LENGTH, stdin) &&
							hup==0 && stop==0) {
			auparse_feed(au, tmp, strnlen(tmp,
						MAX_AUDIT_MESSAGE_LENGTH));
		}
		if(feof(stdin))
			break;
	} while(stop == 0);

    syslog(LOG_DEBUG, "finishing");
	/* Flush any accumulated events from queue */
	auparse_flush_feed(au);
	auparse_destroy(au);

	return 0;
}

int
send_acct_msg(int tac_fd, int type, char *user, char *tty, char *host,
    char *cmd, uint16_t taskid)
{
    char buf[128];
    struct tac_attrib *attr;
    int retval;
    struct areply re;

    attr=(struct tac_attrib *)xcalloc(1, sizeof(struct tac_attrib));

    snprintf(buf, sizeof buf, "%lu", (unsigned long)time(NULL));
    tac_add_attrib(&attr, "start_time", buf);

    snprintf(buf, sizeof buf, "%hu", taskid);
    tac_add_attrib(&attr, "task_id", buf);

    tac_add_attrib(&attr, "service", tac_service);
    if(tac_protocol[0])
      tac_add_attrib(&attr, "protocol", tac_protocol);
    tac_add_attrib(&attr, "cmd", (char*)cmd);

    re.msg = NULL;
    retval = tac_acct_send(tac_fd, type, user, tty, host, attr);

    if(retval < 0)
        syslog(LOG_WARNING, "send of accounting msg failed: %m");
    else if(tac_acct_read(tac_fd, &re) != TAC_PLUS_ACCT_STATUS_SUCCESS ) {
        syslog(LOG_WARNING, "accounting msg response failed: %m");
        retval = -1;
    }

    tac_free_attrib(&attr);
    if(re.msg != NULL)
        free(re.msg);

    return retval >= 0 ? 0 : 1;
}

/*
 * Send the accounting record to the TACACS+ server.
 *
 * We have to make a new connection each time, because libtac is single threaded
 * (doesn't support multiple connects at the same time due to use of globals)),
 * and doesn't have support for persistent connections.
 */
static void
send_tacacs_acct(char *user, char *tty, char *host, char *cmdmsg, int type,
    uint16_t task_id)
{
    int retval, srv_i, srv_fd;

    for(srv_i = 0; srv_i < tac_srv_no; srv_i++) {
        srv_fd = tac_connect_single(tac_srv[srv_i].addr, tac_srv[srv_i].key, &tac_source_addr, tac_timeout, __vrfname);
        if(srv_fd < 0) {
            syslog(LOG_WARNING, "connection to %s failed (%d) to send"
                " accounting record: %m",
                tac_ntop(tac_srv[srv_i].addr->ai_addr), srv_fd);
            continue;
        }
        retval = send_acct_msg(srv_fd, type, user, tty, host, cmdmsg, task_id);
        if(retval)
            syslog(LOG_WARNING, "error sending accounting record to %s: %m",
                tac_ntop(tac_srv[srv_i].addr->ai_addr));
        close(srv_fd);
        if(!retval) {
            connected_ok = 1;
            if(!(tacacs_ctrl & PAM_TAC_ACCT)) {
                break; /* only send to first responding server */
            }
        }
    }
}

/*
 * encapsulate the field lookup, and rewind if needed,
 * rather than repeating at each call.
 */
static const char *get_field(auparse_state_t *au, const char *field)
{
    const char *str;
    if(!(str=auparse_find_field(au, field))) {
        auparse_first_field(au);
        if(!(str=auparse_find_field(au, field))) {
            /* sometimes auparse_first_field() isn't enough, depending
             * on earlier lookup order. */
            auparse_first_record(au);
            if(!(str=auparse_find_field(au, field)))
                return NULL;
        }
    }
    return str;
}

/* find an audit field, and return the value for numeric fields.
 * return 1 if OK (field found and is numeric), otherwise 0.
 * It is somewhat smart, in that it will try from current position in case code
 * is written "knowing" field order; if not found will rewind and try again.
 */
static unsigned long
get_auval(auparse_state_t *au, const char *field, int *val)
{
    int rv;

    if(!get_field(au, field))
        return 0;
    rv = auparse_get_field_int(au);
    if(rv == -1 && errno)
        return 0;
    *val = rv;
    return 1;
}


/*
 * Get the audit record for exec system calls, and send it off to the
 * tacacs+ server.   Lookup the original tacacs username first.
 * This just gets us the starts of commands, not the stop, which would
 * require matching up the exit system call.   For now, don't bother.
 * Maybe add some caching of usernames at some point.
 * Both auid and sessionid have to be valid for us to do accounting.
 * We don't bother with really long cmd names or really long arg lists,
 * we stop at 240 characters, because the longest field tacacs+ can handle
 * is 255 characters, and some of the accounting doesn't seem to work
 * if right at full length.
 */
static void get_acct_record(auparse_state_t *au, int type)
{
    int val, i, llen, tlen, freeloguser=0;
    int acct_type;
    pid_t pid;
    uint16_t taskno;
    unsigned argc=0, session=0, auid;
    char *auser = NULL, *loguser, *tty = NULL;
    char *cmd = NULL, *ausyscall = NULL;
    char logbuf[240], *logptr, *logbase;

    /* get host name. */
    char host[HOST_NAME_MAX];
    memset(host, 0, sizeof(host));
    if (gethostname(host, sizeof(host)) != 0)
    {
        strncpy(host, unknown_hostname, sizeof(host));
    }

    if(get_field(au, "syscall"))
        ausyscall = (char *)auparse_interpret_field(au);

    /* exec calls are START of commands, exit (including exit_group) are STOP */
    if(ausyscall && !strncmp(ausyscall, "exec", 4)) {
        acct_type = TAC_PLUS_ACCT_FLAG_START;
    }
    else if(ausyscall && !strncmp(ausyscall, "exit", 4)) {
        acct_type = TAC_PLUS_ACCT_FLAG_STOP;
    }
    else if(type == AUDIT_ANOM_ABEND) {
        acct_type = TAC_PLUS_ACCT_FLAG_STOP;
    }
    else /* not a system call we care about */
        return;

    auid = session = val = 0;
    if(get_auval(au, "auid", &val))
        auid = (unsigned)val;
    if(auid == 0 || auid == (unsigned)-1) {
        /* we have to have auid for tacplus mapping */
        return;
    }
    if(get_auval(au, "ses", &val))
        session = (unsigned)val;
    if(session == 0 || session == (unsigned)-1) {
        /* we have to have session for tacplus mapping */
        return;
    }
    if(get_auval(au, "pid", &val)) {
        /*
         * Use pid so start and stop have matching taskno.  If pids wrap
         * in 16 bit space, we might have a collsion, but that's unlikely,
         * and with 16 bits, it could happen no matter what we do.
         */
        pid = (pid_t)val;
        taskno = (uint16_t) pid;
    }
    else {
        /* should never happen, if it does, records won't match */
        taskno = (u_int32_t)rand();
    }

    if(get_field(au, "auid")) {
        auser = (char *)auparse_interpret_field(au);
    }
    if(!auser) {
        auser="unknown";
    }
    if(get_field(au, "tty"))
        tty = (char *)auparse_interpret_field(au);

    auparse_first_field(au);

    /*
     * pass NULL as the name lookup because we must have an auid and session
     * match in order to qualify as a tacacs session accounting record.  With
     * the NSS library, the username in auser will likely already be the login
     * name.
     */
    loguser = lookup_logname(auid);
    if(!loguser) {
        char *user = NULL;

        if(auser) {
            user = auser;
        }
        else {
            auparse_first_field(au);
            if(auparse_find_field(au, "uid")) {
                user = (char *)auparse_interpret_field(au);
            }
        }
        if(!user)
            return; /* must be an invalid record */
        loguser = user;
    }
    else {
        freeloguser = 1;
    }

    if(get_field(au, "exe"))
        cmd = (char *)auparse_interpret_field(au);
    if(get_auval(au, "argc", &val))
        argc = (int)val;

    /*
     * could also grab "exe", since it can in theory
     * be different, and besides gives full path, so not ambiguous,
     * but not for now.
     */
    logbase = logptr = logbuf;
    tlen =  0;

    if(cmd) {
        i = 1; /* don't need argv[0], show full executable */
        llen = snprintf(logptr, sizeof logbuf - tlen, "%s", cmd);
        if(llen >= sizeof logbuf) {
            llen = sizeof logbuf - 1;
        }
        logptr += llen;
        tlen = llen;
    }
    else
        i = 0; /* show argv[0] */
    for(; i<argc && tlen < sizeof logbuf; i++) {
        char anum[13];
        snprintf(anum, sizeof anum, "a%u", i);
        if(get_field(au, anum)) { /* should always be true */
            llen = snprintf(logptr, sizeof logbuf - tlen,
                "%s%s", i?" ":"", auparse_interpret_field(au));
            if(llen >= (sizeof logbuf - tlen)) {
                llen = sizeof logbuf - tlen;
                break;
            }
            logptr += llen;
            tlen += llen;
        }
    }

    /*
     * Put exit status after command name, the argument to exit is in a0
     * for exit syscall; duplicates part of arg loop below
     * This won't ever happen for processes that terminate on signals,
     * including SIGSEGV, unfortunately.  ANOM_ABEND would be perfect,
     * but it doesn't always happen, at least in jessie.
     */
    if(acct_type == TAC_PLUS_ACCT_FLAG_STOP && argc == 0) {
        llen = 0;
        if(get_field(au, "a0")) {
            llen = snprintf(logptr, sizeof logbuf - tlen,
                " exit=%d", auparse_get_field_int(au));
        }
        else if(get_auval(au, "sig", &val)) {
            llen = snprintf(logptr, sizeof logbuf - tlen,
                " exitsig=%d", (int)val);
        }
        logptr += llen;
        tlen += llen;
    }

    /*
     * loguser is always set, we bail if not.  For ANOM_ABEND, tty may be
     *  unknown, and in some cases, host may be not be set.
     */
    send_tacacs_acct(loguser, tty?tty:"UNK", host, logbase, acct_type, taskno);

    if(freeloguser) {
        free(loguser);
    }
}

/*
 * This function receives a single complete event at a time from the auparse
 * library. This is where the main analysis code would be added.
 */
static void
handle_event(auparse_state_t *au, auparse_cb_event_t cb_event_type,
             void *user_data __attribute__ ((unused)))
{
    int type, num=0;

    if(cb_event_type != AUPARSE_CB_EVENT_READY) {
	    return;
    }

    /* Loop through the records in the event looking for one to process.
     * We use physical record number because we may search around and
     * move the cursor accidentally skipping a record.
     */
    while(auparse_goto_record_num(au, num) > 0) {
	type = auparse_get_type(au);
	/*
	 * we are only writing TACACS account records for syslog exec
	 * records.  login, etc. are handled through pam_tacplus
	 */
	switch(type) {
	    case AUDIT_SYSCALL:
	    case AUDIT_ANOM_ABEND:
		get_acct_record(au, type);
		break;
	    default:
		// for doublechecking dump_whole_record(au);
		break;
	}
	num++;
    }
}
