/* pam_xauth module */

/*
 * Written by Michael K. Johnson <johnsonm@redhat.com> 1999/04/10
 * A few functions loosely based on functions from Cristian Gafton's
 * pam_wheel module.  Others are loosely based on pam_console by
 * Michael K. Johnson.
 */

#include <pwd.h>
#include <errno.h>
#include <fcntl.h>
#include <features.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/fsuid.h>
#include <sys/wait.h>

/* PAM is stupid about some things, <sigh> */
#define CAST_ME_HARDER (const void**)

#define PAM_SM_SESSION
#include <security/pam_modules.h>
#include <security/_pam_macros.h>


typedef enum {
  Source = 0,
  Target = 1,
} user_context;

typedef enum {
  Exist,
  Map,
  Delete,
} access_type;

typedef enum {
  RdOnly = O_RDONLY,
  WrOnly = O_WRONLY,
  RdWr   = O_RDWR,
  Create = O_CREAT,
} access_level;

typedef struct action {
  user_context context;
  access_type  type;
  access_level level;
  char *filename; /* always relative to home directory */
  char *data;
  int size;   /* minimum size; negative sizes added to existing filesize */
  int map_size;  /* size actually mapped, private to do_file and do_close */
  int fd;
  struct stat sb;
} action;


typedef enum {
  Incoming,
  Outgoing,
} direction;


static int debug = 0;
static int log_auth = LOG_AUTHPRIV;
static int systemuser = 499;
static char *xauthority = NULL;
static const char *xauthdefpath = "/usr/X11R6/bin/xauth";
static char *xauth = NULL;
static char *display = NULL;
static char *name[2] = {NULL, NULL};
static char *home[2] = {NULL, NULL};
static uid_t user[2] = {0, 0};




/* some syslogging */
static void
_pam_vlog(int err, int debug_p, const char *format, va_list args)
{
    if (debug_p && !debug) return;

    openlog("pam_xauth", LOG_CONS|LOG_PID, LOG_DAEMON);
    vsyslog(err, format, args);
    closelog();
}

static void
_pam_log(int err, int debug_p, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    _pam_vlog(err, debug_p, format, args);
    va_end(args);
}




/* generic file access
 * Returns 0 on failure, 1 on success
 * Iff a.type is Map, a.fd needs to be do_close'd later
 * Creating a file should create any necessary intermediate
 * directory structure, all with mode 700 (handled by umask :-).
 */
static int
do_file(action *a)
{
    char *p, *xauthpath, *path;

    setfsuid(user[a->context]);
    /* need enough space for expanded "$HOME/.xauth/<a->filename>" */
    path = alloca(strlen(home[a->context]) + strlen(a->filename) + 9);
    xauthpath = alloca(strlen(home[a->context]) + 9);
    if (!path || !xauthpath) {
	_pam_log(LOG_ERR|log_auth, 0, "do_file: out of memory");
	setfsuid(0); return 0;
    }

    sprintf(xauthpath, "%s/.xauth", home[a->context]);
    _pam_log(LOG_ERR, 1, "do_file: trying to create dir %s towards %s for %d",
	     xauthpath, a->filename, user[a->context]);
    if (mkdir(xauthpath, 0700) && errno != EEXIST) {
	_pam_log(LOG_ERR, 0, "do_file: could not create dir %s", xauthpath);
	setfsuid(0); return 0;
    }

    strcpy(path, xauthpath); strcat(path, "/"); strcat(path, a->filename);
    _pam_log(LOG_ERR, 1, "do_file: proceeding with file %s", path);
    if (a->type == Delete) {
	if (unlink(path)) {
	    _pam_log(LOG_ERR, 0, "do_file: could not delete %s", path);
	    setfsuid(0); return 0;
	}
	setfsuid(0); return 1;
    } else if (a->type == Exist) {
	if (stat(path, &a->sb)) {
	    _pam_log(LOG_ERR, 1, "do_file: could not find %s", path);
	    setfsuid(0); return 0;
	}
	_pam_log(LOG_ERR, 1, "do_file: found %s", path);
	setfsuid(0); return 1;
    }

    /* a->type must be Map */
    p = a->filename;
    while (*p) {
	while (p && (*p != '/') && (*p != '\0')) p++;
	if (*p == '/') {
	    strcpy(path, xauthpath); strcat(path, "/");
	    strncat(path, a->filename, (p)-a->filename);
	    if (mkdir(path, 0700) && errno != EEXIST) {
		_pam_log(LOG_ERR|log_auth, 0, "do_file: could not create dir %s", path);
		setfsuid(0); return 0;
	    } else {
		_pam_log(LOG_ERR, 1, "do_file: made intermediate dir %s", path);
	    }
	}
	if (*p) p++;
    }

    strcpy(path, xauthpath); strcat(path, "/"); strcat(path, a->filename);
    if (stat(path, &a->sb)) {
	_pam_log(LOG_ERR, 1, "do_file: could not find %s", path);
	if (a->size < 0) a->size *= -1;
	a->sb.st_size = 0;     /* set up for calculations */
	a->sb.st_blksize = 13; /* prime blocksize requests re-stat later */
    } else {
	if (a->size < 0) a->size = (a->size * -1) + a->sb.st_size;
	else            a->size = a->size > a->sb.st_size ? a->size : a->sb.st_size;
    }
    a->map_size = a->size+1; /* leave room for \0 */

    a->fd = open(path, a->level, 0600);
    if (a->fd < 0) {
	_pam_log(LOG_ERR|log_auth, 1, "do_file: could not open %s", path);
	setfsuid(0); return 0;
    }
    if ((a->sb.st_blksize == 13) && fstat(a->fd, &a->sb)) {
	_pam_log(LOG_ERR|log_auth, 0, "do_file: could not fstat %s", path);
	setfsuid(0); return 0;
    }
    if ((a->level & RdWr) || (a->level & WrOnly)) {
	/* writable map */
	_pam_log(LOG_ERR, 1, "readwrite map for %s", path);
	ftruncate(a->fd, a->map_size);
	a->data = mmap(NULL, a->map_size,
		      (a->level|RdWr) ? PROT_READ|PROT_WRITE : PROT_WRITE,
		      MAP_FILE|MAP_SHARED, a->fd, 0);
    } else {
	/* readonly map we will not expand the size no matter what */
	_pam_log(LOG_ERR, 1, "readonly map for %s", path);
	a->size = a->sb.st_size;
	a->map_size = a->size;
	a->data = mmap(NULL, a->map_size, PROT_READ, MAP_FILE|MAP_SHARED, a->fd, 0);
    }
    if (a->data == MAP_FAILED) {
	a->data = NULL;
	_pam_log(LOG_ERR|log_auth, 0, "do_file: could not mmap %s", path);
	setfsuid(0); return 0;
    }
    if ((a->level & RdWr) || (a->level & WrOnly)) {
	a->data[a->map_size-1] = '\0';
	if (a->sb.st_size < a->map_size)
	    a->data[a->sb.st_size] = '\0';
    }
    setfsuid(0);
    _pam_log(LOG_ERR, 1, "do_file: success for file %s", path);
    return 1;
}

static void
do_close(action a)
{
    _pam_log(LOG_ERR, 1, "do_close: a.size = %d, a.map_size = %d", a.size, a.map_size);
    setfsuid(user[a.context]);
    munmap(a.data, a.map_size);
    if ((a.level & RdWr) || (a.level & WrOnly)) {
	_pam_log(LOG_ERR, 1, "do_file: ftruncating to %d", a.size);
	ftruncate(a.fd, a.size);
    }
    close(a.fd);
    setfsuid(0);
}


/* looks for the user needle in the file haystack;
 * returns 1 on success, 0 on failure
 */
static int
find_user(user_context needle, action haystack)
{
    char *wordstart, *wordend;
    int  needlen, wordlen;

    _pam_log(LOG_ERR, 1, "find_user: looking for name %s in file %s",
	     name[needle], haystack.filename);
    needlen = strlen(name[needle]);
    wordstart = wordend = haystack.data;
    while (wordend < haystack.data+haystack.size) {
        if ((*wordstart == '*') &&
	    ((*(wordstart+1) == '\n') ||
	     (wordstart+1 >= haystack.data+haystack.size))) return 1;
	while ((*wordend != '\n') && (wordend < haystack.data+haystack.size))
	    wordend++;
	wordlen = wordend - wordstart;
	_pam_log(LOG_ERR, 1, "find_user: n = %d, w = %d", needlen, wordlen);
	if ((needlen == wordlen) &&
	    !strncmp(name[needle], wordstart, needlen)) {
	    _pam_log(LOG_ERR, 1, "find_user: found %s", name[needle]);
	    return 1;
	}
	if (wordend >= haystack.data+haystack.size) break;
	wordstart = ++wordend;
    }

    _pam_log(LOG_ERR, 1, "find_user: did not find %s", name[needle]);
    return 0;
}




/* run an xauth command securely
 * cannot use popen() because it does not setuid(getuid()) in the
 * child process before calling system()
 */
static void
call_xauth(char **data, user_context c, direction d, char *path, ...)
{
    int tube[2];
    int child, status;

    pipe(tube);
    if (!(child = fork())) {
	char *args[10]; /* known to be more than enough */
	int argindex;
	char *arg;
	va_list ap;
	va_start(ap, path); /* no va_end because we exec instead... */

	setuid(0);
	setuid(user[c]);
	_pam_log(LOG_ERR, 1, "call_xauth: setuid to %d for %s with %s %s",
		 user[c], path, d==Incoming ? "incoming" : "outgoing", display);

	/* modify the environment appropriately -- no need to sanitize
	 * because we are working only within an authenticated user
	 * environment -- user[c] is known to be authenticated at this
	 * stage
	 */
	setenv("HOME", home[c], 1);
	if (c == Source && xauthority && xauthority[0]) {
	    setenv("XAUTHORITY", xauthority, 1);
	}

	/* create the argvector */
	args[0] = path;
	arg = va_arg(ap, char *);
	for (argindex = 1; argindex < 9; argindex++) {
	    args[argindex] = arg;
	    if (arg) arg = va_arg(ap, char *);
	    else break;
	}
    
	if (d == Incoming) {
	    dup2(tube[1], STDOUT_FILENO);
	    close(STDIN_FILENO);
	    close(STDERR_FILENO);
	} else {
	    dup2(tube[0], STDIN_FILENO);
	    close(STDOUT_FILENO);
	    close(STDERR_FILENO);
	}
        close(tube[0]);
        close(tube[1]);
	execv(path, args);
	_pam_log(LOG_ERR|log_auth, 1, "call_xauth: execve failed for %s", path);
	_exit(1);
    }

    /* read/write output/input */
    if (d == Incoming) {
	int datasize = 256; /* enough for normal cookies */
	int sofar = 0;
	int charsread = 0;

	close(tube[1]);
	*data = malloc(datasize);
	if (!*data) {
	    _pam_log(LOG_ERR|log_auth, 0, "call_xauth: out of memory"); return;
	}
	*data[0] = '\0';
	charsread = sofar = read(tube[0], *data, datasize);
	while (charsread) {
	    if (sofar >= datasize-1) {
		datasize += 256;
		*data = realloc(*data, datasize);
		if (!*data) {
		    _pam_log(LOG_ERR|log_auth, 0, "call_xauth: out of memory");
		    return;
		}
	    }
	    charsread = read(tube[0], *data+sofar, datasize-sofar);
	    sofar += charsread;
	}
    } else {
	close(tube[0]);
	if (data && *data) write(tube[1], *data, strlen(*data));
	close(tube[1]);
    }

    wait(&status);
    if (WIFEXITED(status)) {
	if (WEXITSTATUS(status)) {
	    _pam_log(LOG_ERR|log_auth, 1, "call_xauth: child returned %d",
		     WEXITSTATUS(status));
	}
    } else {
	_pam_log(LOG_ERR|log_auth, 0, "call_xauth: child got signal %d",
		 WIFSIGNALED(status)?WTERMSIG(status):WSTOPSIG(status));
    }
    close(tube[0]);
    close(tube[1]);
}



/* return 0 means caller should export/purge
 * return -1 means caller should return immediately
 * return -2 means caller should return after updating refcount
 */
static int
_args_init(int argc, const char **argv, int *ret, pam_handle_t *pamh)
{
    struct passwd *pw;
    action a;

    /* step through arguments */
    for (; argc-- > 0; ++argv) {
        /* generic options */
        if (!strcmp(*argv, "debug")) {
	    debug = 1;
        } else if (!strcmp(*argv, "logpub")) {
	    log_auth = 0;
	} else if (!strncmp(*argv, "warndays=", 9)) {
	    ; /* ignore obsolete argument */
	} else if (!strncmp(*argv, "warnhours=", 10)) {
	    ; /* ignore obsolete argument */
	} else if (!strncmp(*argv, "systemuser=", 11)) {
	    systemuser = atoi(*argv+11);
	} else if (!strncmp(*argv, "xauthpath=", 10)) {
	    if (!xauth) xauth = strdup(*argv+10);
	    if (!xauth) {
		_pam_log(LOG_ERR|log_auth, 0, "_args_init: out of memory");
		*ret = PAM_SESSION_ERR; return -1;
	    }
	} else {
            _pam_log(LOG_ERR, 0, "_args_init: unknown option; %s",*argv);
        }
    }
    if (!xauth)
	(const char *) xauth = xauthdefpath; /* avoid silly warning */

    if (getenv("XAUTHORITY")) {
	xauthority = strdup(getenv("XAUTHORITY"));
	unsetenv("XAUTHORITY");
	_pam_log(LOG_ERR, 1, "_args_init: unset XAUTHORITY fm %s", xauthority);
    }

    if (!name[Source]) {
	char *loginname = getlogin();
	if (!loginname || !loginname[0]) {
	    _pam_log(LOG_ERR|log_auth, 1, "_args_init: getlogin failed");
	    pw = getpwuid(getuid());
	} else {
	    pw = getpwnam(loginname);
	}
	if (!pw) {
	    _pam_log(LOG_ERR|log_auth, 0, "_args_init: source user %s not found",
		     name[Source]);
	    *ret = PAM_SESSION_ERR; return -1;
	}
	name[Source] = strdup(pw->pw_name);
	user[Source] = pw->pw_uid;
	home[Source] = strdup(pw->pw_dir);
    }

    /* pam_get_user is really only for auth modules, not session modules */
    if (!name[Target]) pam_get_item(pamh, PAM_USER, CAST_ME_HARDER &name[Target]);
    if (!name[Target]) {
	_pam_log(LOG_ERR|log_auth, 0, "_args_init: no target user");
	*ret = PAM_SESSION_ERR; return -1;
    }
    if (!home[Target]) {
	pw = getpwnam(name[Target]);
	if (!pw) {
	    _pam_log(LOG_ERR|log_auth, 0, "_args_init: target user %s not found",
		     name[Target]);
	    *ret = PAM_SESSION_ERR; return -1;
	}
	user[Target] = pw->pw_uid;
	home[Target] = strdup(pw->pw_dir);
    }

    if (!home[Target] || !home[Source] || !name[Source]) {
	/* not that we'll be able to log in these circumstances, but... */
	_pam_log(LOG_ERR|log_auth, 0, "out of memory");
	*ret = PAM_SESSION_ERR; return -1;
    }

    if (user[Target] == user[Source]) {
	_pam_log(LOG_ERR, 1, "target = source = %s(%d)",
		 name[Source], user[Source]);
	*ret = PAM_SUCCESS; return -1;
    }

    if (user[Source] && user[Source] <= systemuser) {
	_pam_log(LOG_ERR, 1, "not touching system user %s(%d)",
		 name[Source], user[Source]);
	*ret = PAM_SUCCESS; return -1;
    }



    if (!display) {
	char *disptemp, *p;
	disptemp = getenv("DISPLAY");
	/* no need to sanitize $DISPLAY because it is used only in
	 * providing (source) user's context :-)
	 */
	if (!disptemp || (disptemp[0] == '\0')) {
	    _pam_log(LOG_ERR, 1, "_pam_xauth: $DISPLAY missing");
	    if (disptemp) free(disptemp);
	    *ret = PAM_SESSION_ERR; return -1;
	}
	/* use xauth to canonicalize $DISPLAY */
	call_xauth(&disptemp, Source, Incoming, xauth, "list", disptemp, NULL);
	if (!*disptemp) {
	    _pam_log(LOG_ERR, 1, "_pam_xauth: xauth missing display");
	    free(disptemp);
	    *ret = PAM_SESSION_ERR; return -1;
	}
	/* cut off the part we want */
	p = disptemp;
	while (*p && *p != ' ') p++;
	*p = '\0';
	display = strdup(disptemp);
	if (!display) {
	    _pam_log(LOG_ERR, 0, "_pam_xauth: out of memory");
	    *ret = PAM_SESSION_ERR; return -1;
	}
	_pam_log(LOG_ERR, 1, "canonical display name is %s", display);
	free(disptemp);
    }

    /* from this point on, we still want to manage reference counts even
     * in the case of failure, so that changes to config files do not
     * mess up reference counting.  Before this, there's not enough
     * data prepared to do reference counting.
     */

    a.context=Target; a.type=Map; a.level=RdOnly;
    (const char *) a.filename="import";
    a.size=0;

    if (do_file(&a)) {
	/* only allow if source is in the target's import file */
	if (!find_user(Source, a)) {
	    _pam_log(LOG_ERR, 1, "target user %s rejected source user %s",
		     name[Target], name[Source]);
	    *ret = PAM_SESSION_ERR;
	    do_close(a);
	    return -2;
	}
	do_close(a);
    } /* else unconditionally allowed */
    _pam_log(LOG_ERR, 1, "target user %s accepted source user %s",
	     name[Target], name[Source]);

    /* avoid silly const warning */
    a.context=Source; a.type=Map; a.level=RdOnly;
    (const char *) a.filename="export";
    a.size=0;
    
    if (do_file(&a)) {
	/* only allow if target is in the source's export file */
	if (!find_user(Target, a)) {
	    _pam_log(LOG_ERR, 1, "source user %s rejected target user %s",
		     name[Source], name[Target]);
	    *ret = PAM_SESSION_ERR;
	    do_close(a);
	    return -2;
	}
	do_close(a);
    } else {
	/* only allow if target is root */
	if (user[Target] != 0) {
	    _pam_log(LOG_ERR, 1, "source user %s implicitly rejected non-root target user %s",
		     name[Source], name[Target]);
	    *ret = PAM_SUCCESS; return -2;
	}
    }

    return 0;
}


/* change the reference count
 * returns -1 on failure, refcount on success
 */
static int
mangle_refcount(pam_handle_t *pamh, int increment, char *cookie)
{
    action a;
    int count;
    char *oldcookie;

    _pam_log(LOG_ERR, 1, "modify refcount by %d", increment);
    if (!name[Target] || !name[Source] || !display) return -1;

    /* "refcount/<name[Target]>/<display>" */
    a.filename=alloca(strlen(name[Target]) + strlen(display) + 12);
    if (!a.filename) {
	_pam_log(LOG_ERR|log_auth, 0, "mangle_refcount: out of memory");
	setfsuid(0); return 0;
    }
    sprintf(a.filename, "refcount/%s/%s", name[Target], display);
    a.context=Source;
    a.type=Map;
    a.level=RdWr|Create;
    /* refcount may need to be up to 1 character larger; may need to
       a trailing space and cookie if they aren't there to facilitate
       upgrades from old versions that didn't keep track of the cookie
       If !cookie, then this is a decrement and the size will not increase. */
    if (cookie) a.size = -(2+strlen(cookie));
    if (!do_file(&a)) {
	_pam_log(LOG_ERR|log_auth, 0, "could not open %s", a.filename);
	return -1;
    }

    if (!a.data[0]) count = 0;
    else count = atoi(a.data);
    count += increment;
    for (oldcookie = a.data; *oldcookie && *oldcookie != ' '; oldcookie++);
    if (*oldcookie == ' ') {
	oldcookie++;
	if (cookie) {
	    if (strncmp(oldcookie, cookie, strlen(cookie))) {
		count = 1;
	    }
	} else {
	    cookie = oldcookie;
	}
    }
    if (count <= 0) {
	a.type = Delete;
	do_file(&a);
    } else {
	if (!cookie)
	    (const char *) cookie = "placeholder"; /* avoid const warning */
	sprintf(a.data, "%d %s%n", count, cookie, &a.size);
    }

    do_close(a);
    _pam_log(LOG_ERR, 1, "returning refcount %d", count);
    return count;
}





PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int ret = PAM_SESSION_ERR;
    int willret = 0;
    char *key, *cookie_start = NULL, *cookie_end, *cookie;
    int mask;

    mask = umask(0077);

    willret = _args_init(argc, argv, &ret, pamh);
    if (willret == -1) { umask(mask); return ret; }

    call_xauth(&key, Source, Incoming,
	       xauth, "-iq", "nextract", "-", display, NULL);

    if (key[0]) {
	cookie_end = strchr(key, '\n');
	if (cookie_end) {
	    cookie_end[0] = '\0';
	} else {
	    cookie_end = key + strlen(key);
	}
	cookie_start = strrchr(key, ' ');
    }
    if (cookie_start && cookie_end && (cookie_start < cookie_end)) {
	/* copy cookie */
	cookie = alloca(cookie_end - cookie_start);
	cookie_start++; /* go past the space character */
	if (!cookie) {
	    _pam_log(LOG_ERR|log_auth, 0, "pam_sm_open_session: out of memory");
	    willret = -3; ret = PAM_SESSION_ERR;
	}
	strncpy(cookie, cookie_start, cookie_end-cookie_start);
	cookie[cookie_end-cookie_start] = '\0';

	if (mangle_refcount(pamh, 1, cookie) < 0) {
	    willret = -3; ret = PAM_SESSION_ERR;
	}
	if (willret >= 0) {
	    call_xauth(&key, Target, Outgoing, xauth, "nmerge", "-", NULL);
	    ret = PAM_SUCCESS;
	}
    }
    if (key) free(key);
    umask(mask);

    return ret;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int ret = PAM_SESSION_ERR;
    int refcount;
    int willret = 0;
    int mask;

    mask = umask(0077);

    willret = _args_init(argc, argv, &ret, pamh);
    if (willret == -1) { umask(mask); return ret; }
    refcount = mangle_refcount(pamh, -1, NULL);
    if (refcount < 0) { umask(mask); return PAM_SESSION_ERR; }
    if (willret < 0) { umask(mask); return ret; }

    if (!refcount)
	call_xauth(NULL, Target, Outgoing, xauth, "-q", "remove", display, NULL);
    ret = PAM_SUCCESS;
    umask(mask);

    return ret;
}


#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_xauth_modstruct = {
     "pam_xauth",
     NULL,
     NULL,
     NULL,
     pam_sm_open_session,
     pam_sm_close_session,
     NULL,
};

#endif

/*
 * Copyright Red Hat, Inc. 1999.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED `AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
