/* pam_xauth module */

/*
 * Written by Michael K. Johnson <johnsonm@redhat.com> 1999/04/10
 * A few functions loosely based on functions from Cristian Gafton's
 * pam_wheel module.  Others are loosely based on pam_console by
 * Michael K. Johnson.
 */

#include <_pam_aconf.h>

#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
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

#ifndef MAP_FAILED
#define MAP_FAILED -1
#endif

#define COOKIE_PLACEHOLDER "placeholderplaceholder"

enum user_context {
  SourceUser = 0,
  TargetUser = 1,
};

enum access_type {
  Map,
  Delete,
};

enum access_level {
  RdOnly = O_RDONLY,
  WrOnly = O_WRONLY,
  RdWr   = O_RDWR,
  Create = O_CREAT,
};

struct action {
  enum user_context context;
  enum access_type  type;
  enum access_level level;
  char *filename; /* always relative to .xauth subdirectory in home directory */
  char *data;
  int size;      /* maximum size for newly-created file */
  int map_size;  /* size actually mapped, private to do_file and do_close */
  int fd;
  struct stat sb;
};

enum direction {
  reading = 0,
  writing = 1,
};

static int debug = 0;
static int log_facility = LOG_AUTHPRIV;
static int systemuser = 99;
static char *xauthority = NULL;
static const char *xauthdefpath = "/usr/X11R6/bin/xauth";
static char *xauth = NULL;
static char *display = NULL;
static char *name[2] = {NULL, NULL};
static char *home[2] = {NULL, NULL};
static uid_t user[2] = {0, 0};
static gid_t group[2] = {0, 0};

/* some syslogging */
static void
_pam_log(int err, const char *format, ...)
{
    va_list args;

    if ((err == LOG_DEBUG) && !debug) return;

    va_start(args, format);
    openlog("pam_xauth", LOG_CONS|LOG_PID, log_facility);
    vsyslog(err, format, args);
    closelog();
    va_end(args);
}

/* generic file access
 * Returns 0 on failure, 1 on success
 * Iff action.type is Map, action.fd needs to be do_close'd later
 * Creating a file should create any necessary intermediate
 * directory structure, all with mode 700 (handled by umask :-).
 */
static int
do_file(struct action *action)
{
    char *p, *xauthpath, *path;
    int restat;

    setfsuid(user[action->context]);
    /* need enough space for expanded "$HOME/.xauth/<action->filename>" */
    path = alloca(strlen(home[action->context]) + sizeof("/.xauth/") +
		  strlen(action->filename) + 1);
    xauthpath = alloca(strlen(home[action->context]) + sizeof("/.xauth") + 1);
    if (!path || !xauthpath) {
	_pam_log(LOG_ERR, "do_file: out of memory");
	setfsuid(0); return 0;
    }

    sprintf(xauthpath, "%s/.xauth", home[action->context]);
    _pam_log(LOG_DEBUG, "do_file: trying to create dir %s towards %s for %d",
	     xauthpath, action->filename, user[action->context]);
    if ((mkdir(xauthpath, 0700) == -1) && (errno != EEXIST)) {
	_pam_log(LOG_ERR, "do_file: could not create dir %s", xauthpath);
	setfsuid(0); return 0;
    }

    strcpy(path, xauthpath);
    strcat(path, "/");
    strcat(path, action->filename);
    _pam_log(LOG_DEBUG, "do_file: proceeding with file %s", path);

    /* if action->type is Delete, nuke the file */
    if (action->type == Delete) {
	if (unlink(path)) {
	    _pam_log(LOG_ERR, "do_file: could not delete %s", path);
	    setfsuid(0); return 0;
	}
	setfsuid(0); return 1;
    }

    /* action->type must be Map; create any intermediate directories */
    p = action->filename;
    while (*p) {
	while (p && (*p != '/') && (*p != '\0')) p++;
	if (*p == '/') {
	    strcpy(path, xauthpath);
	    strcat(path, "/");
	    strncat(path, action->filename, p - action->filename);
	    if (mkdir(path, 0700) && errno != EEXIST) {
		_pam_log(LOG_ERR, "do_file: could not create dir %s", path);
		setfsuid(0); return 0;
	    } else {
		_pam_log(LOG_DEBUG, "do_file: made intermediate dir %s", path);
	    }
	}
	if (*p) p++;
    }

    restat = 0;
    strcpy(path, xauthpath);
    strcat(path, "/");
    strcat(path, action->filename);
    if (stat(path, &action->sb) == -1) {
	_pam_log(LOG_DEBUG, "do_file: could not find %s", path);
	restat = 1;
    } else {
     	action->size = (action->size > action->sb.st_size) ? action->size : action->sb.st_size;
    }
    action->map_size = action->size+1; /* leave room for \0 */

    action->fd = open(path, action->level, 0600);
    if (action->fd == -1) {
	_pam_log(LOG_DEBUG, "do_file: could not open %s", path);
	setfsuid(0); return 0;
    }
    if (restat && fstat(action->fd, &action->sb)) {
	_pam_log(LOG_ERR, "do_file: could not fstat %s", path);
	setfsuid(0); return 0;
    }
    if ((action->level & RdWr) || (action->level & WrOnly)) {
	/* writable map */
	_pam_log(LOG_DEBUG, "readwrite map for %s", path);
	ftruncate(action->fd, action->map_size);
	action->data = mmap(NULL, action->map_size,
		      (action->level|RdWr) ? PROT_READ|PROT_WRITE : PROT_WRITE,
		      MAP_FILE|MAP_SHARED, action->fd, 0);
    } else {
	/* readonly map we will not expand the size no matter what */
	_pam_log(LOG_DEBUG, "readonly map for %s", path);
	action->map_size = action->size = action->sb.st_size;
	action->data = mmap(NULL, action->map_size, PROT_READ, MAP_FILE|MAP_SHARED, action->fd, 0);
    }
    if (action->data == MAP_FAILED) {
	action->data = NULL;
	_pam_log(LOG_ERR, "do_file: could not mmap %s", path);
	setfsuid(0); return 0;
    }
    if ((action->level & RdWr) || (action->level & WrOnly)) {
	action->data[action->map_size-1] = '\0';
	if (action->sb.st_size < action->map_size)
	    action->data[action->sb.st_size] = '\0';
    }
    setfsuid(0);
    _pam_log(LOG_DEBUG, "do_file: success for file %s", path);
    return 1;
}

static void
do_close(struct action action)
{
    _pam_log(LOG_DEBUG, "do_close: action.size = %d, action.map_size = %d", action.size, action.map_size);
    setfsuid(user[action.context]);
    munmap(action.data, action.map_size);
    if ((action.level & RdWr) || (action.level & WrOnly)) {
	_pam_log(LOG_DEBUG, "do_file: ftruncating to %d", action.size);
	ftruncate(action.fd, action.size);
    }
    close(action.fd);
    setfsuid(0);
}

/* looks for the user needle in the file haystack;
 * returns 1 on success, 0 on failure
 */
static int
find_user(enum user_context needle, struct action haystack)
{
    char *wordstart, *wordend;
    int  needlen, wordlen;

    _pam_log(LOG_DEBUG, "find_user: looking for name %s in file %s",
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
	_pam_log(LOG_DEBUG, "find_user: n = %d, w = %d", needlen, wordlen);
	if ((needlen == wordlen) &&
	    !strncmp(name[needle], wordstart, needlen)) {
	    _pam_log(LOG_DEBUG, "find_user: found %s", name[needle]);
	    return 1;
	}
	if (wordend >= haystack.data+haystack.size) break;
	wordstart = ++wordend;
    }

    _pam_log(LOG_DEBUG, "find_user: did not find %s", name[needle]);
    return 0;
}




/* run an xauth command securely
 * cannot use popen() because it does not setuid(getuid()) in the
 * child process before calling system()
 */
static void
call_xauth(char **data, enum user_context c, enum direction direction, char *path, ...)
{
    int tube[2];
    int status;
    pid_t child_pid;

    pipe(tube);

    child_pid = fork();

    /* catch any fork() errors */
    if (child_pid == -1) {
	_pam_log(LOG_ERR, "call_xauth: fork error"); return;
    }

    if (child_pid == 0) {
	char *args[10]; /* known to be more than enough */
	int argindex;
	char *arg;
	va_list ap;
	va_start(ap, path); /* no va_end because we exec instead... */

	setuid(0);
	setgroups(0, NULL);
	setgid(group[c]);
	setreuid(user[c], user[c]);

	/* modify the environment appropriately -- no need to sanitize
	 * because we are working only within an authenticated user
	 * environment -- user[c] is known to be authenticated at this
	 * stage
	 */
	setenv("HOME", home[c], 1);
	if ((c == SourceUser) && xauthority && xauthority[0]) {
	    setenv("XAUTHORITY", xauthority, 1);
	}
	_pam_log(LOG_DEBUG, "call_xauth: setuid to %d for %s with %s, "
		 "DISPLAY = `%s', HOME = `%s', and XAUTHORITY = `%s'",
		 user[c], (direction == reading) ? "reading" : "writing", path,
		 display ?: "(null)",
		 getenv("HOME") ?: "(null)",
		 getenv("XAUTHORITY") ?: "(null)");

	/* create the argvector */
	memset(args, 0, sizeof(args));
	args[0] = path;
	for(argindex = 1; (arg = va_arg(ap, char *)) && (argindex < 9); argindex++) {
	    args[argindex] = arg;
	}
    
	if (direction == reading) {
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
	_pam_log(LOG_DEBUG, "call_xauth: execve failed for %s", path);
	_exit(1);
    }

    /* read/write output/input */
    if (direction == reading) {
	int datasize = 256; /* enough for normal cookies */
	int sofar = 0;
	int charsread = 0;

	close(tube[1]);
	*data = malloc(datasize);
	if (!*data) {
	    _pam_log(LOG_ERR, "call_xauth: out of memory"); return;
	}
	*data[0] = '\0';
	charsread = sofar = read(tube[0], *data, datasize);
	while (charsread > 0) {
	    if (sofar >= datasize-1) {
		datasize += 256;
		*data = realloc(*data, datasize);
		if (!*data) {
		    _pam_log(LOG_ERR, "call_xauth: out of memory");
		    return;
		}
		memset(*data + sofar, 0, datasize - sofar);
	    }
	    charsread = read(tube[0], *data+sofar, datasize-sofar);
	    if(charsread > 0) {
		sofar += charsread;
	    }
	}
	_pam_log(LOG_DEBUG, "call_xauth: read %d bytes", sofar);
    } else {
	close(tube[0]);
	if (data && *data) write(tube[1], *data, strlen(*data));
	close(tube[1]);
    }

    waitpid(child_pid, &status, 0);
    if (WIFEXITED(status)) {
	_pam_log(LOG_DEBUG, "call_xauth: child returned %d",
		 WEXITSTATUS(status));
    } else {
	_pam_log(LOG_ERR, "call_xauth: child got signal %d",
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
    struct passwd *pw = NULL, pwd;
    char ubuf[LINE_MAX];
    struct action action;

    memset(&action, 0, sizeof(action));

    /* step through arguments */
    for (; argc-- > 0; ++argv) {
        /* generic options */
        if (!strcmp(*argv, "debug")) {
	    debug = 1;
        } else if (!strcmp(*argv, "logpub")) {
	    log_facility = LOG_DAEMON;
	} else if (!strncmp(*argv, "warndays=", 9)) {
	    ; /* ignore obsolete argument */
	} else if (!strncmp(*argv, "warnhours=", 10)) {
	    ; /* ignore obsolete argument */
	} else if (!strncmp(*argv, "systemuser=", 11)) {
	    systemuser = atoi(*argv+11);
	} else if (!strncmp(*argv, "xauthpath=", 10)) {
	    if (!xauth) xauth = strdup(*argv+10);
	    if (!xauth) {
		_pam_log(LOG_ERR, "_args_init: out of memory");
		*ret = PAM_SESSION_ERR; return -1;
	    }
	} else {
            _pam_log(LOG_ERR, "_args_init: unknown option; %s",*argv);
        }
    }
    if (!xauth)
	(const char *) xauth = xauthdefpath; /* avoid silly warning */

    if (getenv("XAUTHORITY")) {
	xauthority = strdup(getenv("XAUTHORITY"));
	unsetenv("XAUTHORITY");
	_pam_log(LOG_DEBUG, "_args_init: unset XAUTHORITY (was %s)", xauthority);
    } else {
	_pam_log(LOG_DEBUG, "_args_init: XAUTHORITY not set");
    }

    if (!name[SourceUser]) {
	if (getpwuid_r(getuid(), &pwd, ubuf, sizeof(ubuf), &pw) != 0)
	    pw = NULL;
	if (pw == NULL) {
	    _pam_log(LOG_ERR, "_args_init: source user not found");
	    *ret = PAM_SESSION_ERR; return -1;
	}
	name[SourceUser] = strdup(pw->pw_name);
	user[SourceUser] = pw->pw_uid;
	group[SourceUser] = pw->pw_gid;
	home[SourceUser] = strdup(pw->pw_dir);
    }

    /* pam_get_user is really only for auth modules, not session modules */
    if (!name[TargetUser]) pam_get_item(pamh, PAM_USER, CAST_ME_HARDER &name[TargetUser]);
    if (!name[TargetUser]) {
	_pam_log(LOG_ERR, "_args_init: no target user");
	*ret = PAM_SESSION_ERR; return -1;
    }
    if (!home[TargetUser]) {
	if (getpwnam_r(name[TargetUser], &pwd, ubuf, sizeof(ubuf), &pw) != 0)
	    pw = NULL;
	if (pw == NULL) {
	    _pam_log(LOG_ERR, "_args_init: target user %s not found",
		     name[TargetUser]);
	    *ret = PAM_SESSION_ERR; return -1;
	}
	user[TargetUser] = pw->pw_uid;
	group[TargetUser] = pw->pw_gid;
	home[TargetUser] = strdup(pw->pw_dir);
    }

    if (!home[TargetUser] || !home[SourceUser] || !name[SourceUser]) {
	/* not that we'll be able to log in these circumstances, but... */
	_pam_log(LOG_ERR, "out of memory");
	*ret = PAM_SESSION_ERR; return -1;
    }

    if (user[TargetUser] == user[SourceUser]) {
	_pam_log(LOG_DEBUG, "target = source = %s(%d), nothing to do",
		 name[SourceUser], user[SourceUser]);
	*ret = PAM_SUCCESS; return -1;
    }

    if ((user[SourceUser] != 0) && (user[SourceUser] <= systemuser)) {
	_pam_log(LOG_DEBUG, "not touching system user %s(%d)",
		 name[SourceUser], user[SourceUser]);
	*ret = PAM_SUCCESS; return -1;
    }

    if (!display) {
	char *disptemp = NULL, *p = NULL;
	/* no need to sanitize $DISPLAY because it is used only in
	 * providing (source) user's context :-)
	 */
	p = getenv("DISPLAY");
	if (!p || (p[0] == '\0')) {
	    _pam_log(LOG_DEBUG, "_pam_xauth: $DISPLAY missing");
	    *ret = PAM_SESSION_ERR; return -1;
	}
	/* use xauth to canonicalize $DISPLAY */
	call_xauth(&disptemp, SourceUser, reading, xauth, "list", p, NULL);
	if (!disptemp || !*disptemp) {
	    _pam_log(LOG_DEBUG, "_pam_xauth: xauth missing display");
	    if(disptemp) free(disptemp);
	    *ret = PAM_SESSION_ERR; return -1;
	}
	/* cut off the part we want */
	p = disptemp;
	while (*p && *p != ' ') p++;
	*p = '\0';
	display = strdup(disptemp);
	if (!display) {
	    _pam_log(LOG_ERR, "_pam_xauth: out of memory");
	    *ret = PAM_SESSION_ERR; return -1;
	}
	_pam_log(LOG_DEBUG, "canonical display name is %s", display);
	free(disptemp);
    }

    /* from this point on, we still want to manage reference counts even
     * in the case of failure, so that changes to config files do not
     * mess up reference counting.  Before this, there's not enough
     * data prepared to do reference counting.
     */

    action.context=TargetUser;
    action.type=Map;
    action.level=RdOnly;
    action.size=0;
    (const char *) action.filename="import";

    if (do_file(&action)) {
	/* only allow if source is in the target's import file */
	if (!find_user(SourceUser, action)) {
	    _pam_log(LOG_DEBUG, "target user %s rejects cookies from source user %s",
		     name[TargetUser], name[SourceUser]);
	    *ret = PAM_SESSION_ERR;
	    do_close(action);
	    return -2;
	}
	do_close(action);
    } /* else unconditionally allowed */
    _pam_log(LOG_DEBUG, "target user %s accepts cookies from source user %s",
	     name[TargetUser], name[SourceUser]);

    /* avoid silly const warning */
    action.context=SourceUser;
    action.type=Map;
    action.level=RdOnly;
    action.size=0;
    (const char *) action.filename="export";
    
    if (do_file(&action)) {
	/* only allow if target is in the source's export file */
	if (!find_user(TargetUser, action)) {
	    _pam_log(LOG_DEBUG, "source user %s withholds cookies from target user %s",
		     name[SourceUser], name[TargetUser]);
	    *ret = PAM_SESSION_ERR;
	    do_close(action);
	    return -2;
	}
	do_close(action);
    } else {
	/* only allow if target is root */
	if (user[TargetUser] != 0) {
	    _pam_log(LOG_DEBUG, "source user %s implicitly withholds cookies from non-root target user %s",
		     name[SourceUser], name[TargetUser]);
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
    struct action action;
    int count;
    char *oldcookie;

    memset(&action, 0, sizeof(action));

    _pam_log(LOG_DEBUG, "modify refcount by %d", increment);
    if (!name[TargetUser] || !name[SourceUser] || !display) return -1;

    /* "refcount/<name[TargetUser]>/<display>" */
    action.filename=alloca(strlen("refcount/") + strlen(name[TargetUser]) + 1 + strlen(display) + 1);
    if (!action.filename) {
	_pam_log(LOG_ERR, "mangle_refcount: out of memory");
	setfsuid(0); return 0;
    }
    sprintf(action.filename, "refcount/%s/%s", name[TargetUser], display);
    action.context=SourceUser;
    action.type=Map;
    action.level=RdWr|Create;

    /* make sure that a created file is big enough for the cookie, if we were
     * passed one -- note that we need to calculate a minimum size which can
     * hold the string created with snprintf() below */
    action.size = strlen("0") + 1 + strlen(cookie ?: COOKIE_PLACEHOLDER) + 1;
    if (!do_file(&action)) {
	_pam_log(LOG_ERR, "could not open %s", action.filename);
	return -1;
    }

    count = atoi(action.data);
    count += increment;
    for (oldcookie = action.data; *oldcookie && *oldcookie != ' '; oldcookie++);
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
	action.type = Delete;
	do_file(&action);
    } else {
	snprintf(action.data, action.size, "%d %s%n", count, cookie ?: COOKIE_PLACEHOLDER, &action.size);
    }

    do_close(action);
    _pam_log(LOG_DEBUG, "returning refcount %d", count);
    return count;
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int ret = PAM_SESSION_ERR;
    int willret = 0;
    char *key, *cookie_start = NULL, *cookie_end = NULL, *cookie;
    int mask;

    mask = umask(0077);

    willret = _args_init(argc, argv, &ret, pamh);
    if (willret == -1) { umask(mask); return ret; }

    call_xauth(&key, SourceUser, reading,
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
	    _pam_log(LOG_ERR, "pam_sm_open_session: out of memory");
	    willret = -3; ret = PAM_SESSION_ERR;
	}
	strncpy(cookie, cookie_start, cookie_end-cookie_start);
	cookie[cookie_end-cookie_start] = '\0';

	if (mangle_refcount(pamh, 1, cookie) < 0) {
	    willret = -3; ret = PAM_SESSION_ERR;
	}
	if (willret >= 0) {
	    call_xauth(&key, TargetUser, writing, xauth, "nmerge", "-", NULL);
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

    if (refcount == 0)
	call_xauth(NULL, TargetUser, writing, xauth, "-q", "remove", display, NULL);
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
