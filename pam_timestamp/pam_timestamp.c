/******************************************************************************
 * A module for Linux-PAM that will cache authentication results, inspired by
 * (and implemented with an eye toward being mixable with) sudo.
 *
 * Copyright (c) 2002 Red Hat, Inc.
 * Written by Nalin Dahyabhai <nalin@redhat.com>
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
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
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
 *
 */

#define PAM_SM_AUTH
#define PAM_SM_SESSION

#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define PAM_GETPWUID_R
#include "../../_pam_aconf.h"
#include "../../libpam/include/security/_pam_macros.h"
#include "../../libpam/include/security/pam_modules.h"

/* The default timeout we use is 5 minutes, which matches the sudo default
 * for the timestamp_timeout parameter. */
#define DEFAULT_TIMESTAMP_TIMEOUT (5 * 60)
#define MODULE "pam_timestamp"
#define TIMESTAMPDIR "/var/run/sudo"

static int
get_cache_name(pam_handle_t *pamh, int argc, const char **argv,
	       char *path, size_t len)
{
	const char *user, *ruser, *tty;
	const char *tdir = TIMESTAMPDIR;
	char scratch[LINE_MAX];
	char *buf = NULL;
	size_t bufsize = 0;
	struct passwd passwd, *pwd;
	int i, debug = 0;
	/* Parse arguments. */
	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "debug") == 0) {
			debug = 1;
		}
	}
	for (i = 0; i < argc; i++) {
		if (strncmp(argv[i], "timestampdir=", 13) == 0) {
			tdir = argv[i] + 13;
			if (debug) {
				syslog(LOG_DEBUG,
				       MODULE ": storing timestamps in `%s'",
				       tdir);
			}
		}
	}
	/* Get the name of the target user. */
	if (pam_get_item(pamh, PAM_USER, (const void**)&user) != PAM_SUCCESS) {
		user = NULL;
	}
	if ((user == NULL) || (strlen(user) == 0)) {
		return PAM_AUTH_ERR;
	}
	if (debug) {
		syslog(LOG_DEBUG, MODULE ": becoming user `%s'", user);
	}
	/* Get the name of the source user. */
	if (pam_get_item(pamh, PAM_RUSER, (const void**)&ruser) != PAM_SUCCESS) {
		ruser = NULL;
	}
	if ((ruser == NULL) || (strlen(ruser) == 0)) {
		/* Barring that, use the current RUID. */
		if (_pam_getpwuid_r(getuid(), &passwd, &buf, &bufsize, &pwd) == 0) {
			if (strlen(pwd->pw_name) < sizeof(scratch)) {
				strcpy(scratch, pwd->pw_name);
				ruser = scratch;
			}
			free(buf);
		}
	}
	if ((ruser == NULL) || (strlen(ruser) == 0)) {
		return PAM_AUTH_ERR;
	}
	if (debug) {
		syslog(LOG_DEBUG, MODULE ": currently user `%s'", ruser);
	}
	/* Get the name of the terminal. */
	if (pam_get_item(pamh, PAM_TTY, (const void**)&tty) != PAM_SUCCESS) {
		tty = NULL;
	}
	if ((tty == NULL) || (strlen(tty) == 0)) {
		tty = ttyname(STDIN_FILENO);
		if ((tty == NULL) || (strlen(tty) == 0)) {
			tty = ttyname(STDOUT_FILENO);
		}
		if ((tty == NULL) || (strlen(tty) == 0)) {
			tty = ttyname(STDERR_FILENO);
		}
	}
	if ((tty == NULL) || (strlen(tty) == 0)) {
		return PAM_AUTH_ERR;
	}
	if (debug) {
		syslog(LOG_DEBUG, MODULE ": tty is `%s'", tty);
	}
	/* Snip off all but the last part of the tty name. */
	if (strchr(tty, '/') != NULL) {
		tty = strrchr(tty, '/') + 1;
	}
	/* Make sure the tty isn't actually a directory. */
	if (strlen(tty) == 0) {
		return PAM_AUTH_ERR;
	}
	/* Generate the name of the file used to cache auth results. */
	if (strcmp(ruser, user) == 0) {
		if (snprintf(path, len, "%s/%s/%s",
			     tdir, user, tty) > len - 1) {
			return PAM_AUTH_ERR;
		}
	} else {
		if (snprintf(path, len, "%s/%s/%s:%s",
			     tdir, ruser, tty, user) > len - 1) {
			return PAM_AUTH_ERR;
		}
	}
	if (debug) {
		syslog(LOG_DEBUG, MODULE ": using timestamp file `%s'", path);
	}
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	struct stat st;
	time_t interval = DEFAULT_TIMESTAMP_TIMEOUT;
	int i, debug = 0;
	char path[PATH_MAX];
	const char *service = "(unknown)";
	time_t now;
	/* Parse arguments. */
	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "debug") == 0) {
			debug = 1;
		}
	}
	for (i = 0; i < argc; i++) {
		if (strncmp(argv[i], "timestamp_timeout=", 18) == 0) {
			interval = atol(argv[i] + 18);
			if (debug) {
				syslog(LOG_DEBUG,
				       MODULE ": setting timeout to %ld seconds",
				       (long)interval);
			}
		}
	}
	/* Get the name of the cache. */
	if (get_cache_name(pamh, argc, argv,
			   path, sizeof(path)) != PAM_SUCCESS) {
		return PAM_AUTH_ERR;
	}
	/* Get the name of the service. */
	if (pam_get_item(pamh, PAM_SERVICE, (const void**)&service) != PAM_SUCCESS) {
		service = NULL;
	}
	if ((service == NULL) || (strlen(service) == 0)) {
		service = "(unknown)";
	}
	/* Check the date on the file. */
	if (lstat(path, &st) == 0) {
		/* Check that the file is a normal file. */
		if (!(S_ISREG(st.st_mode))) {
			syslog(LOG_ERR, MODULE ": timestamp file `%s' is "
			       "not a regular file", path);
			return PAM_AUTH_ERR;
		}
		/* Compare the dates. */
		now = time(NULL);
		if ((now - st.st_mtime) < interval) {
			syslog(LOG_NOTICE, MODULE ": timestamp file `%s' is "
			       "only %ld seconds old, allowing access to %s "
			       "for %ld", path, now - st.st_mtime,
			       service, (long)getuid());
			return PAM_SUCCESS;
		} else {
			syslog(LOG_NOTICE, MODULE ": timestamp file `%s' is "
			       "too old, disallowing access to %s for %ld",
			       path, service, (long)getuid());
			return PAM_AUTH_ERR;
		}
	}
	/* Fail by default. */
	return PAM_AUTH_ERR;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	struct stat st;
	char path[PATH_MAX], subdir[PATH_MAX];
	int fd, i, debug = 0;
	/* Parse arguments. */
	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "debug") == 0) {
			debug = 1;
		}
	}
	/* Get the name of the cache. */
	if (get_cache_name(pamh, argc, argv,
			   path, sizeof(path)) != PAM_SUCCESS) {
		return PAM_SESSION_ERR;
	}
	/* Create a cache file if it doesn't already exist. */
	for (i = 1; path[i] != '\0'; i++) {
		if (path[i] == '/') {
			/* Check for the existence of a directory. */
			strncpy(subdir, path, i);
			subdir[i] = '\0';
			if ((stat(subdir, &st) == -1) && (errno == ENOENT)) {
				if (mkdir(subdir, 0700) != 0) {
					if (debug) {
						syslog(LOG_DEBUG,
						       MODULE ": created "
						       "directory `%s'",
						       subdir);
					}
					return PAM_SESSION_ERR;
				}
			}
		}
	}
	/* Open the file. */
	fd = open(path, O_WRONLY | O_CREAT, 0600);
	if (fd == -1) {
		syslog(LOG_ERR, MODULE ": unable to open `%s': %m", path);
		return PAM_SESSION_ERR;
	}
	/* Write a single byte to the file, and then truncate it. */
	if (write(fd, path, 1) != 1) {
		syslog(LOG_ERR, MODULE ": unable to write to `%s': %m", path);
		close(fd);
		return PAM_SESSION_ERR;
	}
	if (ftruncate(fd, 0) != 0) {
		syslog(LOG_ERR, MODULE ": unable to write to `%s': %m", path);
		close(fd);
		return PAM_SESSION_ERR;
	}
	/* Close the file and return successfully. */
	close(fd);
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}
