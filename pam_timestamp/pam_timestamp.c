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
#include <signal.h>
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

/* Return PAM_SUCCESS if the given directory looks "safe". */
static int
check_dir_perms(const char *tdir)
{
	char scratch[PATH_MAX];
	struct stat st;
	int i;
	/* Check that the directory is "safe". */
	if ((tdir == NULL) || (strlen(tdir) == 0)) {
		return PAM_AUTH_ERR;
	}
	/* Iterate over the path, checking intermediate directories. */
	memset(scratch, 0, sizeof(scratch));
	for (i = 0; (tdir[i] != '\0') && (i < sizeof(scratch)); i++) {
		scratch[i] = tdir[i];
		if ((scratch[i] == '/') || (tdir[i + 1] == '\0')) {
			/* We now have the name of a directory in the path, so
			 * we need to check it. */
			if ((lstat(scratch, &st) == -1) && (errno != ENOENT)) {
				syslog(LOG_ERR,
				       MODULE ": unable to read `%s'",
				       scratch);
				return PAM_AUTH_ERR;
			}
			if (!S_ISDIR(st.st_mode)) {
				syslog(LOG_ERR,
				       MODULE ": `%s' is not a directory",
				       scratch);
				return PAM_AUTH_ERR;
			}
			if (S_ISLNK(st.st_mode)) {
				syslog(LOG_ERR,
				       MODULE ": `%s' is a symbolic link",
				       scratch);
				return PAM_AUTH_ERR;
			}
			if (st.st_uid != 0) {
				syslog(LOG_ERR,
				       MODULE ": `%s' owner UID != 0",
				       scratch);
				return PAM_AUTH_ERR;
			}
			if (st.st_gid != 0) {
				syslog(LOG_ERR,
				       MODULE ": `%s' owner GID != 0",
				       scratch);
				return PAM_AUTH_ERR;
			}
			if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
				syslog(LOG_ERR,
				       MODULE ": `%s' permissions are lax",
				       scratch);
				return PAM_AUTH_ERR;
			}
		}
	}
	return PAM_SUCCESS;
}

/* Validate a tty pathname as actually belonging to a tty, and return its base
 * name if it's valid. */
static const char *
check_tty(const char *tty)
{
	struct stat st;
	/* Check that we're not being set up to take a fall. */
	if ((tty == NULL) || (strlen(tty) == 0)) {
		return NULL;
	}
	/* Make sure the tty isn't a directory. */
	if (lstat(tty, &st) == -1) {
		return NULL;
	}
	/* Make sure it's a special. */
	if (!S_ISCHR(st.st_mode)) {
		return NULL;
	}
	/* Pull out the meaningful part of the tty's name. */
	if (strchr(tty, '/') != NULL) {
		tty = strrchr(tty, '/') + 1;
	}
	/* Make sure the tty wasn't actually a directory. */
	if (strlen(tty) == 0) {
		return NULL;
	}
	return tty;
}

/* Determine the right path name for a given user's timestamp. */
static int
format_timestamp_name(char *path, size_t len,
		      const char *timestamp_dir,
		      const char *tty,
		      const char *ruser,
		      const char *user)
{
	if (strcmp(ruser, user) == 0) {
		return snprintf(path, len, "%s/%s/%s", timestamp_dir,
				ruser, tty);
	} else {
		return snprintf(path, len, "%s/%s/%s:%s", timestamp_dir,
				ruser, tty, user);
	}
}

/* Check if a given timestamp date, when compared to a current time, fits
 * within the given interval. */
static int
timestamp_good(time_t then, time_t now, time_t interval)
{
	if (((now > then) && ((now - then) < interval)) ||
	    ((now < then) && ((then - now) < (2 * interval)))) {
		return PAM_SUCCESS;
	}
	return PAM_AUTH_ERR;
}

#ifndef PAM_TIMESTAMP_MAIN
/* Get the path to the timestamp to use. */
static int
get_timestamp_name(pam_handle_t *pamh, int argc, const char **argv,
		   char *path, size_t len)
{
	const char *user, *ruser, *tty;
	const char *tdir = TIMESTAMPDIR;
	char scratch[LINE_MAX > PATH_MAX ? LINE_MAX : PATH_MAX];
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
	i = check_dir_perms(tdir);
	if (i != PAM_SUCCESS) {
		return i;
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
	tty = check_tty(tty);
	if (tty == NULL) {
		return PAM_AUTH_ERR;
	}
	/* Generate the name of the file used to cache auth results.  These
	 * paths should jive with sudo's per-tty naming scheme. */
	if (format_timestamp_name(path, len, tdir, tty, ruser, user) >= len) {
		return PAM_AUTH_ERR;
	}
	if (debug) {
		syslog(LOG_DEBUG, MODULE ": using timestamp file `%s'", path);
	}
	return PAM_SUCCESS;
}

/* Tell the user that access has been granted. */
static void
verbose_success(pam_handle_t *pamh, int debug, int diff)
{
	struct pam_conv *conv;
	char text[LINE_MAX];
	struct pam_message message;
	const struct pam_message *messages[] = {&message};
	struct pam_response *responses;
	if (pam_get_item(pamh, PAM_CONV, (const void**) &conv) == PAM_SUCCESS) {
		if (conv->conv != NULL) {
			memset(&message, 0, sizeof(message));
			message.msg_style = PAM_TEXT_INFO;
			snprintf(text, sizeof(text),
				 "Access granted (last access was %d "
				 "seconds ago).", diff);
			message.msg = text;
			syslog(LOG_DEBUG, MODULE ": %s", message.msg);
			conv->conv(1, messages, &responses, conv->appdata_ptr);
		} else {
			syslog(LOG_DEBUG, MODULE ": bogus conversation function");
		}
	} else {
		syslog(LOG_DEBUG, MODULE ": no conversation function");
	}
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	struct stat st;
	time_t interval = DEFAULT_TIMESTAMP_TIMEOUT;
	int i, debug = 0, verbose = 0;
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
		} else
		if (strcmp(argv[i], "verbose") == 0) {
			verbose = 1;
			if (debug) {
				syslog(LOG_DEBUG,
				       MODULE ": becoming more verbose");
			}
		}
	}
	/* Get the name of the timestamp file. */
	if (get_timestamp_name(pamh, argc, argv,
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
		/* Check that the file is owned by the superuser. */
		if ((st.st_uid != 0) || (st.st_gid != 0)) {
			syslog(LOG_ERR, MODULE ": timestamp file `%s' is "
			       "not owned by root", path);
			return PAM_AUTH_ERR;
		}
		/* Check that the file is a normal file. */
		if (!(S_ISREG(st.st_mode))) {
			syslog(LOG_ERR, MODULE ": timestamp file `%s' is "
			       "not a regular file", path);
			return PAM_AUTH_ERR;
		}
		/* Compare the dates. */
		now = time(NULL);
		if (timestamp_good(st.st_mtime, now, interval) == PAM_SUCCESS) {
			syslog(LOG_NOTICE, MODULE ": timestamp file `%s' is "
			       "only %ld seconds old, allowing access to %s "
			       "for UID %ld", path, now - st.st_mtime,
			       service, (long)getuid());
			if (verbose) {
				verbose_success(pamh, debug, now - st.st_mtime);
			}
			return PAM_SUCCESS;
		} else {
			syslog(LOG_NOTICE, MODULE ": timestamp file `%s' is "
			       "too old, disallowing access to %s for UID %ld",
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
	/* Get the name of the timestamp file. */
	if (get_timestamp_name(pamh, argc, argv,
			       path, sizeof(path)) != PAM_SUCCESS) {
		return PAM_SESSION_ERR;
	}
	/* Create a timestamp file if it doesn't already exist. */
	for (i = 1; path[i] != '\0'; i++) {
		if (path[i] == '/') {
			/* Check for the existence of a directory. */
			strncpy(subdir, path, i);
			subdir[i] = '\0';
			if ((stat(subdir, &st) == -1) && (errno == ENOENT)) {
				if (mkdir(subdir, 0700) != 0) {
					if (debug) {
						syslog(LOG_DEBUG,
						       MODULE ": error creating"
						       " directory `%s': %s",
						       subdir, strerror(errno));
					}
					return PAM_SESSION_ERR;
				}
				/* Attempt to set the owner to the superuser. */
				lchown(subdir, 0, 0);
			}
		}
	}
	/* Open the file. */
	fd = open(path, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		syslog(LOG_ERR, MODULE ": unable to open `%s': %m", path);
		return PAM_SESSION_ERR;
	}
	/* Attempt to set the owner to the superuser. */
	fchown(fd, 0, 0);
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
	syslog(LOG_DEBUG, MODULE ": updated timestamp file `%s'", path);
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}

#else /* PAM_TIMESTAMP_MAIN */

#define USAGE "Usage: %s [[-k] | [-d]] [target user]\n"
#define CHECK_INTERVAL 5

int
main(int argc, char **argv)
{
	int i, pretval = -1, retval = 0, dflag = 0, kflag = 0;
	const char *target_user = NULL, *user = NULL, *tty = NULL;
	struct passwd *pwd;
	struct timeval tv;
	fd_set write_fds;
	char path[PATH_MAX];
	struct stat st;

	while ((i = getopt(argc, argv, "dk")) != -1) {
		switch (i) {
			case 'd':
				dflag++;
				break;
			case 'k':
				kflag++;
				break;
			default:
				fprintf(stderr, USAGE, argv[0]);
				return 1;
				break;
		}
	}

	/* Bail if both -k and -d are given together. */
	if ((kflag + dflag) > 1) {
		fprintf(stderr, USAGE, argv[0]);
		return 1;
	}

	/* Check that we're setuid. */
	if (geteuid() != 0) {
		fprintf(stderr, "%s must be setuid root\n",
			argv[0]);
		retval = 2;
	}

	/* Check that we have a controlling tty. */
	tty = ttyname(STDIN_FILENO);
	if (tty == NULL) {
		fprintf(stderr, "no controlling tty\n");
		retval = 3;
	}

	/* Get the name of the invoking (requesting) user. */
	pwd = getpwuid(getuid());
	if (pwd == NULL) {
		retval = 4;
	}

	/* Get the name of the target user. */
	user = strdup(pwd->pw_name);
	target_user = (optind < argc) ? argv[optind] : user;
	if ((strchr(target_user, '.') != NULL) ||
	    (strchr(target_user, '/') != NULL) ||
	    (strchr(target_user, '%') != NULL)) {
		fprintf(stderr, "unknown user: %s\n",
			target_user);
		retval = 4;
	}

	do {
		/* Sanity check the timestamp directory itself. */
		if (retval == 0) {
			if (check_dir_perms(TIMESTAMPDIR) != PAM_SUCCESS) {
				retval = 5;
			}
		}

		/* Sanity check the tty to make sure we should be checking
		 * for timestamps which pertain to it. */
		if (retval == 0) {
			tty = check_tty(ttyname(STDIN_FILENO));
			if (tty == NULL) {
				fprintf(stderr, "invalid tty\n");
				retval = 6;
			}
		}

		if (retval == 0) {
			/* Generate the name of the timestamp file. */
			format_timestamp_name(path, sizeof(path), TIMESTAMPDIR,
					      tty, user, target_user);
		}

		if (retval == 0) {
			if (kflag) {
				/* Remove the timestamp. */
				if (lstat(path, &st) != -1) {
					retval = unlink(path);
				}
			} else {
				/* Check the timestamp. */
				if (lstat(path, &st) != -1) {
					if (!timestamp_good(st.st_mtime, time(NULL),
							    DEFAULT_TIMESTAMP_TIMEOUT) == PAM_SUCCESS) {
						retval = 7;
					}
				} else {
					retval = 7;
				}
			}
		}

		if (dflag > 0) {
			/* Send the would-be-returned value to our parent. */
			signal(SIGPIPE, SIG_DFL);
			fprintf(stdout, "%d\n", retval);
			fflush(stdout);
			/* Wait. */
			tv.tv_sec = CHECK_INTERVAL;
			tv.tv_usec = 0;
			FD_ZERO(&write_fds);
			FD_SET(STDOUT_FILENO, &write_fds);
			select(STDOUT_FILENO + 1,
			       NULL, NULL, &write_fds,
			       &tv);
			pretval = retval;
			retval = 0;
		}
	} while (dflag > 0);

	return retval;
}

#endif
