/*
 * Copyright 2001 Red Hat, Inc.
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
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#define PAM_SM_SESSION
#include "../../libpam/include/security/pam_modules.h"

#define PAM_GETPWNAM_R
#define PAM_GETPWUID_R
#include "../../libpam/include/security/_pam_macros.h"

#define DATANAME "pam_xauth_cookie_file"
#define XAUTHBIN "/usr/X11R6/bin/xauth"
#define XAUTHENV "XAUTHORITY"
#define HOMEENV  "HOME"
#define XAUTHDEF ".Xauthority"
#define XAUTHTMP ".xauthXXXXXX"

/* Run a given command (with a NULL-terminated argument list), feeding it the
 * given input on stdin, and storing any output it generates. */
static int
run_coprocess(const char *input, char **output,
	      uid_t uid, gid_t gid, const char *command, ...)
{
	int ipipe[2], opipe[2], i;
	char buf[LINE_MAX];
	pid_t child;
	char *buffer = NULL;
	size_t buffer_size = 0;
	va_list ap;

	*output = NULL;

	/* Create stdio pipery. */
	if(pipe(ipipe) == -1) {
		return -1;
	}
	if(pipe(opipe) == -1) {
		close(ipipe[0]);
		close(ipipe[1]);
		return -1;
	}

	/* Fork off a child. */
	child = fork();
	if(child == -1) {
		close(ipipe[0]);
		close(ipipe[1]);
		close(opipe[0]);
		close(opipe[1]);
		return -1;
	}

	if(child == 0) {
		/* We're the child. */
		char *args[10];
		const char *tmp;
		/* Drop privileges. */
		setgid(gid);
		setgroups(0, NULL);
		setuid(uid);
		/* Initialize the argument list. */
		memset(&args, 0, sizeof(args));
		/* Set the pipe descriptors up as stdin and stdout, and close
		 * everything else, including the original values for the
		 * descriptors. */
		dup2(ipipe[0], STDIN_FILENO);
		dup2(opipe[1], STDOUT_FILENO);
		for(i = 0; i < sysconf(_SC_OPEN_MAX); i++) {
			if((i != STDIN_FILENO) && (i != STDOUT_FILENO)) {
				close(i);
			}
		}
		/* Convert the varargs list into a regular array of strings. */
		va_start(ap, command);
		args[0] = strdup(command);
		for(i = 1; i < ((sizeof(args) / sizeof(args[0])) - 1); i++) {
			tmp = va_arg(ap, const char*);
			if(tmp == NULL) {
				break;
			}
			args[i] = strdup(tmp);
		}
		/* Run the command. */
		execvp(command, args);
		/* Never reached. */
		exit(1);
	}

	/* We're the parent, so close the other ends of the pipes. */
	close(ipipe[0]);
	close(opipe[1]);
	/* Send input to the process (if we have any), then send an EOF. */
	if(input) {
		write(ipipe[1], input, strlen(input));
	}
	close(ipipe[1]);

	/* Read data output until we run out of stuff to read. */
	i = read(opipe[0], buf, sizeof(buf));
	while((i != 0) && (i != -1)) {
		char *tmp;
		/* Resize the buffer to hold the data. */
		tmp = realloc(buffer, buffer_size + i + 1);
		if(tmp == NULL) {
			/* Uh-oh, bail. */
			if(buffer != NULL) {
				free(buffer);
			}
			close(opipe[0]);
			waitpid(child, NULL, 0);
			return -1;
		}
		/* Save the new buffer location, copy the newly-read data into
		 * the buffer, and make sure the result will be
		 * nul-terminated. */
		buffer = tmp;
		memcpy(buffer + buffer_size, buf, i);
		buffer[buffer_size + i] = '\0';
		buffer_size += i;
		/* Try to read again. */
		i = read(opipe[0], buf, sizeof(buf));
	}
	/* No more data.  Clean up and return data. */
	close(opipe[0]);
	*output = buffer;
	waitpid(child, NULL, 0);
	return 0;
}

/* Free a data item. */
static void
cleanup(pam_handle_t *pamh, void *data, int err)
{
	free(data);
}

int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	char xauthpath[] = XAUTHBIN;
	char *cookiefile = NULL, *xauthority = NULL,
	     *cookie = NULL, *display = NULL, *thome = NULL, *tmp;
	const char *user, *xauth = xauthpath;
	struct passwd passwd, *pwd;
	size_t buflen;
	int fd, i, debug = 0;
	uid_t systemuser = 499;

	/* Parse arguments.  We don't understand many, so no sense in breaking
	 * this into a separate function. */
	for(i = 0; i < argc; i++) {
		if(strcmp(argv[i], "debug") == 0) {
			debug = 1;
			continue;
		}
		if(strncmp(argv[i], "xauthpath=", 10) == 0) {
			xauth = argv[i] + 10;
			continue;
		}
		if(strncmp(argv[i], "systemuser=", 11) == 0) {
			long l = strtol(argv[i] + 11, &tmp, 10);
			if((strlen(argv[i] + 11) > 0) && (*tmp == '\0')) {
				systemuser = l;
			} else {
				syslog(LOG_WARNING, "pam_xauth: invalid value "
				       "for systemuser (`%s')", argv[i] + 11);
			}
			continue;
		}
		syslog(LOG_WARNING, "pam_xauth: unrecognized option `%s'",
		       argv[i]);
	}

	/* If DISPLAY isn't set, we don't really care, now do we? */
	if((display = getenv("DISPLAY")) == NULL) {
		if(debug) {
			syslog(LOG_DEBUG, "pam_xauth: user has no DISPLAY");
		}
		return PAM_IGNORE;
	}

	/* Read the target user's name. */
	if(pam_get_item(pamh, PAM_USER, (const void**)&user) != PAM_SUCCESS) {
		syslog(LOG_ERR, "pam_xauth: error determining target "
		       "user's name");
		return PAM_IGNORE;
	}

	/* Get the target user's UID and primary GID, which we'll need to set
	 * on the xauthority file we create later on. */
	if(_pam_getpwnam_r(user, &passwd, &tmp, &buflen, &pwd) != 0) {
		syslog(LOG_ERR, "pam_xauth: error determining target "
		       "user's UID");
		return PAM_IGNORE;
	}

	/* We only care about the target user's IDs, so we can free the
	 * string data after making a copy of the user's home directory. */
	thome = strdup(passwd.pw_dir);
	if(tmp) {
		free(tmp);
	}

	/* If the UID is a system account (and not the superuser), forget
	 * about forwarding keys. */
	if((passwd.pw_uid != 0) && (passwd.pw_uid <= systemuser)) {
		free(thome);
		return PAM_IGNORE;
	}

	/* Figure out where the source user's .Xauthority file is. */
	if(getenv(XAUTHENV) != NULL) {
		cookiefile = strdup(getenv(XAUTHENV));
	} else {
		char *t, *homedir = NULL;
		size_t t_len;
		struct passwd tpasswd, *tpwd;
		if(_pam_getpwuid_r(getuid(), &tpasswd, &t, &t_len,
				   &tpwd) == 0) {
			homedir = strdup(tpasswd.pw_dir);
			free(t);
		} else {
			free(thome);
			return PAM_IGNORE;
		}
		cookiefile = malloc(strlen(homedir) + 1 + strlen(XAUTHDEF) + 1);
		if(cookiefile == NULL) {
			free(t);
			free(thome);
			return PAM_IGNORE;
		}
		strcpy(cookiefile, homedir);
		strcat(cookiefile, "/");
		strcat(cookiefile, XAUTHDEF);
		free(homedir);
	}
	if(debug) {
		syslog(LOG_DEBUG, "pam_xauth: reading keys from `%s'",
		       cookiefile);
	}

	/* Read the user's .Xauthority file.  Because the current UID is
	 * the original user's UID, this will only fail if something has
	 * gone wrong, or we have no cookies. */
	if(run_coprocess(NULL, &cookie,
			 getuid(), getgid(),
			 xauth, "-f", cookiefile, "nlist", display, NULL) == 0) {
		/* Check that we got a cookie. */
		if((cookie == NULL) || (strlen(cookie) == 0)) {
			if(debug) {
				syslog(LOG_DEBUG, "pam_xauth: no key");
			}
			return PAM_IGNORE;
		}

		/* Generate the environment variable "XAUTHORITY=filename". */
		xauthority = malloc(strlen(XAUTHENV) + strlen(thome) +
				    strlen(XAUTHTMP) + 3);
		if(xauthority == NULL) {
			if(debug) {
				syslog(LOG_DEBUG, "pam_xauth: no free memory");
			}
			return PAM_IGNORE;
		}
		strcpy(xauthority, XAUTHENV);
		strcat(xauthority, "=");
		strcat(xauthority, thome);
		strcat(xauthority, "/");
		strcat(xauthority, XAUTHTMP);

		/* Generate a new file to hold the data. */
		fd = mkstemp(xauthority + strlen(XAUTHENV) + 1);
		if(fd == -1) {
			syslog(LOG_ERR, "pam_xauth: error creating "
			       "temporary file `%s': %s",
			       xauthority + strlen(XAUTHENV) + 1,
			       strerror(errno));
			free(xauthority);
			return PAM_IGNORE;
		}
		/* Set permissions on the new file and dispose of the
		 * descriptor. */
		fchown(fd, passwd.pw_uid, passwd.pw_gid);
		close(fd);

		/* Get a copy of the filename to save as a data item for
		 * removal at session-close time. */
		free(cookiefile);
		cookiefile = strdup(xauthority + strlen(XAUTHENV) + 1);

		/* Save the filename. */
		if(pam_set_data(pamh, DATANAME, cookiefile, cleanup) != PAM_SUCCESS) {
			syslog(LOG_ERR, "pam_xauth: error saving name of "
			       "temporary file `%s'", cookiefile);
			unlink(cookiefile);
			free(cookiefile);
			free(xauthority);
			free(cookie);
			return PAM_IGNORE;
		}

		/* Unset any old XAUTHORITY variable in the environment. */
		if(getenv(XAUTHENV)) {
			unsetenv(XAUTHENV);
		}

		/* Set the new variable in the environment. */
		pam_putenv(pamh, xauthority);
		putenv(xauthority);

		/* Merge the cookie we read before into the new file. */
		if(debug) {
			syslog(LOG_DEBUG, "pam_xauth: writing key `%s' to "
			       "temporary file `%s'", cookie, cookiefile);
		}
		run_coprocess(cookie, &tmp,
			      passwd.pw_uid, passwd.pw_gid,
			      xauth, "-f", cookiefile, "nmerge", "-", NULL);

		/* We don't need to keep a copy of this around any more. */
		free(cookie);
	}
	return PAM_IGNORE;
}

int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	void *cookiefile;
	int i, debug = 0;

	/* Parse arguments.  We don't understand many, so no sense in breaking
	 * this into a separate function. */
	for(i = 0; i < argc; i++) {
		if(strcmp(argv[i], "debug") == 0) {
			debug = 1;
			continue;
		}
		if(strncmp(argv[i], "xauthpath=", 10) == 0) {
			continue;
		}
		if(strncmp(argv[i], "systemuser=", 11) == 0) {
			continue;
		}
		syslog(LOG_WARNING, "pam_xauth: unrecognized option `%s'",
		       argv[i]);
	}

	/* Try to retrieve the name of a file we created when the session was
	 * opened. */
	if(pam_get_data(pamh, DATANAME, (const void**) &cookiefile) == PAM_SUCCESS) {
		/* We'll only try to remove the file once. */
		if(strlen((char*)cookiefile) > 0) {
			if(debug) {
				syslog(LOG_DEBUG, "pam_xauth: removing `%s'",
				       (char*)cookiefile);
			}
			unlink((char*)cookiefile);
			*((char*)cookiefile) = '\0';
		}
	}
	return PAM_IGNORE;
}
