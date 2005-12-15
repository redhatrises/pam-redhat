/* pam_loginuid.c --
 * Copyright 2005 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
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
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 *
 * PAM module that sets the login uid introduced in kernel 2.6.11
 */

#include "config.h"
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <string.h>
#include <pwd.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>

#include <fcntl.h>


/*
 * This function writes the loginuid to the /proc system. It returns
 * 0 on success and 1 on failure.
 */
static int set_loginuid(pam_handle_t *pamh, uid_t uid)
{
	int fd, count, rc = 0;
	char loginuid[16];

	count = snprintf(loginuid, sizeof(loginuid), "%d", uid);
	fd = open("/proc/self/loginuid", O_NOFOLLOW|O_WRONLY|O_TRUNC);
	if (fd < 0) {
		int loglevel = LOG_DEBUG;
		if (errno != ENOENT) {
			rc = 1;
			loglevel = LOG_ERR;
		}
		pam_syslog(pamh, loglevel, "set_loginuid failed opening loginuid");
		return rc;
	}
	if (pam_modutil_write(fd, loginuid, count) != count) 
		rc = 1;
	close(fd);
	return rc;
}

/*
 * Initialize audit session for user
 */
static int
_pam_loginuid(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	char		*user = NULL;
	struct passwd	*pwd;

	/* get user name */
	if (pam_get_item(pamh, PAM_USER, (const void **) &user) != PAM_SUCCESS)
	{
		pam_syslog(pamh, LOG_ERR, "error recovering login user-name");
		return PAM_SESSION_ERR;
	}

        /* get user info */
	if ((pwd = getpwnam(user)) == NULL) {
		pam_syslog(pamh, LOG_ERR,
			 "error: login user-name '%s' does not exist", user);
		return PAM_SESSION_ERR;
	}

	if (set_loginuid(pamh, pwd->pw_uid)) {
		pam_syslog(pamh, LOG_ERR, "set_loginuid failed\n");
		return PAM_SESSION_ERR;
	}

	return PAM_SUCCESS;
}

/*
 * PAM routines
 *
 * This is here for vsftpd which doesn't seem to run the session stack 
 */
PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return _pam_loginuid(pamh, flags, argc, argv);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return _pam_loginuid(pamh, flags, argc, argv);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}

/* static module data */
#ifdef PAM_STATIC
struct pam_module _pam_loginuid_modstruct = {
    "pam_loginuid",
    NULL,
    NULL,
    pam_sm_acct_mgmt,
    pam_sm_open_session,
    pam_sm_close_session,
    NULL
};
#endif

