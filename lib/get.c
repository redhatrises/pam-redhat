/*
 * Copyright 2004 Red Hat, Inc.
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

#ident "$Id$"

#include "../config.h"
#include <security/pam_modules.h>
#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <pthread.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include "libmisc.h"

static pthread_mutex_t getpw_mutex = PTHREAD_MUTEX_INITIALIZER;
static void
getpw_lock(void)
{
	pthread_mutex_lock(&getpw_mutex);
}
static void
getpw_unlock(void)
{
	pthread_mutex_unlock(&getpw_mutex);
}

static int
intlen(long long number)
{ 
	int len;
	len = 2;
	while (number != 0) {
		number /= 10;
		len++;
	}
	return len;
}

static void
getpw_cleanup(pam_handle_t *pamh, void *data, int error_status)
{
	free(data);
}

struct passwd *
libmisc_getpwnam(pam_handle_t *pamh, const char *user)
{
	char *buffer;
	size_t length, name_length, pwd_length;
	struct passwd *result;

	buffer = NULL;
	pwd_length = sizeof(struct passwd);
	name_length = strlen("getpw_getpwnam_%s_%d") +
		      strlen(user) + 1 + intlen(INT_MAX) + 1;
	length = 0;

	do {
		int status;
		struct passwd *tmppwd;

		length += 256;
		buffer = malloc(pwd_length + name_length + length);
		result = NULL;
		if (buffer == NULL) {
			/* out of memory, bail */
			break;
		}

		/* make the re-entrant call to get the pwd structure */
		status = getpwnam_r(user, (struct passwd*) buffer,
				    buffer + pwd_length + name_length,
				    length,
				    &result);
		if ((status == 0) && (result == (struct passwd*) buffer)) {
			char *data_name;
			const void *ignore;
			int i;

			data_name = buffer + pwd_length;

			getpw_lock();
			for (i = 0; i < INT_MAX; i++) {
				sprintf(data_name, "getpw_getpwnam_%s_%d",
					user, i);
				status = PAM_NO_MODULE_DATA;
				if (pam_get_data(pamh, data_name,
						 &ignore) != PAM_SUCCESS) {
					 status = pam_set_data(pamh, data_name,
							       result,
							       getpw_cleanup);
				}
				if (status == PAM_SUCCESS) {
					break;
				}
			}
			getpw_unlock();
			if (status != PAM_SUCCESS) {
				result = NULL;
			}
		} else {
			result = NULL;
		}
		if (result == NULL) {
			free(buffer);
		}
	} while ((result == NULL) && (errno == ERANGE) && (length < 0x10000));

	if (result != NULL) {
		return result;
	}

	free(buffer);
	return NULL;
}

struct passwd *
libmisc_getpwuid(pam_handle_t *pamh, uid_t uid)
{
	char *buffer;
	size_t length, name_length, pwd_length;
	struct passwd *result;

	buffer = NULL;
	pwd_length = sizeof(struct passwd);
	name_length = strlen("getpw_getpwuid_%lld_%d") +
		      intlen(uid) + 1 + intlen(INT_MAX) + 1;
	length = 0;

	do {
		int status;
		struct passwd *tmppwd;

		length += 256;
		buffer = malloc(pwd_length + name_length + length);
		result = NULL;
		if (buffer == NULL) {
			/* out of memory, bail */
			break;
		}

		/* make the re-entrant call to get the pwd structure */
		status = getpwuid_r(uid, (struct passwd*) buffer,
				    buffer + pwd_length + name_length,
				    length,
				    &result);
		if ((status == 0) && (result == (struct passwd*) buffer)) {
			char *data_name;
			const void *ignore;
			int i;

			data_name = buffer + pwd_length;

			getpw_lock();
			for (i = 0; i < INT_MAX; i++) {
				sprintf(data_name, "getpw_getpwuid_%lld_%d",
					(long long) uid, i);
				status = PAM_NO_MODULE_DATA;
				if (pam_get_data(pamh, data_name,
						 &ignore) != PAM_SUCCESS) {
					 status = pam_set_data(pamh, data_name,
							       result,
							       getpw_cleanup);
				}
				if (status == PAM_SUCCESS) {
					break;
				}
			}
			getpw_unlock();
			if (status != PAM_SUCCESS) {
				result = NULL;
			}
		} else {
			result = NULL;
		}
		if (result == NULL) {
			free(buffer);
		}
	} while ((result == NULL) && (errno == ERANGE) && (length < 0x10000));

	if (result != NULL) {
		return result;
	}

	free(buffer);
	return NULL;
}

struct group *
libmisc_getgrnam(pam_handle_t *pamh, const char *group)
{
	char *buffer;
	size_t length, name_length, grp_length;
	struct group *result;

	buffer = NULL;
	grp_length = sizeof(struct group);
	name_length = strlen("getpw_getgrnam_%s_%d") +
		      strlen(group) + 1 + intlen(INT_MAX) + 1;
	length = 0;

	do {
		int status;
		struct group *tmpgrp;

		length += 256;
		buffer = malloc(grp_length + name_length + length);
		result = NULL;
		if (buffer == NULL) {
			/* out of memory, bail */
			break;
		}

		/* make the re-entrant call to get the pwd structure */
		status = getgrnam_r(group, (struct group*) buffer,
				    buffer + grp_length + name_length,
				    length,
				    &result);
		if ((status == 0) && (result == (struct group*) buffer)) {
			char *data_name;
			const void *ignore;
			int i;

			data_name = buffer + grp_length;

			getpw_lock();
			for (i = 0; i < INT_MAX; i++) {
				sprintf(data_name, "getpw_getgrnam_%s_%d",
					group, i);
				status = PAM_NO_MODULE_DATA;
				if (pam_get_data(pamh, data_name,
						 &ignore) != PAM_SUCCESS) {
					 status = pam_set_data(pamh, data_name,
							       result,
							       getpw_cleanup);
				}
				if (status == PAM_SUCCESS) {
					break;
				}
			}
			getpw_unlock();
			if (status != PAM_SUCCESS) {
				result = NULL;
			}
		} else {
			result = NULL;
		}
		if (result == NULL) {
			free(buffer);
		}
	} while ((result == NULL) && (errno == ERANGE) && (length < 0x10000));

	if (result != NULL) {
		return result;
	}

	free(buffer);
	return NULL;
}

struct group *
libmisc_getgrgid(pam_handle_t *pamh, gid_t gid)
{
	char *buffer;
	size_t length, name_length, grp_length;
	struct group *result;

	buffer = NULL;
	grp_length = sizeof(struct group);
	name_length = strlen("getpw_getgrgid_%lld_%d") +
		      intlen(gid) + 1 + intlen(INT_MAX) + 1;
	length = 0;

	do {
		int status;
		struct group *tmpgrp;

		length += 256;
		buffer = malloc(grp_length + name_length + length);
		result = NULL;
		if (buffer == NULL) {
			/* out of memory, bail */
			break;
		}

		/* make the re-entrant call to get the pwd structure */
		status = getgrgid_r(gid, (struct group*) buffer,
				    buffer + grp_length + name_length,
				    length,
				    &result);
		if ((status == 0) && (result == (struct group*) buffer)) {
			char *data_name;
			const void *ignore;
			int i;

			data_name = buffer + grp_length;

			getpw_lock();
			for (i = 0; i < INT_MAX; i++) {
				sprintf(data_name, "getpw_getgrgid_%lld_%d",
					(long long) gid, i);
				status = PAM_NO_MODULE_DATA;
				if (pam_get_data(pamh, data_name,
						 &ignore) != PAM_SUCCESS) {
					 status = pam_set_data(pamh, data_name,
							       result,
							       getpw_cleanup);
				}
				if (status == PAM_SUCCESS) {
					break;
				}
			}
			getpw_unlock();
			if (status != PAM_SUCCESS) {
				result = NULL;
			}
		} else {
			result = NULL;
		}
		if (result == NULL) {
			free(buffer);
		}
	} while ((result == NULL) && (errno == ERANGE) && (length < 0x10000));

	if (result != NULL) {
		return result;
	}

	free(buffer);
	return NULL;
}
