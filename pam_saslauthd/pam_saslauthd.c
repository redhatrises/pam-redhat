/******************************************************************************
 * A password-checking module for PAM which contacts a saslauthd v2 daemon
 * and lets it decide.
 *
 * Copyright (c) 2004 Red Hat, Inc.
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

#include "../config.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <security/pam_modules.h>
#include "../lib/libmisc.h"

#define MODULE_PREFIX "pam_saslauthd: "
#define DEFAULT_SASLAUTHD_SOCKET_PATH "/var/run/saslauthd/mux"

static int
try_sasl_auth(const char *path,
	      int protocol_version,
	      const char *user,
	      const char *password,
	      const char *realm,
	      const char *service)
{
	struct sockaddr_un un;
	char *buf, *p;
	size_t bufsize;
	u_int16_t length;
	int sock, ret;

	if (strlen(path) >= sizeof(un.sun_path)) {
		return PAM_SYSTEM_ERR;
	}
	un.sun_family = AF_UNIX;
	strcpy(un.sun_path, path);

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
		return PAM_SYSTEM_ERR;
	}

	if (user == NULL) {
		user = "";
	}
	if (password == NULL) {
		password = "";
	}
	if (service == NULL) {
		service = "";
	}
	if (realm == NULL) {
		realm = "";
	}

	bufsize = 1024;
	bufsize += strlen(user);
	bufsize += strlen(password);
	bufsize += strlen(service);
	bufsize += strlen(realm);

	buf = malloc(bufsize);
	if (buf == NULL) {
		close(sock);
		return PAM_BUF_ERR;
	}

	switch (protocol_version) {
	case 1:
		p = buf;

		strcpy(p, user);
		p += strlen(user);
		p++;

		strcpy(p, password);
		p += strlen(password);
		p++;

		length = p - buf;
		break;
	case 2:
	default:
		p = buf;

		length = htons(strlen(user));
		memcpy(p, &length, sizeof(length));
		p += sizeof(length);
		strcpy(p, user);
		p += strlen(user);

		length = htons(strlen(password));
		memcpy(p, &length, sizeof(length));
		p += sizeof(length);
		strcpy(p, password);
		p += strlen(password);

		length = htons(strlen(service));
		memcpy(p, &length, sizeof(length));
		p += sizeof(length);
		strcpy(p, service);
		p += strlen(service);

		length = htons(strlen(realm));
		memcpy(p, &length, sizeof(length));
		p += sizeof(length);
		strcpy(p, realm);
		p += strlen(realm);

		length = p - buf;
		break;
	}

	ret = PAM_AUTH_ERR;

	if (connect(sock, &un, sizeof(un)) != 0) {
		ret = PAM_AUTHINFO_UNAVAIL;
	} else {
		if (libmisc_retry_write(sock, buf, length) != length) {
			ret = PAM_SYSTEM_ERR;
		} else {
			memset(buf, '\0', bufsize);
			if (libmisc_retry_read(sock, buf, bufsize) < 1) {
				ret = PAM_SYSTEM_ERR;
			} else {
				switch (protocol_version) {
				case 1:
					if (strncmp(buf, "OK", 2) != 0) {
						ret = PAM_AUTH_ERR;
					} else {
						ret = PAM_SUCCESS;
					}
					break;
				case 2:
				default:
					if (strncmp(buf + 2, "OK", 2) != 0) {
						ret = PAM_AUTH_ERR;
					} else {
						ret = PAM_SUCCESS;
					}
					break;
				}
			}
		}
	}

	free(buf);
	return ret;
}

int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	const char *user, *password, *realm, *service, *path, *user_prompt;
	int ret, i, try_second_pass, proto;
	struct pam_message password_prompt = {
		PAM_PROMPT_ECHO_OFF,
		"Password: ",
	};
	struct pam_response *resp;

	user_prompt = "login: ";
	libmisc_get_string_item(pamh, PAM_USER_PROMPT, &user_prompt);
	ret = pam_get_user(pamh, &user, user_prompt);
	if (ret != PAM_SUCCESS) {
		return ret;
	}

	password = NULL;
	libmisc_get_string_item(pamh, PAM_AUTHTOK, &password);

	realm = "";

	ret = libmisc_get_string_item(pamh, PAM_SERVICE, &service);
	if (ret != PAM_SUCCESS) {
		return ret;
	}

	try_second_pass = 1;
	proto = 2;

	path = DEFAULT_SASLAUTHD_SOCKET_PATH;

	for (i = 0; i < argc; i++) {
		if (strncmp(argv[i], "service=", 8) == 0) {
			service = argv[i] + 8;
		} else
		if (strncmp(argv[i], "realm=", 6) == 0) {
			service = argv[i] + 6;
		} else
		if (strncmp(argv[i], "socket_path=", 12) == 0) {
			path = argv[i] + 12;
		} else
		if (strncmp(argv[i], "protocol=", 9) == 0) {
			proto = atoi(argv[i] + 9);
		} else
		if (strcmp(argv[i], "try_first_pass") == 0) {
			try_second_pass = 1;
		} else
		if (strcmp(argv[i], "use_first_pass") == 0) {
			try_second_pass = 0;
		}
	}

	ret = PAM_AUTH_ERR;
	if (password != NULL) {
		ret = try_sasl_auth(path, proto,
				    user, password, realm, service);
	}
	if ((ret != PAM_SUCCESS) && try_second_pass) {
		resp = NULL;
		ret = libmisc_converse(pamh, &password_prompt, 1, &resp);
		if (ret == PAM_SUCCESS) {
			ret = try_sasl_auth(path, proto,
					    user, resp->resp, realm, service);
		}
		libmisc_free_responses(resp, 1);
	}
	return ret;
}

int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}
