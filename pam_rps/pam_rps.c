/******************************************************************************
 * A truly challenge-response module for PAM.
 *
 * Copyright (c) 2003,2004 Red Hat, Inc.
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
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <security/pam_modules.h>

#define MODULE_PREFIX "pam_rps: "

int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	const char *values[] = {
		"\x72\x6f\x63\x6b",
		"\x70\x61\x70\x65\x72",
		"\x73\x63\x69\x73\x73\x6f\x72\x73"};
	char prompt_text[32] = "";
	const char *want = "";
	const struct pam_message message = {
		PAM_PROMPT_ECHO_OFF,
		prompt_text,
	};
	const struct pam_message *messages[] = {
		&message,
	};
	struct pam_response *responses = NULL;

	int debug = 0;

	struct pam_conv *conv;
	int ret, fd, r, i;
	unsigned char c;

	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "debug") == 0) {
			debug = 1;
			break;
		}
	}

	ret = pam_get_item(pamh, PAM_CONV, (const void **) &conv);
	if (ret != PAM_SUCCESS) {
		syslog(LOG_AUTHPRIV | LOG_CRIT,
		       MODULE_PREFIX "error determining user name");
		return ret;
	}
	if ((conv == NULL) || (conv->conv == NULL)) {
		syslog(LOG_AUTHPRIV | LOG_CRIT,
		       MODULE_PREFIX "conversation error");
		return PAM_CONV_ERR;
	}

	r = -1;
	for (i = 0; i < argc; i++) {
		if (strncmp(argv[i], "throw=", 6) == 0) {
			r = atol(argv[i] + 6) % 3;
			break;
		}
	}
	if (r == -1) {
		r = 0;
		fd = open("/dev/urandom", O_RDONLY);
		if (fd != -1) {
			c = 0;
			do {
				ret = read(fd, &c, 1);
			} while ((ret == 1) && (c == 0xff));
			/* We drop 0xff here to avoid a variation on
			 * Bleichenbacher's attack. */
			r = c / 85;
			close(fd);
		}
	}
	switch (r) {
	case 0:
		strcpy(prompt_text, values[0]);
		want = values[1];
		break;
	case 1:
		strcpy(prompt_text, values[1]);
		want = values[2];
		break;
	case 2:
		strcpy(prompt_text, values[2]);
		want = values[0];
		break;
	}
	if (debug) {
		syslog(LOG_AUTHPRIV | LOG_DEBUG, "challenge is \"%s\", "
		       "expected response is \"%s\"", prompt_text, want);
	}
	strcat(prompt_text, ": ");
	ret = conv->conv(1, messages, &responses, conv->appdata_ptr);
	if (ret != PAM_SUCCESS) {
		syslog(LOG_AUTHPRIV | LOG_CRIT,
		       MODULE_PREFIX "conversation error");
		return PAM_CONV_ERR;
	}
	if ((responses != NULL) &&
	    (responses[0].resp_retcode == 0) &&
	    (responses[0].resp != NULL) &&
	    (strcasecmp(responses[0].resp, want) == 0)) {
		ret = PAM_SUCCESS;
	} else {
		ret = PAM_AUTH_ERR;
	}
	return ret;
}

int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}
