/******************************************************************************
 * A module for Linux-PAM that will divert to another file and use configuration
 * information from it, percolating the result code back up.  Recursion is fun.
 *
 * Copyright (c) 2000,2001 Red Hat, Inc.
 * Written by Nalin Dahyabhai <nalin@redhat.com>
 * Portions also Copyright (c) 2000 Dmitry V. Levin
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 ******************************************************************************/

#define PAM_SM_AUTH
#define PAM_SM_SESSION
#define PAM_SM_ACCOUNT
#define PAM_SM_PASSWD

#define PAM_CONST const

#include "../../_pam_aconf.h"
#include "../../libpam/include/security/_pam_types.h"
#include "../../libpam/pam_private.h"
#include <sys/syslog.h>
#include <stdlib.h>
#include <string.h>

static int _pam_stack_dispatch(pam_handle_t *pamh, int flags,
			       int argc, const char **argv,
			       int which_stack);

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return _pam_stack_dispatch(pamh, flags, argc, argv, PAM_AUTHENTICATE);
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return _pam_stack_dispatch(pamh, flags, argc, argv, PAM_SETCRED);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return _pam_stack_dispatch(pamh, flags, argc, argv, PAM_OPEN_SESSION);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return _pam_stack_dispatch(pamh, flags, argc, argv, PAM_CLOSE_SESSION);
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return _pam_stack_dispatch(pamh, flags, argc, argv, PAM_ACCOUNT);
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return _pam_stack_dispatch(pamh, flags, argc, argv, PAM_CHAUTHTOK);
}

/* Current libpam now distinguishes between modules and applications, so the
   neat behavior we depended on is gone.  So we have to this the messy way.
   What's amazing is that this simplifies things due to the lack of a need to
   check for error return codes. */
static void
_pam_stack_copy(pam_handle_t *source, pam_handle_t *dest, unsigned int item,
		const char *recipient)
{
	const char *name = NULL;			/* name of the item */
	int copied = 0;					/* was it copied */
	const char *reason = "(no reason)";		/* if not copied, why */
	switch(item) {
		case PAM_AUTHTOK:
			name = "PAM_AUTHTOK";
			if(source->authtok) {
				copied = 1;
				dest->authtok = _pam_strdup(source->authtok);
			} else {
				reason = "source is NULL";
			}
			break;
		case PAM_CONV:
			name = "PAM_CONV";
			if(source->pam_conversation && !dest->pam_conversation) {
				copied = 1;
				dest->pam_conversation =
					source->pam_conversation;
			} else {
				if(!source->pam_conversation)
					reason = "source not NULL";
				if(dest->pam_conversation)
					reason = "destination already set";
			}
			break;
		case PAM_FAIL_DELAY:
			name = "PAM_FAIL_DELAY";
			if(source->fail_delay.set) {
				copied = 1;
				dest->fail_delay = source->fail_delay;
			} else {
				reason = "source not set";
			}
			break;
		case PAM_OLDAUTHTOK:
			name = "PAM_OLDAUTHTOK";
			if(source->oldauthtok) {
				copied = 1;
				dest->oldauthtok = _pam_strdup(source->oldauthtok);
			} else {
				reason = "source is NULL";
			}
			break;
		case PAM_RHOST:
			name = "PAM_RHOST";
			if(source->rhost) {
				copied = 1;
				dest->rhost = _pam_strdup(source->rhost);
			} else {
				reason = "source is NULL";
			}
			break;
		case PAM_RUSER:
			name = "PAM_RUSER";
			if(source->ruser) {
				copied = 1;
				dest->ruser = _pam_strdup(source->ruser);
			} else {
				reason = "source is NULL";
			}
			break;
		case PAM_SERVICE:
			name = "PAM_SERVICE";
			if(source->service_name) {
				copied = 1;
				dest->service_name = _pam_strdup(source->service_name);
			} else {
				reason = "source is NULL";
			}
			break;
		case PAM_TTY:
			name = "PAM_TTY";
			if(source->tty) {
				copied = 1;
				dest->tty = _pam_strdup(source->tty);
			} else {
				reason = "source is NULL";
			}
			break;
		case PAM_USER:
			name = "PAM_USER";
			if(source->user) {
				copied = 1;
				dest->user = _pam_strdup(source->user);
			} else {
				reason = "source is NULL";
			}
			break;
		case PAM_USER_PROMPT:
			name = "PAM_USER_PROMPT";
			if(source->prompt) {
				copied = 1;
				dest->prompt = _pam_strdup(source->prompt);
			} else {
				reason = "source is NULL";
			}
			break;
	}
	if(recipient) {
		openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
		if(copied) {
			syslog(LOG_DEBUG, "passing %s to %s", name, recipient);
		} else {
			syslog(LOG_DEBUG, "NOT passing %s to %s: %s", name,
			       recipient, reason);
		}
		closelog();
	}
}

static int _pam_stack_dispatch(pam_handle_t *pamh, int flags,
			       int argc, const char **argv,
			       int which_stack)
{
	char **env = NULL, *service = NULL;
	const char *parent_service = NULL;
	pam_handle_t *sub_pamh = NULL;
	int debug = 0, i = 0, ret = PAM_SUCCESS, final_ret = PAM_SUCCESS;

	/* Save the main service name. */
	ret = pam_get_item(pamh, PAM_SERVICE, (const void **) &parent_service);
	if(ret != PAM_SUCCESS) {
		openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
		syslog(LOG_ERR, "pam_get_item(PAM_SERVICE) returned %s",
		       pam_strerror(pamh, ret));
		closelog();
		return PAM_SYSTEM_ERR;
	}

	/* Parse arguments. */
	for(i = 0; i < argc; i++) {
		if(strncmp("debug", argv[i], 5) == 0) {
			const char *stack_description = NULL;
			debug = 1;
			switch(which_stack) {
				case PAM_AUTHENTICATE:
					stack_description = "PAM_AUTHENTICATE";
					break;
				case PAM_SETCRED:
					stack_description = "PAM_SETCRED";
					break;
				case PAM_OPEN_SESSION:
					stack_description = "PAM_OPEN_SESSION";
					break;
				case PAM_CLOSE_SESSION:
					stack_description = "PAM_CLOSE_SESSION";
					break;
				case PAM_ACCOUNT:
					stack_description = "PAM_ACCOUNT";
					break;
				case PAM_CHAUTHTOK:
					stack_description = "PAM_CHAUTHTOK";
					break;
				default:
					stack_description = "(unknown)";
			}
			if(stack_description) {
				openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
				syslog(LOG_DEBUG, "called for \"%s\"",
				       stack_description);
				closelog();
			}
		}
		if(strncmp("service=", argv[i], 8) == 0) {
			_pam_drop(service);
			service = _pam_strdup(argv[i] + 8);
		}
	}

	/* Sign-on message. */
	if(debug) {
		openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
		syslog(LOG_DEBUG, "called from \"%s\"",
		       parent_service ? parent_service : "unknown service");
		closelog();
	}
	if(service == NULL) {
		openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
		syslog(LOG_ERR, "required argument \"service\" not given");
		closelog();
		return PAM_SYSTEM_ERR;
	}

	/* Create and initialize a pam_handle_t structure for our substack. */
	if(debug) {
		openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
		syslog(LOG_DEBUG, "initializing");
		closelog();
	}
	sub_pamh = calloc(1, sizeof(pam_handle_t));

	/* Create an environment for the child. */
	if(debug) {
		openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
		syslog(LOG_DEBUG, "creating environment");
		closelog();
	}
	ret = _pam_make_env(sub_pamh);
	if(ret != PAM_SUCCESS) {
		openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
		syslog(LOG_ERR, "_pam_make_env() returned %s",
		       pam_strerror(pamh, ret));
		closelog();
		return PAM_SYSTEM_ERR;
	}

	/* Set the service.  This loads the service modules. */
	ret = pam_set_item(sub_pamh, PAM_SERVICE, service);
	if(ret != PAM_SUCCESS) {
		openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
		syslog(LOG_ERR, "pam_set_item(PAM_SERVICE) returned %d (%s)",
		       ret, pam_strerror(sub_pamh, ret));
		closelog();
		return PAM_SYSTEM_ERR;
	}

	/* Initialize the handlers for the substack. */
	_pam_start_handlers(sub_pamh);
	ret = _pam_init_handlers(sub_pamh);
	if(ret != PAM_SUCCESS) {
		openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
		syslog(LOG_ERR, "_pam_init_handlers() returned %d (%s)",
		       ret, pam_strerror(sub_pamh, ret));
		closelog();
		return PAM_SYSTEM_ERR;
	}

	/* Copy the environment from the upper stack to the lower stack. */
	env = pam_getenvlist(pamh); 
	for(i = 0; (env != NULL) && (env[i] != NULL); i++) {
		if(debug) {
			openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
			syslog(LOG_DEBUG, "setting environment \"%s\" in child",
			       env[i]);
			closelog();
		}
		pam_putenv(sub_pamh, env[i]);
	}

	/* Copy named PAM items to the child. */
	_pam_stack_copy(pamh, sub_pamh, PAM_AUTHTOK, debug ? "child" : NULL);
	_pam_stack_copy(pamh, sub_pamh, PAM_CONV, debug ? "child" : NULL);
	_pam_stack_copy(pamh, sub_pamh, PAM_FAIL_DELAY, debug ? "child" : NULL);
	_pam_stack_copy(pamh, sub_pamh, PAM_OLDAUTHTOK, debug ? "child" : NULL);
	_pam_stack_copy(pamh, sub_pamh, PAM_RHOST, debug ? "child" : NULL);
	_pam_stack_copy(pamh, sub_pamh, PAM_RUSER, debug ? "child" : NULL);
	_pam_stack_copy(pamh, sub_pamh, PAM_SERVICE, debug ? "child" : NULL);
	_pam_stack_copy(pamh, sub_pamh, PAM_TTY, debug ? "child" : NULL);
	_pam_stack_copy(pamh, sub_pamh, PAM_USER, debug ? "child" : NULL);
	_pam_stack_copy(pamh, sub_pamh, PAM_USER_PROMPT, debug ? "child" : NULL);

	/* Pass the generic data pointer, too. */
	if(debug) {
		openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
		syslog(LOG_DEBUG, "passing data to child");
		closelog();
	}
	sub_pamh->data = pamh->data;
	if(debug) {
		openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
		syslog(LOG_DEBUG, "passing former to child");
		closelog();
	}
	sub_pamh->former = pamh->former;

	/* Now call the substack. */
	if(debug) {
		openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
		syslog(LOG_DEBUG, "calling substack");
		closelog();
	}
	final_ret = _pam_dispatch(sub_pamh, flags, which_stack);

	/* Copy the useful data back up to the main stack, environment first. */
	env = pam_getenvlist(sub_pamh); 
	for(i = 0; (env != NULL) && (env[i] != NULL); i++) {
		if(debug) {
			openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
			syslog(LOG_DEBUG, "setting environment \"%s\" in "
			       "parent", env[i]);
			closelog();
		}
		pam_putenv(pamh, env[i]);
	}

	/* Now the named data items. */
	_pam_stack_copy(sub_pamh, pamh, PAM_AUTHTOK, debug ? "parent" : NULL);
	_pam_stack_copy(sub_pamh, pamh, PAM_CONV, debug ? "parent" : NULL);
	_pam_stack_copy(sub_pamh, pamh, PAM_FAIL_DELAY, debug ? "parent" : NULL);
	_pam_stack_copy(sub_pamh, pamh, PAM_OLDAUTHTOK, debug ? "parent" : NULL);
	_pam_stack_copy(sub_pamh, pamh, PAM_RHOST, debug ? "parent" : NULL);
	_pam_stack_copy(sub_pamh, pamh, PAM_RUSER, debug ? "parent" : NULL);
	_pam_stack_copy(sub_pamh, pamh, PAM_SERVICE, debug ? "parent" : NULL);
	_pam_stack_copy(sub_pamh, pamh, PAM_TTY, debug ? "parent" : NULL);
	_pam_stack_copy(sub_pamh, pamh, PAM_USER, debug ? "parent" : NULL);
	_pam_stack_copy(sub_pamh, pamh, PAM_USER_PROMPT, debug ? "parent" : NULL);

	/* Wow, passing the extra data back is hard. */
	if(debug) {
		openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
		syslog(LOG_DEBUG, "passing data back");
		closelog();
	}
	pamh->data = sub_pamh->data;
	if(debug) {
		openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
		syslog(LOG_DEBUG, "passing former back");
		closelog();
	}
	pamh->former = sub_pamh->former;

	/* Clean up and bug out.  Don't free the ITEMs because they're shared
	   by the parent's pamh.  Because of how setting items works, we don't
	   actually leak memory doing this (!). */
	sub_pamh->data = NULL;
	_pam_drop(sub_pamh->service_name);
	_pam_drop_env(sub_pamh);
	_pam_drop(service);

	if(debug) {
		openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
		syslog(LOG_DEBUG, "returning %d (%s)", final_ret,
		       pam_strerror(sub_pamh, final_ret));
		closelog();
	}
	free(sub_pamh);

	return final_ret;
}

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_stack_modstruct = {
	"pam_stack",
	pam_sm_authenticate,
	pam_sm_setcred,
	pam_sm_acct_mgmt,
	pam_sm_open_session,
	pam_sm_close_session,
	pam_sm_chauthtok,
};
#endif

