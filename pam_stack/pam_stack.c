/******************************************************************************
 * A module for Linux-PAM that will divert to another file and use configuration
 * information from it, percolating the result code back up.  Recursion is fun.
 *
 * Copyright (c) 2000,2001,2004 Red Hat, Inc.
 * Written by Nalin Dahyabhai <nalin@redhat.com>
 * Portions also Copyright (c) 2000 Dmitry V. Levin
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
 * $Log$
 * Revision 1.28.2.2  2004/03/09 15:12:38  nalin
 * - fix the laus patch. and i suck.
 *
 * Revision 1.28.2.1  2004/02/03 20:28:46  nalin
 * - backport HAVE_LIBLAUS changes from HEAD
 *
 * Revision 1.28  2001/11/21 19:38:57  nalin
 * free handlers at clean-up time
 *
 * Revision 1.27  2001/11/21 19:38:33  nalin
 * free handlers at clean-up time
 *
 * Revision 1.26  2001/11/21 17:54:59  nalin
 * fix some memory leaks (reported by Fernando Trias)
 *
 */

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

#define STACK_DATA_NAME "pam_stack_saved_stacks"
struct stack_data {
	char *service;
	int debug;
	pam_handle_t *pamh;
	struct stack_data *next;
};

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
   What's surprising is that this simplifies things due to the lack of a need
   to check for error return codes. */
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
				if(dest->authtok) {
					_pam_drop(dest->authtok);
				}
				dest->authtok = _pam_strdup(source->authtok);
			} else {
				reason = "source is NULL";
			}
			break;
		case PAM_CONV:
			name = "PAM_CONV";
			if(source->pam_conversation && !dest->pam_conversation) {
				copied = 1;
				dest->pam_conversation = calloc(1, sizeof(struct pam_conv));
				*dest->pam_conversation = *source->pam_conversation;
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
				if(dest->oldauthtok) {
					_pam_drop(dest->oldauthtok);
				}
				dest->oldauthtok = _pam_strdup(source->oldauthtok);
			} else {
				reason = "source is NULL";
			}
			break;
		case PAM_RHOST:
			name = "PAM_RHOST";
			if(source->rhost) {
				copied = 1;
				if(dest->rhost) {
					_pam_drop(dest->rhost);
				}
				dest->rhost = _pam_strdup(source->rhost);
			} else {
				reason = "source is NULL";
			}
			break;
		case PAM_RUSER:
			name = "PAM_RUSER";
			if(source->ruser) {
				copied = 1;
				if(dest->ruser) {
					_pam_drop(dest->ruser);
				}
				dest->ruser = _pam_strdup(source->ruser);
			} else {
				reason = "source is NULL";
			}
			break;
		case PAM_SERVICE:
			name = "PAM_SERVICE";
			if(source->service_name) {
				copied = 1;
				if(dest->service_name) {
					_pam_drop(dest->service_name);
				}
				dest->service_name = _pam_strdup(source->service_name);
			} else {
				reason = "source is NULL";
			}
			break;
		case PAM_TTY:
			name = "PAM_TTY";
			if(source->tty) {
				copied = 1;
				if(dest->tty) {
					_pam_drop(dest->tty);
				}
				dest->tty = _pam_strdup(source->tty);
			} else {
				reason = "source is NULL";
			}
			break;
		case PAM_USER:
			name = "PAM_USER";
			if(source->user) {
				copied = 1;
				if(dest->user) {
					_pam_drop(dest->user);
				}
				dest->user = _pam_strdup(source->user);
			} else {
				reason = "source is NULL";
			}
			break;
		case PAM_USER_PROMPT:
			name = "PAM_USER_PROMPT";
			if(source->prompt) {
				copied = 1;
				if(dest->prompt) {
					_pam_drop(dest->prompt);
				}
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

static void
_pam_stack_cleanup(pam_handle_t *pamh, void *data, int status)
{
	struct stack_data *stack_this = (struct stack_data*) data, *next;
	while(stack_this != NULL) {
		if(stack_this->debug) {
			openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
			syslog(LOG_DEBUG, "freeing stack data for `%s' service",
			       stack_this->service);
			closelog();
		}
		/* Clean up and bug out.  Don't free the ITEMs because they're
		 * shared by the parent's pamh.  Because of how setting items
		 * works, we don't actually leak memory doing this (!). */
		next = stack_this->next;
		stack_this->pamh->data = NULL;
		_pam_free_handlers(stack_this->pamh);
		_pam_drop(stack_this->pamh->pam_conversation);
		_pam_drop(stack_this->pamh->service_name);
		_pam_drop(stack_this->pamh->user);
		_pam_drop(stack_this->pamh->authtok);
		_pam_drop(stack_this->pamh->oldauthtok);
		_pam_drop(stack_this->pamh->tty);
		_pam_drop(stack_this->pamh->rhost);
		_pam_drop(stack_this->pamh->ruser);
		_pam_drop_env(stack_this->pamh);
		_pam_drop(stack_this->pamh);
		free(stack_this->service);
		free(stack_this);
		stack_this = next;
	}
}

static int
_pam_stack_dispatch(pam_handle_t *pamh, int flags, int argc, const char **argv,
		    int which_stack)
{
	char **env = NULL, *service = NULL;
	const char *parent_service = NULL;
	int debug = 0, i = 0, ret = PAM_SUCCESS, final_ret = PAM_SUCCESS;
	struct stack_data *stack_data = NULL, *stack_this;

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

	/* Log that we're initializing. */
	if(debug) {
		openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
		syslog(LOG_DEBUG, "initializing");
		closelog();
	}

	/* Retrieve a previously-used stack, if we've been called before. */
	if(pam_get_data(pamh, STACK_DATA_NAME, (const void**)&stack_data) != PAM_SUCCESS) {
		stack_data = NULL;
	}

	/* Search for the record for this stack. */
	stack_this = stack_data;
	while(stack_this != NULL) {
		if(strcmp(service, stack_this->service) == 0) {
			break;
		}
		stack_this = stack_this->next;
	}

	/* If we didn't find one, create one and put it at the front of the
	 * list of substacks we have contexts for. */
	if(stack_this == NULL) {
		if(debug) {
			openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
			syslog(LOG_DEBUG, "creating child stack `%s'", service);
			closelog();
		}

		stack_this = malloc(sizeof(struct stack_data));
		if(stack_this == NULL) {
			return PAM_BUF_ERR;
		}

		memset(stack_this, 0, sizeof(struct stack_data));
		stack_this->service = _pam_strdup(service);
		stack_this->pamh = calloc(1, sizeof(pam_handle_t));

		/* Create an environment for the child. */
		if(debug) {
			openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
			syslog(LOG_DEBUG, "creating environment");
			closelog();
		}
		ret = _pam_make_env(stack_this->pamh);
		if(ret != PAM_SUCCESS) {
			openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
			syslog(LOG_ERR, "_pam_make_env() returned %s",
			       pam_strerror(stack_this->pamh, ret));
			closelog();
			return PAM_SYSTEM_ERR;
		}

		/* Set the service.  This loads the service modules. */
		ret = pam_set_item(stack_this->pamh, PAM_SERVICE, service);
		if(ret != PAM_SUCCESS) {
			openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
			syslog(LOG_ERR, "pam_set_item(PAM_SERVICE) returned %d (%s)",
			       ret, pam_strerror(stack_this->pamh, ret));
			closelog();
			return PAM_SYSTEM_ERR;
		}

		/* Initialize the handlers for the substack. */
		_pam_start_handlers(stack_this->pamh);
		ret = _pam_init_handlers(stack_this->pamh);
		if(ret != PAM_SUCCESS) {
			openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
			syslog(LOG_ERR, "_pam_init_handlers() returned %d (%s)",
			       ret, pam_strerror(stack_this->pamh, ret));
			closelog();
			return PAM_SYSTEM_ERR;
		}

		/* Insert the data item at the end of the stack list, or make
		 * it the head if we don't have one yet. */
		if(stack_data == NULL) {
			pam_set_data(pamh, STACK_DATA_NAME, stack_this,
				     _pam_stack_cleanup);
		} else {
			while(stack_data->next != NULL) {
				stack_data = stack_data->next;
			}
			stack_data->next = stack_this;
		}

	} else {
		if(debug) {
			openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
			syslog(LOG_DEBUG, "found previously-used child stack "
			       "`%s'", service);
			closelog();
		}
	}
	stack_this->debug = debug;

	/* Copy the environment from the upper stack to the lower stack. */
	env = pam_getenvlist(pamh); 
	for(i = 0; (env != NULL) && (env[i] != NULL); i++) {
		if(debug) {
			openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
			syslog(LOG_DEBUG, "setting environment \"%s\" in child",
			       env[i]);
			closelog();
		}
		pam_putenv(stack_this->pamh, env[i]);
	}

	/* Copy named PAM items to the child. */
	_pam_stack_copy(pamh, stack_this->pamh, PAM_AUTHTOK, debug ? "child" : NULL);
	_pam_stack_copy(pamh, stack_this->pamh, PAM_CONV, debug ? "child" : NULL);
	_pam_stack_copy(pamh, stack_this->pamh, PAM_FAIL_DELAY, debug ? "child" : NULL);
	_pam_stack_copy(pamh, stack_this->pamh, PAM_OLDAUTHTOK, debug ? "child" : NULL);
	_pam_stack_copy(pamh, stack_this->pamh, PAM_RHOST, debug ? "child" : NULL);
	_pam_stack_copy(pamh, stack_this->pamh, PAM_RUSER, debug ? "child" : NULL);
	_pam_stack_copy(pamh, stack_this->pamh, PAM_SERVICE, debug ? "child" : NULL);
	_pam_stack_copy(pamh, stack_this->pamh, PAM_TTY, debug ? "child" : NULL);
	_pam_stack_copy(pamh, stack_this->pamh, PAM_USER, debug ? "child" : NULL);
	_pam_stack_copy(pamh, stack_this->pamh, PAM_USER_PROMPT, debug ? "child" : NULL);

	/* Pass the generic data pointer, too. */
	if(debug) {
		openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
		syslog(LOG_DEBUG, "passing data to child");
		closelog();
	}
	stack_this->pamh->data = pamh->data;
#if HAVE_LIBLAUS
	stack_this->pamh->laus_state = pamh->laus_state;
#endif

	/* Now call the substack. */
	if(debug) {
		openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
		syslog(LOG_DEBUG, "calling substack");
		closelog();
	}
	final_ret = _pam_dispatch(stack_this->pamh, flags, which_stack);
	if(debug) {
		openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
		syslog(LOG_DEBUG, "substack returned %d (%s)", final_ret,
		       pam_strerror(stack_this->pamh, final_ret));
		closelog();
	}

	/* Copy the useful data back up to the main stack, environment first. */
	env = pam_getenvlist(stack_this->pamh); 
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
	_pam_stack_copy(stack_this->pamh, pamh, PAM_AUTHTOK, debug ? "parent" : NULL);
	_pam_stack_copy(stack_this->pamh, pamh, PAM_CONV, debug ? "parent" : NULL);
	_pam_stack_copy(stack_this->pamh, pamh, PAM_FAIL_DELAY, debug ? "parent" : NULL);
	_pam_stack_copy(stack_this->pamh, pamh, PAM_OLDAUTHTOK, debug ? "parent" : NULL);
	_pam_stack_copy(stack_this->pamh, pamh, PAM_RHOST, debug ? "parent" : NULL);
	_pam_stack_copy(stack_this->pamh, pamh, PAM_RUSER, debug ? "parent" : NULL);
	_pam_stack_copy(stack_this->pamh, pamh, PAM_SERVICE, debug ? "parent" : NULL);
	_pam_stack_copy(stack_this->pamh, pamh, PAM_TTY, debug ? "parent" : NULL);
	_pam_stack_copy(stack_this->pamh, pamh, PAM_USER, debug ? "parent" : NULL);
	_pam_stack_copy(stack_this->pamh, pamh, PAM_USER_PROMPT, debug ? "parent" : NULL);

	/* Wow, passing the extra data back is hard. */
	if(debug) {
		openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
		syslog(LOG_DEBUG, "passing data back");
		closelog();
	}
#if HAVE_LIBLAUS
	pamh->laus_state = stack_this->pamh->laus_state;
#endif
	pamh->data = stack_this->pamh->data;
	if(debug) {
		openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
		syslog(LOG_DEBUG, "passing former back");
		closelog();
	}

	if(debug) {
		openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
		syslog(LOG_DEBUG, "returning %d (%s)", final_ret,
		       pam_strerror(stack_this->pamh, final_ret));
		closelog();
	}

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

