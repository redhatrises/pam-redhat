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

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
				   int argc, const char **argv)
{
	return _pam_stack_dispatch(pamh, flags, argc, argv, PAM_AUTHENTICATE);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
			      int argc, const char **argv)
{
	return _pam_stack_dispatch(pamh, flags, argc, argv, PAM_SETCRED);
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
				   int argc, const char **argv)
{
	return _pam_stack_dispatch(pamh, flags, argc, argv, PAM_OPEN_SESSION);
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
				    int argc, const char **argv)
{
	return _pam_stack_dispatch(pamh, flags, argc, argv, PAM_CLOSE_SESSION);
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
				   int argc, const char **argv)
{
	return _pam_stack_dispatch(pamh, flags, argc, argv, PAM_ACCOUNT);
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags,
				int argc, const char **argv)
{
	return _pam_stack_dispatch(pamh, flags, argc, argv, PAM_CHAUTHTOK);
}

static int _pam_stack_dispatch(pam_handle_t *pamh, int flags,
			       int argc, const char **argv,
			       int which_stack)
{
	char **env = NULL, *service = NULL;
	const char **parent_service = NULL;
	pam_handle_t *sub_pamh = NULL;
	int debug = 0, i = 0, ret = PAM_SUCCESS, final_ret = PAM_SUCCESS;
	struct {
		int num;
		const char *name;
		const void *item;
	} defined_items[] = {
		{PAM_SERVICE, "PAM_SERVICE", NULL},
		{PAM_USER, "PAM_USER", NULL},
		{PAM_TTY, "PAM_TTY", NULL},
		{PAM_RHOST, "PAM_RHOST", NULL},
		{PAM_CONV, "PAM_CONV", NULL},

		{PAM_RUSER, "PAM_RUSER", NULL},
		{PAM_USER_PROMPT, "PAM_USER_PROMPT", NULL},
		{PAM_FAIL_DELAY, "PAM_FAIL_DELAY", NULL},

		{PAM_AUTHTOK, "PAM_AUTHTOK", NULL},
		{PAM_OLDAUTHTOK, "PAM_OLDAUTHTOK", NULL},
	};

	/* Figure out where to save the main service name. */
	for(i = 0; i < sizeof(defined_items) / sizeof(defined_items[0]); i++) {
		if(defined_items[i].num == PAM_SERVICE) {
			parent_service = (const char**) &defined_items[i].item;
			break;
		}
	}
	if(i >= sizeof(defined_items) / sizeof(defined_items[0])) {
		openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
		syslog(LOG_ERR, "serious internal problems!");
		closelog();
		return PAM_SYSTEM_ERR;
	}

	/* Save the main service name. */
	ret = pam_get_item(pamh, PAM_SERVICE, &defined_items[i].item);
	if(ret != PAM_SUCCESS) {
		openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
		syslog(LOG_ERR, "pam_get_data(PAM_SERVICE) returned %s",
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
			if(service != NULL) {
				free(service);
			}
			service = strdup(argv[i] + 8);
		}
	}

	/* Sign-on message. */
	if(debug) {
		openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
		syslog(LOG_DEBUG, "called from \"%s\"",
		       parent_service && *parent_service ?
		       *parent_service : "unknown service");
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

	if(debug) {
		openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
		syslog(LOG_DEBUG, "creating environment");
		closelog();
	}
	if(_pam_make_env(sub_pamh) != PAM_SUCCESS) {
		openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
		syslog(LOG_ERR, "_pam_make_env() returned %s",
		       pam_strerror(pamh, ret));
		closelog();
		return PAM_SYSTEM_ERR;
	}

	for(i = 0; i < sizeof(defined_items) / sizeof(defined_items[0]); i++) {
		pam_get_item(pamh, defined_items[i].num,
			     &defined_items[i].item);
		if(defined_items[i].item == NULL) {
			if(debug) {
				openlog("pam_stack", LOG_PID,
					LOG_AUTHPRIV);
				syslog(LOG_DEBUG, "item %s is NULL",
				       defined_items[i].name);
				closelog();
			}
			continue;
		}
		if(debug && (defined_items[i].num != PAM_CONV)) {
			if(debug) {
				openlog("pam_stack", LOG_PID,
					LOG_AUTHPRIV);
				syslog(LOG_DEBUG, "setting item %s to \"%s\"",
				       defined_items[i].name,
				       (const char*)defined_items[i].item);
				closelog();
			}
		}
		ret = pam_set_item(sub_pamh, defined_items[i].num,
			           defined_items[i].item);
		if(ret != PAM_SUCCESS) {
			if(debug) {
				openlog("pam_stack", LOG_PID,
					LOG_AUTHPRIV);
				syslog(LOG_ERR, "pam_set_item(%s) returned %s",
				       defined_items[i].name,
				       pam_strerror(pamh, ret));
				closelog();
			}
			return PAM_SYSTEM_ERR;
		}
	}

	if(debug) {
		openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
		syslog(LOG_DEBUG, "setting item PAM_SERVICE to %s", service);
		closelog();
	}
	pam_set_item(sub_pamh, PAM_SERVICE, service);

	/* Initialize the handlers. */
	_pam_start_handlers(sub_pamh);
	if(_pam_init_handlers(sub_pamh) != PAM_SUCCESS) {
		openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
		syslog(LOG_ERR, "_pam_init_handlers() returned %d (%s)",
		       defined_items[i].num, pam_strerror(pamh, ret));
		closelog();
		return PAM_SYSTEM_ERR;
	}

	/* Copy data from the upper stack to the lower stack. */
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
	if(pamh->fail_delay.set) {
		sub_pamh->fail_delay = pamh->fail_delay;
		if(debug) {
			openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
			syslog(LOG_DEBUG, "passing delay (%u) down",
			       sub_pamh->fail_delay.delay );
			closelog();
		}
	}

	if(debug) {
		openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
		syslog(LOG_DEBUG, "passing data to child");
		closelog();
	}
	sub_pamh->data = pamh->data;

	/* This isn't exactly Correct, but it does seem to work without getting
	 * us into infinite recursion which using set_item() would. */
	if(parent_service && *parent_service)
		sub_pamh->service_name = strdup(*parent_service);

	/* Now call the substack. */
	if(debug) {
		openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
		syslog(LOG_DEBUG, "calling substack");
		closelog();
	}
	final_ret = _pam_dispatch(sub_pamh, flags, which_stack);

	/* Copy the useful data back up to the main stack. */
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
	for(i = 0; i < sizeof(defined_items) / sizeof(defined_items[0]); i++) {
		const void *ignored;
		pam_get_item(pamh, defined_items[i].num, &ignored);
		if(ignored != NULL) {
			if(debug) {
				openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
				syslog(LOG_DEBUG, "not passing %s back up to "
				       "parent", defined_items[i].name);
				closelog();
			}
			continue;
		}
		pam_get_item(sub_pamh, defined_items[i].num,
			     &defined_items[i].item);
		if(defined_items[i].item == NULL) {
			if(debug) {
				openlog("pam_stack", LOG_PID,
					LOG_AUTHPRIV);
				syslog(LOG_DEBUG, "substack's item %s is NULL",
				       defined_items[i].name);
				closelog();
			}
			continue;
		}
		if(debug && (defined_items[i].num != PAM_CONV)) {
			openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
			syslog(LOG_DEBUG, "setting parent item %s to \"%s\"",
			       (const char*)defined_items[i].name,
			       (const char*)defined_items[i].item);
			closelog();
		}
		ret = pam_set_item(pamh, defined_items[i].num,
			           defined_items[i].item);
		if(ret != PAM_SUCCESS) {
			openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
			syslog(LOG_ERR, "pam_set_item(%s) returned %s",
			       defined_items[i].name, pam_strerror(pamh, ret));
			closelog();
			return PAM_SYSTEM_ERR;
		}
	}

	/* Wow, passing the extra data back is hard. */
	if(debug) {
		openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
		syslog(LOG_DEBUG, "passing data back");
		closelog();
	}
	pamh->data = sub_pamh->data;

	/* Clean up and bug out.  Don't free the ITEMs because they're shared
	   by the parent's pamh. */
	sub_pamh->service_name = NULL;
	sub_pamh->data = NULL;
	_pam_drop_env(sub_pamh);
	if(service != NULL) {
		_pam_drop(service);
	}

	if(sub_pamh->fail_delay.set) {
		if(debug) {
			openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
			syslog(LOG_DEBUG, "passing delay (%u) back",
			       sub_pamh->fail_delay.delay );
			closelog();
		}
		if(pamh->fail_delay.set)
			pam_fail_delay(pamh, sub_pamh->fail_delay.delay);
		else
			pamh->fail_delay = sub_pamh->fail_delay;
	}

	if(debug) {
		openlog("pam_stack", LOG_PID, LOG_AUTHPRIV);
		syslog(LOG_DEBUG, "returning %d (%s)", final_ret,
		       pam_strerror(sub_pamh, final_ret));
		closelog();
	}
	_pam_drop(sub_pamh);

	return final_ret;
}
