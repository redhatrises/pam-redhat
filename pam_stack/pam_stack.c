/******************************************************************************
 * A module for Linux-PAM that will divert to another file and use configuration
 * information from it, percolating the result code back up.  Recursion is fun.
 *
 * Copyright (c) 2000 Red Hat, Inc.
 * Written by Nalin Dahyabhai <nalin@redhat.com>
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

/* Oh yeah, this is cheap. */
#include "../../libpam/include/security/_pam_types.h"
#include "../../libpam/pam_private.h"
#include <sys/syslog.h>
#include <stdlib.h>
#include <string.h>

#define MODULE_NAME "pam_stack"

static struct {
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
};

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
	pam_handle_t *sub_pamh = NULL;
	int debug = 0, i = 0, ret = PAM_SUCCESS;

	/* Figure out where to save the main service name. */
	for(i = 0; i < sizeof(defined_items) / sizeof(defined_items[0]); i++) {
		if(defined_items[i].num == PAM_SERVICE) break;
	}
	if(i >= sizeof(defined_items) / sizeof(defined_items[0])) {
		syslog(LOG_WARNING, MODULE_NAME ": serious internal problems!");
		return PAM_SYSTEM_ERR;
	}

	/* Sign-on message. */
	if(debug) syslog(LOG_DEBUG, MODULE_NAME ": called from \"%s\"",
			 defined_items[i].item);

	/* Save the main service name. */
	ret = pam_get_item(pamh, PAM_SERVICE, &defined_items[i].item);
	if(ret != PAM_SUCCESS) {
		syslog(LOG_WARNING, MODULE_NAME ": pam_get_data(PAM_SERVICE) "
		       "returned %s", pam_strerror(pamh, ret));
		return PAM_SYSTEM_ERR;
	}

	/* Parse arguments. */
	for(i = 0; i < argc; i++) {
		if(strncmp("debug", argv[i], 5) == 0) {
			debug = 1;
		}
		if(strncmp("service=", argv[i], 8) == 0) {
			if(service != NULL) {
				free(service);
			}
			service = strdup(argv[i] + 8);
		}
	}

	if(service == NULL) {
		syslog(LOG_WARNING, MODULE_NAME
		       ": required argument \"service\" not given");
		return PAM_SYSTEM_ERR;
	}

	/* Create and initialize a pam_handle_t structure for our substack. */
	if(debug) syslog(LOG_DEBUG, MODULE_NAME ": initializing");
	sub_pamh = calloc(1, sizeof(pam_handle_t));

	if(debug) syslog(LOG_DEBUG, MODULE_NAME ": creating environment");
	if(_pam_make_env(sub_pamh) != PAM_SUCCESS) {
		syslog(LOG_WARNING, MODULE_NAME ": _pam_make_env() "
		       "returned %s", pam_strerror(pamh, ret));
		return PAM_SYSTEM_ERR;
	}

	for(i = 0; i < sizeof(defined_items) / sizeof(defined_items[0]); i++) {
		pam_get_item(pamh, defined_items[i].num,
			     &defined_items[i].item);
		if(defined_items[i].item == NULL) {
			syslog(LOG_DEBUG, MODULE_NAME ": item %s is NULL",
			       defined_items[i].name);
			continue;
		}
		if(debug && (defined_items[i].num != PAM_CONV)) {
			syslog(LOG_DEBUG, MODULE_NAME ": setting item %s to "
			       "\"%s\"", defined_items[i].name,
			       defined_items[i].item);
		}
		ret = pam_set_item(sub_pamh, defined_items[i].num,
			           defined_items[i].item);
		if(ret != PAM_SUCCESS) {
			syslog(LOG_WARNING, MODULE_NAME ": pam_set_item(%s) "
			       "returned %s", defined_items[i].name,
			       pam_strerror(pamh, ret));
			return PAM_SYSTEM_ERR;
		}
	}

	if(debug) syslog(LOG_DEBUG, MODULE_NAME
			 ": setting item PAM_SERVICE to %s", service);
	pam_set_item(sub_pamh, PAM_SERVICE, service);

	/* Initialize the handlers. */
	_pam_start_handlers(sub_pamh);
	if(_pam_init_handlers(sub_pamh) != PAM_SUCCESS) {
		syslog(LOG_WARNING, MODULE_NAME ": _pam_init_handlers() "
		       "returned %s", defined_items[i].num,
		       pam_strerror(pamh, ret));
		return PAM_SYSTEM_ERR;
	}

	/* Copy data from the upper stack to the lower stack. */
	env = pam_getenvlist(pamh); 
	for(i = 0; (env != NULL) && (env[i] != NULL); i++) {
		if(debug) syslog(LOG_DEBUG, MODULE_NAME ": setting environment "
				 "\"%s\" in child", env[i]);
		pam_putenv(sub_pamh, env[i]);
	}
	if(debug) syslog(LOG_DEBUG, MODULE_NAME ": passing data to child");
	sub_pamh->data = pamh->data;

	/* Now call the substack. */
	if(debug) syslog(LOG_DEBUG, MODULE_NAME ": calling substack");
	ret = _pam_dispatch(sub_pamh, flags, which_stack);

	/* Copy the useful data back up to the main stack. */
	env = pam_getenvlist(sub_pamh); 
	for(i = 0; (env != NULL) && (env[i] != NULL); i++) {
		if(debug) syslog(LOG_DEBUG, MODULE_NAME ": setting environment "
				 "\"%s\" in parent", env[i]);
		pam_putenv(pamh, env[i]);
	}
	for(i = 0; i < sizeof(defined_items) / sizeof(defined_items[0]); i++) {
		pam_get_item(sub_pamh, defined_items[i].num,
			     &defined_items[i].item);
		if(defined_items[i].item == NULL) {
			syslog(LOG_DEBUG, MODULE_NAME ": substack's item %s is "
			       "NULL", defined_items[i].name);
			continue;
		}
		if(debug && (defined_items[i].num != PAM_CONV)) {
			syslog(LOG_DEBUG, MODULE_NAME ": setting parent item %s"
			       " to \"%s\"", defined_items[i].name,
			       defined_items[i].item);
		}
		ret = pam_set_item(pamh, defined_items[i].num,
			           defined_items[i].item);
		if(ret != PAM_SUCCESS) {
			syslog(LOG_WARNING, MODULE_NAME ": pam_set_item(%s) "
			       "returned %s", defined_items[i].name,
			       pam_strerror(pamh, ret));
			return PAM_SYSTEM_ERR;
		}
	}

	if(debug) syslog(LOG_DEBUG, MODULE_NAME ": passing data back");
	pamh->data = sub_pamh->data;

	/* Clean up and bug out.  Don't free the ITEMs because they're shared
	   by the parent's pamh. */
	sub_pamh->data = NULL;
	_pam_drop_env(sub_pamh);
	if(service != NULL) {
		_pam_drop(service);
	}
	_pam_drop(sub_pamh);
	if(debug) syslog(LOG_DEBUG, MODULE_NAME ": returning %d (%s)", ret,
			 pam_strerror(sub_pamh, ret));

	return ret;
}
