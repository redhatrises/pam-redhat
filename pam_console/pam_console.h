/* Copyright 1999 Red Hat Software, Inc.
 * This software may be used under the terms of the GNU General Public
 * License, available in the file COPYING accompanying this file
 */
#ifndef _PAM_CONSOLE_H
#define _PAM_CONSOLE_H
#include <glib.h>
#include <security/pam_modules.h>
#include <regex.h>
#include "chmod.h"

typedef struct class_s class;
struct class_s {
	char*	name;
	GSList*	list;
};

typedef struct config_s config;
struct config_s {
	class*	console_class;
	char*	mode;
	class*	device_class;
	char*	revert_mode;
	char*	revert_owner;
	char*	revert_group;
};

/* pam_console.c */

void _pam_log(int err, int debug_p, const char *format, ...);
void *_do_malloc(size_t req);

/* config.l */

extern int lineno;
extern char *filename;

/* config.y */

STATIC void
parse_file(char *name);

STATIC int
check_console_name (const char *consolename, int allow_nonroot);

STATIC int
set_permissions(pam_handle_t *pamh, const char *consolename, const char *username, int allow_nonroot);

STATIC int
reset_permissions(pam_handle_t *pamh, const char *consolename, int allow_nonroot);

/* regerr.c */
void do_regerror(int errcode, const regex_t *preg);

#endif /* _PAM_CONSOLE_H */
