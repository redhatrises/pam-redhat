/* Copyright 1999, 2005 Red Hat, Inc.
 * This software may be used under the terms of the GNU General Public
 * License, available in the file COPYING accompanying this file.
 */
#ifndef _CONFIG_H
#define _CONFIG_H
#include <glib.h>

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

STATIC void
parse_file(const char *name);

STATIC int
check_console_name (const char *consolename);

STATIC int
set_permissions(const char *consolename, const char *username, GSList *files);

STATIC int
reset_permissions(const char *consolename, GSList *files);

#endif /* _CONFIG_H */
