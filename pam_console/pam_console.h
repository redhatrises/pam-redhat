/* Copyright 1999, 2005 Red Hat, Inc.
 * This software may be used under the terms of the GNU General Public
 * License, available in the file COPYING accompanying this file.
 */
#ifndef _PAM_CONSOLE_H
#define _PAM_CONSOLE_H
#include <security/pam_modules.h>

/* pam_console.c */

static void
_pam_log(int err, int debug_p, const char *format, ...);

#endif /* _PAM_CONSOLE_H */
