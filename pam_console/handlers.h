/* Copyright 2005 Red Hat, Inc.
 * This software may be used under the terms of the GNU General Public
 * License, available in the file COPYING accompanying this file.
 */
#ifndef _HANDLERS_H
#define _HANDLERS_H

#ifndef STATIC
#define STATIC
#endif

#define HANDLERS_MAXLINELEN 2000

STATIC int console_parse_handlers (const char *filename);
STATIC void console_run_handlers(int lock, const char *user, const char *tty);
STATIC const char *console_get_regexes(void);

#endif /* _HANDLERS_H */
