#ifndef _HANDLERS_H
#define _HANDLERS_H

#ifndef STATIC
#define STATIC
#endif

#define HANDLERS_MAXLINELEN 2000

STATIC int console_parse_handlers (const char *filename);
STATIC int console_run_handlers(int lock, const char *user, const char *tty);

#endif /* _HANDLERS_H */
