/*
 * Read in the file, and grant ownerships to whoever has the lock.
 */

#include <errno.h>
#include <glib.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#define STATIC static
#include "pam_console.h"

#define CAST_ME_HARDER (const void**)

static char consolelock[PATH_MAX] = "/var/lock/console.lock";
static char consoleperms[PATH_MAX] = "/etc/security/console.perms";
static int debug = 0;

static void *
_do_malloc(size_t req)
{
	void *ret;
	ret = malloc(req);
	if (!ret) abort();
	return ret;
}

static void
_pam_log(int err, int debug_p, const char *format, ...)
{
	va_list args;
	if (debug_p && !debug) return;
	fprintf(stderr, format, args);
}

int
main(int argc, char **argv)
{
	int fd;
	int i;
	struct stat st;
	char *consoleuser;
	enum {Set, Reset} sense = Set;

	if(argv[1] && !strcmp(argv[1], "-r")) {
		sense = Reset;
	}

	parse_file(consoleperms);
        fd = open(consolelock, O_RDONLY);
	if (fd != -1) {
		if (fstat (fd, &st)) {
			fprintf(stderr,
			       "\"impossible\" fstat error on %s", consolelock);
			goto return_error;
		}
		if (st.st_size) {
			consoleuser = _do_malloc(st.st_size+1);
			memset(consoleuser, '\0', st.st_size);
			if ((i = read (fd, consoleuser, st.st_size)) == -1) {
				fprintf(stderr,
				       "\"impossible\" read error on %s",
				       consolelock);
				goto return_error;
			}
			consoleuser[i] = '\0';
		}
		close (fd);
	} else {
		sense = Reset;
	}
	if((sense == Set) && (consoleuser != NULL)) {
		set_permissions("tty0", consoleuser, TRUE);
	}
	if(sense == Reset) {
		reset_permissions("tty0", TRUE);
	}
	return 0;

return_error:
	return 1;
}

/* supporting functions included from other .c files... */

#include "regerr.c"
#include "chmod.c"
#include "modechange.c"
#include "config.lex.c"
#include "config.tab.c"
