/*
 * Read in the file, and grant ownerships to whoever has the lock.
 */

#include "../config.h"
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
#include "pam_console.h"

#include <security/_pam_macros.h>

#define CAST_ME_HARDER (const void**)

static char consolelock[PATH_MAX] = LOCKDIR "/console.lock";
static char consoleperms[PATH_MAX] = "/etc/security/console.perms";
static int debug = 0;

void *
_do_malloc(size_t req)
{
	void *ret;
	ret = malloc(req);
	if (!ret) abort();
	return ret;
}

void
_pam_log(int err, int debug_p, const char *format, ...)
{
	va_list args;
	if (debug_p && !debug) return;
        va_start(args, format);
	fprintf(stderr, format, args);
	va_end(args);
}

int
main(int argc, char **argv)
{
	int fd;
	int i, c;
	struct stat st;
	char *consoleuser = NULL;
	enum {Set, Reset} sense = Set;

	while((c = getopt(argc, argv, "c:f:r")) != -1) {
		switch(c) {
			case 'c': strncpy(consoleperms, optarg, sizeof(consoleperms) - 1);
				  consoleperms[sizeof(consoleperms) - 1] = '\0';
				  break;
			case 'f': chmod_set_fstab(optarg);
				  break;
			case 'r':
				  sense = Reset;
				  break;
			default:
				  fprintf(stderr, "usage: %s [-f /etc/fstab] "
					  "[-c %s] [-r]\n", argv[0],
					  consoleperms);
				  exit(1);
		}
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
		set_permissions(NULL, "tty0", consoleuser, TRUE);
	}
	if(sense == Reset) {
		reset_permissions(NULL, "tty0", TRUE);
	}
	return 0;

return_error:
	return 1;
}
