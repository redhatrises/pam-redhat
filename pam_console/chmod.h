#include <glib.h>
#include <unistd.h>

#ifndef _CHMOD_H
#define _CHMOD_H

#ifndef STATIC
#define STATIC
#endif

STATIC int chmod_files (const char *mode, uid_t user, gid_t group, char *filename, GSList *filelist);

#endif /* _CHMOD_H */
