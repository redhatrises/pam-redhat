#include <glib.h>
#include <unistd.h>

#ifndef _CHMOD_H
#define _CHMOD_H

#ifndef STATIC
#define STATIC
#endif

STATIC int chmod_filelist (char *mode, uid_t user, gid_t group, GSList *filelist);
STATIC int chmod_file (char *mode, uid_t user, gid_t group, char *filename);

#endif /* _CHMOD_H */
