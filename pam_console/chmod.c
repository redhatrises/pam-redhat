/* This file is derived from chmod.c, savedir.c, and stpcpy.c, included
   in the GNU fileutils distribution.  It has been changed to be a
   library specifically for use within the Red Hat pam_console module.
   Changes Copyright 1999 Red Hat Software, Inc.
 */

/* chmod -- change permission modes of files
   Copyright (C) 89, 90, 91, 95, 1996 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#include <errno.h>
#include <glob.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>
#include <mntent.h>
#define NAMLEN(dirent) strlen((dirent)->d_name)

#include <glib.h>

#include "chmod.h"
#include "modechange.h"

/* savedir.c -- save the list of files in a directory in a string
   Copyright (C) 1990 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

/* Written by David MacKenzie <djm@gnu.ai.mit.edu>. */

#define CLOSEDIR(d) closedir (d)

#ifdef _D_NEED_STPCPY
/* stpcpy.c -- copy a string and return pointer to end of new string
    Copyright (C) 1989, 1990 Free Software Foundation.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2, or (at your option)
    any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software Foundation,
    Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

/* Copy SRC to DEST, returning the address of the terminating '\0' in DEST.  */

static char *
stpcpy (char *dest, const char *src)
{
  while ((*dest++ = *src++) != '\0')
    /* Do nothing. */ ;
  return dest - 1;
}
#endif /* _D_NEED_STPCPY */

/* end included files */

static int change_dir __P ((const char *dir,
			    const struct mode_change *changes,
			    const struct stat *statp,
			    uid_t user, gid_t group));

/* Change the mode of FILE according to the list of operations CHANGES.
   If DEREF_SYMLINK is nonzero and FILE is a symbolic link, change the
   mode of the referenced file.  If DEREF_SYMLINK is zero, ignore symbolic
   links.  Return 0 if successful, 1 if errors occurred. */

static int
change_file (const char *file, const struct mode_change *changes,
	     const int deref_symlink, uid_t user, gid_t group)
{
  struct stat file_stats;
  unsigned short newmode;
  int errors = 0;

  if (lstat (file, &file_stats))
    {
      return 1;
    }
  if (S_ISLNK (file_stats.st_mode))
    {
      if (stat (file, &file_stats))
	{
	  return 1;
	}
    }

  newmode = mode_adjust (file_stats.st_mode, changes);

  if (S_ISDIR (file_stats.st_mode))
    errors |= change_dir (file, changes, &file_stats, user, group);
  else
    {
      if (newmode != (file_stats.st_mode & 07777))
        {
          if (chmod (file, (int) newmode) == -1)
	    {
	      errors = 1;
	    }
        }
      errors |= chown (file, user, group);
    }

  return errors;
}

/* If the directory is a filesystem listed in /etc/fstab, modify the
 * device special associated with that filesystem. */
static int
change_dir (const char *dir, const struct mode_change *changes,
	    const struct stat *statp, uid_t user, gid_t group)
{
  int errors = 0;
  FILE *fstab;
  struct mntent *mntent;

  fstab = setmntent("/etc/fstab", "r");

  if (fstab == NULL)
    {
      return 1;
    }

  for(mntent = getmntent(fstab); mntent != NULL; mntent = getmntent(fstab))
    {
      if(mntent->mnt_dir &&
         mntent->mnt_fsname &&
	 (strcmp(mntent->mnt_dir, dir) == 0))
        {
          errors |= change_file(mntent->mnt_fsname, changes, TRUE, user, group);
        }
    }

  endmntent(fstab);

  return errors;
}

/* Parse the ASCII mode into a linked list
   of `struct mode_change' and apply that to each file argument. */


static int
glob_errfn(const char *pathname, int theerr) {
  /* silently ignore inaccessible files */
  return 0;
}

#define DIE(n) {fprintf(stderr, "chmod failure\n"); return (n);}

STATIC int
chmod_files (const char *mode, uid_t user, gid_t group,
	     char *single_file, GSList *filelist)
{
  struct mode_change *changes;
  int errors = 0;
  glob_t result;
  char *filename;
  int flags = 0;
  int i, rc;

  changes = mode_compile (mode,
			  MODE_MASK_EQUALS | MODE_MASK_PLUS | MODE_MASK_MINUS);
  if (changes == MODE_INVALID) DIE(1)
  else if (changes == MODE_MEMORY_EXHAUSTED) DIE(1)

  for (; filelist; filelist = filelist->next)
  {
    filename = filelist->data;
    rc = glob(filename, flags, glob_errfn, &result);
    if (rc == GLOB_NOSPACE) DIE(1)
    flags |= GLOB_APPEND;
  }
  if(filename) {
    rc = glob(single_file, flags, glob_errfn, &result);
    if (rc == GLOB_NOSPACE) DIE(1)
  }

  for (i = 0; i < result.gl_pathc; i++) {
    errors |= change_file (result.gl_pathv[i], changes, 1, user, group);
#if 0
    _pam_log(LOG_DEBUG, TRUE,
	     "file %s (%d): mode %s\n", result.gl_pathv[i], user, mode);
#endif
  }

  globfree(&result);

  return (errors);
}
