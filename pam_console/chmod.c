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

/* Return a freshly allocated string containing the filenames
   in directory DIR, separated by '\0' characters;
   the end is marked by two '\0' characters in a row.
   NAME_SIZE is the number of bytes to initially allocate
   for the string; it will be enlarged as needed.
   Return NULL if DIR cannot be opened or if out of memory. */

static char *
savedir (const char *dir, unsigned name_size)
{
  DIR *dirp;
  struct dirent *dp;
  char *name_space;
  char *namep;

  dirp = opendir (dir);
  if (dirp == NULL)
    return NULL;

  name_space = (char *) malloc (name_size);
  if (name_space == NULL)
    {
      closedir (dirp);
      return NULL;
    }
  namep = name_space;

  while ((dp = readdir (dirp)) != NULL)
    {
      /* Skip "." and ".." (some NFS filesystems' directories lack them). */
      if (dp->d_name[0] != '.'
	  || (dp->d_name[1] != '\0'
	      && (dp->d_name[1] != '.' || dp->d_name[2] != '\0')))
	{
	  unsigned size_needed = (namep - name_space) + NAMLEN (dp) + 2;

	  if (size_needed > name_size)
	    {
	      char *new_name_space;

	      while (size_needed > name_size)
		name_size += 1024;

	      new_name_space = realloc (name_space, name_size);
	      if (new_name_space == NULL)
		{
		  closedir (dirp);
		  return NULL;
		}
	      namep += new_name_space - name_space;
	      name_space = new_name_space;
	    }
	  namep = stpcpy (namep, dp->d_name) + 1;
	}
    }
  *namep = '\0';
  if (CLOSEDIR (dirp))
    {
      free (name_space);
      return NULL;
    }
  return name_space;
}


/* end included files */





static int change_dir_mode __P ((const char *dir,
				 const struct mode_change *changes,
				 const struct stat *statp));

/* Change the mode of FILE according to the list of operations CHANGES.
   If DEREF_SYMLINK is nonzero and FILE is a symbolic link, change the
   mode of the referenced file.  If DEREF_SYMLINK is zero, ignore symbolic
   links.  Return 0 if successful, 1 if errors occurred. */

static int
change_file_mode (const char *file, const struct mode_change *changes,
		  const int deref_symlink)
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

  if (newmode != (file_stats.st_mode & 07777))
    {
      if (!chmod (file, (int) newmode) == 0)
	{
	  errors = 1;
	}
    }

  if (S_ISDIR (file_stats.st_mode))
    errors |= change_dir_mode (file, changes, &file_stats);
  return errors;
}

/* Recursively change the modes of the files in directory DIR
   according to the list of operations CHANGES.
   STATP points to the results of lstat on DIR.
   Return 0 if successful, 1 if errors occurred. */

static int
change_dir_mode (const char *dir, const struct mode_change *changes,
		 const struct stat *statp)
{
  char *name_space, *namep;
  char *path;			/* Full path of each entry to process. */
  unsigned dirlength;		/* Length of DIR and '\0'. */
  unsigned filelength;		/* Length of each pathname to process. */
  unsigned pathlength;		/* Bytes allocated for `path'. */
  int errors = 0;

  errno = 0;
  name_space = savedir (dir, statp->st_size);
  if (name_space == NULL)
    {
      if (errno)
	{
	  return 1;
	}
    }

  dirlength = strlen (dir) + 1;	/* + 1 is for the trailing '/'. */
  pathlength = dirlength + 1;
  /* Give `path' a dummy value; it will be reallocated before first use. */
  path = g_malloc (pathlength);
  strcpy (path, dir);
  path[dirlength - 1] = '/';

  for (namep = name_space; *namep; namep += filelength - dirlength)
    {
      filelength = dirlength + strlen (namep) + 1;
      if (filelength > pathlength)
	{
	  pathlength = filelength * 2;
	  path = g_realloc (path, pathlength);
	}
      strcpy (path + dirlength, namep);
      errors |= change_file_mode (path, changes, 0);
    }
  free (path);
  free (name_space);
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
chmod_filelist (char *mode, uid_t user, gid_t group, GSList *filelist)
{
  struct mode_change *changes;
  int errors = 0;
  char *filename;
  glob_t result;
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

  for (i = 0; i < result.gl_pathc; i++) {
    errors |= change_file_mode (result.gl_pathv[i], changes, 1);
    errors |= chown (result.gl_pathv[i], user, group);
#if 0
    _pam_log(LOG_DEBUG, TRUE,
	     "file %s (%d): mode %s\n", result.gl_pathv[i], user, mode);
#endif
  }

  globfree(&result);

  return (errors);
}

STATIC int
chmod_file (char *mode, uid_t user, gid_t group, char *filename)
{
  struct mode_change *changes;
  int errors = 0;
  glob_t result;
  int flags = 0;
  int i, rc;

  changes = mode_compile (mode,
			  MODE_MASK_EQUALS | MODE_MASK_PLUS | MODE_MASK_MINUS);
  if (changes == MODE_INVALID) DIE(1)
  else if (changes == MODE_MEMORY_EXHAUSTED) DIE(1)

  rc = glob(filename, flags, glob_errfn, &result);
  if (rc == GLOB_NOSPACE) DIE(1)

  for (i = 0; i < result.gl_pathc; i++) {
    errors |= change_file_mode (result.gl_pathv[i], changes, 1);
    errors |= chown (result.gl_pathv[i], user, group);
#if 0
    _pam_log(LOG_DEBUG, TRUE,
    	     "file %s (%d): mode %s\n", result.gl_pathv[i], user, mode);
#endif
  }

  globfree(&result);

  return (errors);
}
