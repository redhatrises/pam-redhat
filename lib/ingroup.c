/*
 * Copyright 2004 Red Hat, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "libmisc.h"

#ifdef HAVE_GETGROUPLIST
static int
checkgrouplist(const char *user, gid_t primary, gid_t target)
{
	gid_t *grouplist = NULL;
	int agroups, ngroups, i;
	ngroups = agroups = 3;
	do {
		grouplist = malloc(sizeof(gid_t) * agroups);
		if (grouplist == NULL) {
			return 0;
		}
		ngroups = agroups;
		i = getgrouplist(user, primary, grouplist, &ngroups);
		if ((i < 0) || (ngroups < 1)) {
			agroups *= 2;
			free(grouplist);
		} else {
			for (i = 0; i < ngroups; i++) {
				if (grouplist[i] == target) {
					free(grouplist);
					return 1;
				}
			}
			free(grouplist);
		}
	} while (((i < 0) || (ngroups < 1)) && (agroups < 10000));
	return 0;
}
#endif

static int
libmisc_user_in_group_common(pam_handle_t *pamh,
			     struct passwd *pwd,
			     struct group *grp)
{
	int i;

	if (pwd == NULL) {
		return 0;
	}
	if (grp == NULL) {
		return 0;
	}

	if (pwd->pw_gid == grp->gr_gid) {
		return 1;
	}

	for (i = 0; (grp->gr_mem != NULL) && (grp->gr_mem[i] != NULL); i++) {
		if (strcmp(pwd->pw_name, grp->gr_mem[i]) == 0) {
			return 1;
		}
	}

#ifdef HAVE_GETGROUPLIST
	if (checkgrouplist(pwd->pw_name, pwd->pw_gid, grp->gr_gid)) {
		return 1;
	}
#endif

	return 0;
}

int
libmisc_user_in_group_nam_nam(pam_handle_t *pamh,
			      const char *user, const char *group)
{
	struct passwd *pwd;
	struct group *grp;

	pwd = libmisc_getpwnam(pamh, user);
	grp = libmisc_getgrnam(pamh, group);

	return libmisc_user_in_group_common(pamh, pwd, grp);
}

int
libmisc_user_in_group_nam_gid(pam_handle_t *pamh, const char *user, gid_t group)
{
	struct passwd *pwd;
	struct group *grp;

	pwd = libmisc_getpwnam(pamh, user);
	grp = libmisc_getgrgid(pamh, group);

	return libmisc_user_in_group_common(pamh, pwd, grp);
}

int
libmisc_user_in_group_uid_nam(pam_handle_t *pamh, uid_t user, const char *group)
{
	struct passwd *pwd;
	struct group *grp;

	pwd = libmisc_getpwuid(pamh, user);
	grp = libmisc_getgrnam(pamh, group);

	return libmisc_user_in_group_common(pamh, pwd, grp);
}

int
libmisc_user_in_group_uid_gid(pam_handle_t *pamh, uid_t user, gid_t group)
{
	struct passwd *pwd;
	struct group *grp;

	pwd = libmisc_getpwuid(pamh, user);
	grp = libmisc_getgrgid(pamh, group);

	return libmisc_user_in_group_common(pamh, pwd, grp);
}

