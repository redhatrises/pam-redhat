#ifndef libmisc_libmisc_h
#define libmisc_libmisc_h

#include <security/pam_modules.h>
#include <sys/types.h>
#include <grp.h>
#include <pwd.h>
struct passwd *libmisc_getpwnam(pam_handle_t *pamh, const char *user);
struct passwd *libmisc_getpwuid(pam_handle_t *pamh, uid_t uid);
struct group *libmisc_getgrnam(pam_handle_t *pamh, const char *group);
struct group *libmisc_getgrgid(pam_handle_t *pamh, gid_t gid);
int libmisc_user_in_group_nam_nam(pam_handle_t *pamh,
				  const char *user, const char *group);
int libmisc_user_in_group_uid_nam(pam_handle_t *pamh,
				  uid_t user, const char *group);
int libmisc_user_in_group_nam_gid(pam_handle_t *pamh,
				  const char *user, gid_t group);
int libmisc_user_in_group_uid_gid(pam_handle_t *pamh,
				  uid_t user, gid_t group);

#endif
