#ifndef libmisc_libmisc_h
#define libmisc_libmisc_h

#include <security/pam_modules.h>
#include <sys/types.h>
#include <grp.h>
#include <pwd.h>

/* get */
struct passwd *libmisc_getpwnam(pam_handle_t *pamh, const char *user);
struct passwd *libmisc_getpwuid(pam_handle_t *pamh, uid_t uid);
struct group *libmisc_getgrnam(pam_handle_t *pamh, const char *group);
struct group *libmisc_getgrgid(pam_handle_t *pamh, gid_t gid);

/* ingroup */
int libmisc_user_in_group_nam_nam(pam_handle_t *pamh,
				  const char *user, const char *group);
int libmisc_user_in_group_uid_nam(pam_handle_t *pamh,
				  uid_t user, const char *group);
int libmisc_user_in_group_nam_gid(pam_handle_t *pamh,
				  const char *user, gid_t group);
int libmisc_user_in_group_uid_gid(pam_handle_t *pamh,
				  uid_t user, gid_t group);

/* conv */
int libmisc_converse(pam_handle_t *pamh,
		     struct pam_message *messages, int n_prompts,
		     struct pam_response **responses);
void libmisc_free_responses(struct pam_response *responses, int n_responses);

/* retryio */
ssize_t libmisc_retry_read(int fd, void *buf, size_t length);
ssize_t libmisc_retry_write(int fd, const void *buf, size_t length);

/* item */
int libmisc_set_string_item(pam_handle_t *pamh, int item, const char *value);
int libmisc_get_string_item(pam_handle_t *pamh, int item, const char **value);
int libmisc_get_conv_item(pam_handle_t *pamh, const struct pam_conv **conv);

#endif
