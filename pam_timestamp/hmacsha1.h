#ifndef pam_timestamp_hmacfile_h
#define pam_timestamp_hmacfile_h

#include <sys/types.h>

size_t hmac_sha1_size(void);
void hmac_sha1_generate(char **mac, size_t *mac_length,
			const unsigned char *key, size_t key_length,
			const char *text, size_t text_length);
void hmac_sha1_generate_file(char **mac, size_t *mac_length,
			     const char *keyfile, uid_t owner, gid_t group,
			     const char *text, size_t text_length);

#endif
