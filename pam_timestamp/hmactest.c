#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

static void
read_key_file(const char *filename, char **key, int *keylen)
{
	int fd;
	struct stat st;

	*key = NULL;
	*keylen = 0;

	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		return;
	}

	if (fstat(fd, &st) == -1) {
		close(fd);
		return;
	}
	
	*keylen = st.st_size;
	*key = malloc(st.st_size);
	read(fd, *key, st.st_size);
}

int
main(int argc, char **argv)
{
	unsigned char hmac[EVP_MAX_MD_SIZE];
	unsigned int hmaclen;
	const char *keyfile;
	char *key;
	int keylen;
	int i, j;

	keyfile = argv[1];
	for (i = 2; i < argc; i++) {
		read_key_file(keyfile, &key, &keylen);
		HMAC(EVP_sha1(), key, keylen, argv[i], strlen(argv[i]),
		     hmac, &hmaclen);
		for (j = 0; j < hmaclen; j++) {
			printf("%02x", hmac[j] & 0xff);
		}
		printf("  %s\n", argv[i]);
		free(key);
	}
	return 0;
}
