/*
 * Copyright 2003,2004 Red Hat, Inc.
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
