/* Yet another sha1sum implementation.  This one doesn't know how to check
 * sha1sum files, though.  Use the version which comes with coreutils for that.
 *
 * Copyright (c) 2003 Red Hat, Inc.
 * Written by Nalin Dahyabhai <nalin@redhat.com>
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
 *
 */

#ident "$Id$"

#include "../config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include "sha1.h"
int
main(int argc, char **argv)
{
	char buf[109], output[SHA1_OUTPUT_SIZE];
	int fd, i, j, count;
	struct sha1_context sha1;

	for (i = 1; i < argc; i++) {
		fd = open(argv[i], O_RDONLY);
		if (fd != -1) {
			sha1_init(&sha1);
			do {
				count = read(fd, buf, sizeof(buf));
				if ((count != 0) && (count != -1)) {
					sha1_update(&sha1, buf, count);
				}
			} while (count != 0);
			sha1_output(&sha1, output);
			for (j = 0; j < sizeof(output); j++) {
				printf("%02x", output[j] & 0xff);
			}
			printf("  %s\n", argv[i]);
			close(fd);
		}
	}
	return 0;
}
