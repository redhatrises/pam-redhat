/* Copyright 1999 Red Hat Software, Inc.
 * This software may be used under the terms of the GNU General Public
 * License, available in the file COPYING accompanying this file
 */
#include "../../_pam_aconf.h"
#include <sys/types.h>
#include <regex.h>
#include "pam_console.h"

#ifndef STATIC
#define STATIC
#endif

STATIC void
do_regerror(int errcode, const regex_t *preg) {
    char *errbuf;
    size_t errbuf_size;

    errbuf_size = regerror(errcode, preg, NULL, 0); /* missing ; */
    errbuf = alloca(errbuf_size);
    if(!errbuf) {
	perror("alloca");
	return;
    }

    regerror(errcode, preg, errbuf, errbuf_size);
    _pam_log(LOG_ERR, 0,
	     "regular expression error %s", errbuf);
}
