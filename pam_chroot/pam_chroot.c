/*
 * Linux-PAM session chroot()er
 *
 * $Id$
 */

#define	PAM_SM_SESSION

#include <_pam_aconf.h>

#include <security/pam_modules.h>

#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <regex.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>

#define	CONFIG	"/etc/security/chroot.conf"

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
				   int argc, const char **argv)
{
	int ret = PAM_SESSION_ERR;
	int debug = 0;
	int onerr = PAM_SUCCESS;
	char conf_line[LINE_MAX];
	int lineno, err, i;
	char *name, *dir;
	char const *user;
	FILE *conf;

	openlog("pam_chroot", LOG_PID, LOG_AUTHPRIV);

	/* parse command-line arguments */
	for(i = 0; i < argc; i++) {
		if(strcmp(argv[i], "debug") == 0)
			debug = 1;
		if(strncmp(argv[i], "onerr=", 6) == 0)
			if(strncmp(argv[i] + 6, "fail", 4) == 0)
				onerr = PAM_SESSION_ERR;
	}

	if((ret = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
		syslog(LOG_ERR, "can't get username: %s",
				pam_strerror(pamh, ret));
		return ret;
	}

	conf = fopen(CONFIG, "r");
	if(conf == NULL) {
		syslog(LOG_ERR, "can't open config file \"" CONFIG "\": %s",
				strerror(errno));
		return ret;
	}

	lineno = 0;
	while(fgets(conf_line, sizeof(conf_line), conf)) {
		regex_t name_regex;
		char *p;

		++lineno;

		/* lose comments */
		if((dir = strchr(conf_line, '#')))
			*dir = 0;

		/* ignore blank lines */
		if((name = strtok_r(conf_line, " \t\r\n", &p)) == NULL)
			continue;

		if((dir = strtok_r(NULL, " \t\r\n", &p)) == NULL) {
			syslog(LOG_ERR, CONFIG ":%d: no directory", lineno);
			ret = onerr;
			break;
		}

		if((err = regcomp(&name_regex, name, REG_ICASE))) {
			char *errbuf; size_t len;

			/* how foul, surely there's a nicer way? */
			len = regerror(err, &name_regex, NULL, 0);
			errbuf = malloc(len + 1);
			memset(errbuf, 0, len + 1);
			regerror(err, &name_regex, errbuf, len);

			syslog(LOG_ERR, CONFIG ":%d: illegal regex \"%s\": %s",
					lineno, name, errbuf);

			free(errbuf);
			regfree(&name_regex);

			ret = onerr;
			break;
		}

		err = regexec(&name_regex, user, 0, NULL, 0);
		regfree(&name_regex);

		if(!err) {
			if(chroot(dir) == -1) {
				syslog(LOG_ERR, "chroot(%s) failed: %s",
						dir, strerror(errno));
				ret = onerr;
			} else {
				if(debug) {
					syslog(LOG_ERR, "chroot(%s) succeeded",
							dir);
				}
				ret = PAM_SUCCESS;
			}
			break;
		}
	}

	fclose(conf);
	closelog();
	return ret;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
				    int argc, const char **argv)
{
	return PAM_SUCCESS;
}
