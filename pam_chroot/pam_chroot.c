/*
 * Linux-PAM session chroot()er
 *
 * $Id$
 */

#define	PAM_SM_SESSION
#include <security/pam_modules.h>

#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <regex.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>



#define	CONFIG	"/etc/security/chroot.conf"
#define LINELEN	1024		/* enough for anybody? */


PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
				   int argc, const char **argv)
{
int ret = PAM_SESSION_ERR;
char conf_line[LINELEN+1];
int lineno, err;
char *name, *dir;
char const *user;
FILE *conf;

	openlog("pam_chroot", LOG_PID, LOG_AUTHPRIV);

	if(pam_get_user(pamh, &user, NULL) != PAM_SUCCESS) {
		syslog(LOG_ERR, "can't get username");
		goto out;
	}


	conf = fopen(CONFIG, "r");
	if(!conf) {
		syslog(LOG_ERR, "can't open config file \"" CONFIG "\": %s",
				strerror(errno));
		goto out;
	}

	/* extra char to ensure it's always terminated */
	conf_line[LINELEN] = 0;

	lineno = 0;
	while(fgets(conf_line, LINELEN, conf)) {
	regex_t name_regex;

		++lineno;

		/* lose comments */
		if((dir = strchr(conf_line, '#')))
			*dir = 0;

		/* ignore blank lines */
		if(!(name = strtok(conf_line, " \t\r\n")))
			continue;

		if(!(dir = strtok(NULL, " \t\r\n"))) {
			syslog(LOG_ERR, CONFIG ":%d: no directory", lineno);
			goto out1;
		}

		if((err = regcomp(&name_regex, name, REG_ICASE))) {
		char *errbuf; size_t len;

			/* how foul, surely there's a nicer way? */
			len = regerror(err, &name_regex, NULL, 0);
			errbuf = malloc(len+1);
			regerror(err, &name_regex, errbuf, len);

			syslog(LOG_ERR, CONFIG ":%d: illegal regex \"%s\": %s",
					lineno, name, errbuf);

			free(errbuf);
			regfree(&name_regex);
			goto out1;
		}


		err = regexec(&name_regex, user, 0, NULL, 0);
		regfree(&name_regex);

		if(!err) {
			if(chroot(dir) < 0)
				syslog(LOG_ERR, "chroot(%s): %s",
						dir, strerror(errno));
			else
				syslog(LOG_ERR, "chrooted ok");

			break;
		}
	}


out1:
	fclose(conf);

out:
	closelog();
	return ret;
}


PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
				    int argc, const char **argv)
{
	return PAM_SUCCESS;
}
