%{
/* Copyright 1999,2000 Red Hat, Inc.
 * This software may be used under the terms of the GNU General Public
 * License, available in the file COPYING accompanying this file
 */
#define YYSTYPE void *

#include <errno.h>
#include <glib.h>
#include <grp.h>
#include <limits.h>
#include <regex.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

static GHashTable *namespace = NULL;
static GSList *configList = NULL;
static GSList *configListEnd = NULL;
static GSList *consoleClassList = NULL;
static GSList *consoleClassListEnd = NULL;
static const char *consoleNameCache = NULL;
static GHashTable *consoleHash = NULL;

static void
do_yyerror(const char *format, ...);

static void
free_class(class *c);

%}

%token EOL
%token OBRACKET
%token CBEQUALS
%token CBRACKET
%token STRING

%%
lines:		lines line
	|	/* empty */
	;

line:		config
	|	classdef
	|	EOL
	|	error
	;

classdef:
		OBRACKET string CBEQUALS stringlist EOL {
		  void *old;
		  class *c;

		  old = g_hash_table_lookup(namespace, $2);
		  if (old) free_class(old);

		  c = g_malloc(sizeof(class));
		  c->name = $2;
		  c->list = $4;
		  g_hash_table_insert(namespace, $2, c);
		}
	;

config:		classlist STRING classlist optstring optstring EOL {
		  config *conf = g_malloc(sizeof(config));
		  conf->console_class = $1;
		  conf->mode = $2;
		  conf->device_class = $3;
		  conf->revert_mode = $4;
		  conf->revert_owner = $5;
                  if (conf->revert_owner != NULL) {
                      conf->revert_group = strchr (conf->revert_owner, ':');
                      if (conf->revert_group == NULL)
                          conf->revert_group = strchr (conf->revert_owner, '.');
                      if (conf->revert_group != NULL) {
                          *(conf->revert_group) = '\0';
                          conf->revert_group++;
                          if (*(conf->revert_group) == '\0')
                              conf->revert_group = NULL;
                          if (*(conf->revert_owner) == '\0')
                              conf->revert_owner = NULL;
                      }
                  }
		  configListEnd = g_slist_append(configListEnd, conf);
		  if (configListEnd->next) configListEnd = configListEnd->next;
		  if (!configList) configList = configListEnd;
		  consoleClassListEnd =
		    g_slist_append(consoleClassListEnd, conf->console_class);
		  if (consoleClassListEnd->next)
		    consoleClassListEnd = consoleClassListEnd->next;
		  if (!consoleClassList) consoleClassList = consoleClassListEnd;
		}
	;

classlist:	OBRACKET string CBRACKET {
		  class *c = g_hash_table_lookup(namespace, $2);
		  $$ = c;
		}
	|	string {
		  class *c = g_malloc(sizeof(class));
		  c->name = $1;
		  c->list = NULL;
		  $$ = c;
		}
	;


stringlist:	string	{$$ = g_slist_append(NULL, $1);}
	|	stringlist string {$$ = g_slist_append($1, $2);}
	;

optstring:	string	{$$=$1}
	|	/* empty */ {$$=NULL}
	;

string:		STRING {$$=$1}

%%

/* exported functions */

/* parse a file given by a file descriptor open for reading, then
   close the file it applies to */
STATIC void
parse_file(char *name) {
  FILE *infile;

  _pam_log(LOG_DEBUG, TRUE, "parsing config file %s", name);
  infile = fopen(name, "r");
  if (!infile) {
    _pam_log(LOG_ERR, FALSE, "could not parse required file %s", name);
    return;
  }

  if (!namespace) namespace = g_hash_table_new(g_str_hash, g_str_equal);

  lex_set_filename(name);
  lex_file(infile);

  yyparse();
  fclose(infile);
}

static int
check_one_console_name (const char *name, char *classComponent) {
    regex_t p;
    int r_err;
    char *class_exp;

    class_exp = _do_malloc(strlen(classComponent) + 3);
    sprintf(class_exp, "^%s$", classComponent);
    r_err = regcomp(&p, class_exp, REG_EXTENDED|REG_NOSUB);
    if (r_err) do_regerror(r_err, &p);
    r_err = regexec(&p, name, 0, NULL, 0);
    regfree(&p);
    free (class_exp);
    return !r_err;
}

STATIC int
check_console_name (const char *consolename, int nonroot_ok) {
    GSList *this_class;
    GSList *this_list;
    class *c;
    int found = 0;
    int statted = 0;
    struct stat st;
    char full_path[PATH_MAX];

    _pam_log(LOG_DEBUG, TRUE, "check console %s", consolename);
    if (consoleNameCache != consolename) {
	consoleNameCache = consolename;
	if (consoleHash) g_hash_table_destroy(consoleHash);
	consoleHash = g_hash_table_new(NULL, NULL);
    }
    for (this_class = consoleClassList; this_class;
	 this_class = this_class->next) {
	c = this_class->data;
        if (c->list) {
	    for (this_list = c->list; this_list; this_list = this_list->next) {
		if (check_one_console_name(consolename, this_list->data)) {
		    g_hash_table_insert(consoleHash, c, c);
		    found = 1;
		}
	    }
	} else {
	    if (check_one_console_name(consolename, c->name)) {
		g_hash_table_insert(consoleHash, c, c);
		found = 1;
	    }
	}
    }

    /* add some policy here -- not really the PAM way of doing things, but
       it gives us an extra measure of security in case of misconfiguration */
    memset(&st, 0, sizeof(st));
    statted = 0;

    _pam_log(LOG_DEBUG, TRUE, "checking possible console \"%s\"", consolename);
    if (lstat(consolename, &st) != -1) {
        statted = 1;
    }
    if (!statted) {
        strcpy(full_path, "/dev/");
        strncat(full_path, consolename,
                sizeof(full_path) - 1 - strlen(full_path));
	full_path[sizeof(full_path) - 1] = '\0';
        _pam_log(LOG_DEBUG, TRUE, "checking possible console \"%s\"",
		 full_path);
        if (lstat(full_path, &st) != -1) {
           statted = 1;
        }
    }
    if (!statted && (consolename[0] == ':')) {
        size_t l;
        char *dot = NULL;
        strcpy(full_path, "/tmp/.X11-unix/X");
        l = sizeof(full_path) - 1 - strlen(full_path);
        dot = strchr(consolename + 1, '.');
        if (dot != NULL) {
            l = (l < dot - consolename - 1) ? l : dot - consolename - 1;
        }
        strncat(full_path, consolename + 1, l);
	full_path[sizeof(full_path) - 1] = '\0';
        _pam_log(LOG_DEBUG, TRUE, "checking possible console \"%s\"",
		 full_path);
        if (lstat(full_path, &st) != -1) {
           statted = 1;
        }
    }

    if (statted) {
        int ok = 0;
        if (st.st_uid == 0) {
            _pam_log(LOG_DEBUG, TRUE, "console %s is owned by UID 0", consolename);
            ok = 1;
        }
        if (S_ISCHR(st.st_mode)) {
            _pam_log(LOG_DEBUG, TRUE, "console %s is a character device", consolename);
            ok = 1;
        }
        if (!ok && !nonroot_ok) {
            _pam_log(LOG_INFO, TRUE, "%s is not a valid console device because it is owned by UID %d and the allow_nonroot flag was not set", consolename, st.st_uid);
            found = 0;
        }
    } else {
        _pam_log(LOG_INFO, TRUE, "can't find device or X11 socket to examine for %s", consolename);
        found = 0;
    }

    if (found)
	return 1;

    /* not found */
    _pam_log(LOG_INFO, TRUE, "did not find console %s", consolename);
    if (consoleHash) {
	g_hash_table_destroy(consoleHash);
	consoleHash = NULL;
    }
    return 0;
}

STATIC int
set_permissions(const char *consolename, const char *username, int nonroot_ok) {
    struct passwd *p;
    config *c;
    GSList *cl;

    if (!consoleNameCache || strcmp(consolename, consoleNameCache)) {
	if (!check_console_name(consolename, nonroot_ok)) return -1;
    }

    p = getpwnam(username);
    if (!p) {
	_pam_log(LOG_ERR, FALSE, "getpwnam failed for \"%s\"", username);
	return -1;
    }

    for (cl = configList; cl; cl = cl->next) {
	c = cl->data;
	if (g_hash_table_lookup(consoleHash, c->console_class)) {
	    if (c->device_class->list)
		chmod_filelist(c->mode, p->pw_uid, -1, c->device_class->list);
	    else
		chmod_file(c->mode, p->pw_uid, -1, c->device_class->name);
	}
    }
    return 0;
}

STATIC int
reset_permissions(const char *consolename, int nonroot_ok) {
    struct passwd *p;
    struct group *g;
    config *c;
    GSList *cl;

    if (!consoleNameCache || strcmp(consolename, consoleNameCache)) {
	if (!check_console_name(consolename, nonroot_ok)) return -1;
    }

    for (cl = configList; cl; cl = cl->next) {
	c = cl->data;
	if (g_hash_table_lookup(consoleHash, c->console_class)) {
	    p = getpwnam(c->revert_owner ? c->revert_owner : "root");
	    if (!p) {
		_pam_log(LOG_ERR, FALSE, "getpwnam failed for %s",
			 c->revert_owner ? c->revert_owner : "root");
		return -1;
	    }
            g = getgrnam(c->revert_group ? c->revert_group : "root");
            if (!g) {
                _pam_log(LOG_ERR, FALSE, "getgrnam failed for %s",
                         c->revert_group ? c->revert_group : "root");
                return -1;
            }
	    if (c->device_class->list)
		chmod_filelist(c->revert_mode ? c->revert_mode : "0600",
			       p->pw_uid, g->gr_gid, c->device_class->list);
	    else
		chmod_file(c->revert_mode ? c->revert_mode : "0600",
			   p->pw_uid, g->gr_gid, c->device_class->name);
	}
    }
    return 0;
}




/* local, static functions */

static void
do_yyerror(const char *format, ...) {
  va_list ap;

  va_start(ap, format);
  openlog("pam_console", LOG_CONS|LOG_PID, LOG_AUTHPRIV);
  vsyslog(LOG_PID|LOG_AUTHPRIV|LOG_ERR, format, ap);
  va_end(ap);
}

static void
free_class(class *c) {
  if (c->name) free (c->name);
  if (c) free (c);
}
