%{
/* Copyright 1999 Red Hat Software, Inc.
 * This software may be used under the terms of the GNU General Public
 * License, available in the file COPYING accompanying this file
 */
#define YYSTYPE void *

#include <errno.h>
#include <glib.h>
#include <grp.h>
#include <regex.h>
#include <stdio.h>
#include <sys/types.h>

static GHashTable *namespace = NULL;
static GSList *configList = NULL;
static GSList *configListEnd = NULL;
static GSList *consoleClassList = NULL;
static GSList *consoleClassListEnd = NULL;
static char *consoleNameCache = NULL;
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

  _pam_log(LOG_PID|LOG_AUTHPRIV|LOG_ERR, 1, "parsing config file %s", name);
  infile = fopen(name, "r");
  if (!infile) {
    _pam_log(LOG_PID|LOG_AUTHPRIV|LOG_ERR, 0,
	     "could not parse required file %s", name);
    return;
  }

  if (!namespace) namespace = g_hash_table_new(g_str_hash, g_str_equal);

  lex_set_filename(name);
  lex_file(infile);

  yyparse();
  fclose(infile);
}

static int
check_one_console_name (char *name, char *classComponent) {
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
check_console_name (char *consolename) {
    GSList *this_class;
    GSList *this_list;
    class *c;
    int found = 0;

    _pam_log(LOG_PID|LOG_AUTHPRIV|LOG_ERR, 1, "check console %s", consolename);
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
    if (found)
	return 1;

    /* not found */
    _pam_log(LOG_PID|LOG_DAEMON|LOG_ERR, 1, "did not find console %s", consolename);
    if (consoleHash) {
	g_hash_table_destroy(consoleHash);
	consoleHash = NULL;
    }
    return 0;
}

STATIC int
set_permissions(char *consolename, char *username) {
    struct passwd *p;
    config *c;
    GSList *cl;

    if (!consoleNameCache || strcmp(consolename, consoleNameCache)) {
	if (!check_console_name(consolename)) return -1;
    }

    p = getpwnam(username);
    if (!p) {
	_pam_log(LOG_PID|LOG_AUTHPRIV|LOG_ERR, 0,
		 "getpwnam failed for %s", username);
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
reset_permissions(char *consolename) {
    struct passwd *p;
    struct group *g;
    config *c;
    GSList *cl;

    if (!consoleNameCache || strcmp(consolename, consoleNameCache)) {
	if (!check_console_name(consolename)) return -1;
    }

    for (cl = configList; cl; cl = cl->next) {
	c = cl->data;
	if (g_hash_table_lookup(consoleHash, c->console_class)) {
	    p = getpwnam(c->revert_owner ? c->revert_owner : "root");
	    if (!p) {
		_pam_log(LOG_PID|LOG_AUTHPRIV|LOG_ERR, 0,
			 "getpwnam failed for %s",
			 c->revert_owner ? c->revert_owner : "root");
		return -1;
	    }
            g = getgrnam(c->revert_group ? c->revert_group : "root");
            if (!g) {
                _pam_log(LOG_PID|LOG_AUTHPRIV|LOG_ERR, 0,
                         "getgrnam failed for %s",
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
  openlog("pam_console", LOG_CONS|LOG_PID, LOG_AUTH);
  vsyslog(LOG_PID|LOG_AUTHPRIV|LOG_ERR, format, ap);
  va_end(ap);
}

static void
free_class(class *c) {
  if (c->name) free (c->name);
  if (c) free (c);
}
