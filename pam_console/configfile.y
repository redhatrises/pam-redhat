%{
/* Copyright 1999,2000 Red Hat, Inc.
 * This software may be used under the terms of the GNU General Public
 * License, available in the file COPYING accompanying this file
 */
#define YYSTYPE void *

#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <regex.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <chmod.h>
#include <hashtable.h>

#include <security/pam_modules.h>
#include <security/pam_modutil.h>

typedef struct hashtable GHashTable;

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
empty_class(class *c);

static unsigned int
str_hash(unsigned char *s)
{
        unsigned int hash = 5381;
	int c;
	                
	while ((c = *s++))
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
	                                    
	return hash;
}

static int
str_equal(void *a, void *b)
{
	return strcmp(a, b) == 0;
}

static unsigned int
ptr_hash(void *p)
{
	return (unsigned long)p >> 3;
}

static int
ptr_equal(void *a, void *b)
{
	return a == b;
}

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
		  class *c;

		  c = hashtable_search(namespace, $2);
		  if (c) { 
			empty_class(c);
		  } else {
			c = malloc(sizeof(class));
			hashtable_insert(namespace, strdup($2), c);
		  }
		  c->name = $2;
		  c->list = $4;
		}
	;

config:		classlist STRING classlist optstring optstring EOL {
		  config *conf = malloc(sizeof(config));
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
                  } else {
		      conf->revert_group = NULL;
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
		  class *c = hashtable_search(namespace, $2);
		  if(!c) {
		    _pam_log(NULL, LOG_ERR, FALSE,
			  "unknown class \"%s\" at line %d in %s\n",
			  (const char *)$2, lineno, filename);
		    YYERROR;
		  }
		  $$ = c;
		}
	|	string {
		  class *c = malloc(sizeof(class));
		  c->name = $1;
		  c->list = NULL;
		  $$ = c;
		}
	;


stringlist:	string	{$$ = g_slist_append(NULL, $1);}
	|	stringlist string {$$ = g_slist_append($1, $2);}
	;

optstring:	string	{$$=$1;}
	|	/* empty */ {$$=NULL;}
	;

string:		STRING {$$=$1;} ;

%%

/* exported functions */

/* parse a file given by a name */
void
parse_file(const char *name) {
  FILE *infile;

  _pam_log(NULL, LOG_DEBUG, TRUE, "parsing config file %s", name);
  infile = fopen(name, "r");
  if (!infile) {
    _pam_log(NULL, LOG_ERR, FALSE, "could not parse required file %s", name);
    return;
  }

  if (!namespace) namespace = create_hashtable(128, (unsigned int (*)(void *))str_hash, str_equal);

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

int
check_console_name (const char *consolename) {
    GSList *this_class;
    GSList *this_list;
    class *c;
    int found = 0;

    _pam_log(NULL, LOG_DEBUG, TRUE, "check console %s", consolename);
    if (consoleNameCache != consolename) {
	consoleNameCache = consolename;
	if (consoleHash) hashtable_destroy(consoleHash, 0);
	consoleHash = create_hashtable(128, ptr_hash, ptr_equal);
    }
    for (this_class = consoleClassList; this_class;
	 this_class = this_class->next) {
	c = this_class->data;
        if (c->list) {
	    for (this_list = c->list; this_list; this_list = this_list->next) {
		if (check_one_console_name(consolename, this_list->data)) {
		    hashtable_insert(consoleHash, c, c);
		    found = 1;
		}
	    }
	} else {
	    if (check_one_console_name(consolename, c->name)) {
		hashtable_insert(consoleHash, c, c);
		found = 1;
	    }
	}
    }

    if (found)
	return 1;

    /* not found */
    _pam_log(NULL, LOG_INFO, TRUE, "did not find console %s", consolename);
    if (consoleHash) {
	hashtable_destroy(consoleHash, 0);
	consoleHash = NULL;
    }
    return 0;
}

int
set_permissions(const char *consolename, const char *username, GSList *files) {
    struct passwd *pwd;
    config *c;
    GSList *cl;

    if (!consoleNameCache || strcmp(consolename, consoleNameCache)) {
	if (!check_console_name(consolename)) return -1;
    }

    pwd = getpwnam(username);
    if (pwd == NULL) {
	_pam_log(NULL, LOG_ERR, FALSE, "getpwnam failed for \"%s\"", username);
	return -1;
    }

    for (cl = configList; cl; cl = cl->next) {
	c = cl->data;
	if (hashtable_search(consoleHash, c->console_class)) {
    	    if (c->device_class->list)
	        chmod_files(c->mode, pwd->pw_uid, -1, NULL, c->device_class->list, files);
	    else
	        chmod_files(c->mode, pwd->pw_uid, -1, c->device_class->name, NULL, files);
	}
    }
    return 0;
}

int
reset_permissions(const char *consolename, GSList *files) {
    struct passwd *pwd;
    struct group *grp;
    config *c;
    GSList *cl;

    if (!consoleNameCache || strcmp(consolename, consoleNameCache)) {
	if (!check_console_name(consolename)) return -1;
    }

    for (cl = configList; cl; cl = cl->next) {
	c = cl->data;
	if (hashtable_search(consoleHash, c->console_class)) {
	    pwd = getpwnam(c->revert_owner ? c->revert_owner : "root");
	    if (pwd == NULL) {
		_pam_log(NULL, LOG_ERR, FALSE, "getpwnam failed for %s",
			 c->revert_owner ? c->revert_owner : "root");
		pwd = getpwuid(0);
		if (pwd == NULL)
		    return -1;
	    }
	    grp = getgrnam(c->revert_group ? c->revert_group : "root");
	    if (grp == NULL) {
                _pam_log(NULL, LOG_ERR, FALSE, "getgrnam failed for %s",
                         c->revert_group ? c->revert_group : "root");
		grp = getgrgid(0);
		if (grp == NULL)
            	    return -1;
            }
	    if (c->device_class->list)
	        chmod_files(c->revert_mode ? c->revert_mode : "0600",
		            pwd->pw_uid, grp->gr_gid, NULL, c->device_class->list, files);
	    else
	        chmod_files(c->revert_mode ? c->revert_mode : "0600",
		            pwd->pw_uid, grp->gr_gid, c->device_class->name, NULL, files);
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
empty_class(class *c) {
  free(c->name);
  c->name = NULL;
  g_slist_free(c->list);
  c->list = NULL;
}
