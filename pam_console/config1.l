%option noyywrap
%{
/* Copyright 1999,2000 Red Hat, Inc.
 * This software may be used under the terms of the GNU General Public
 * License, available in the file COPYING accompanying this file
 */
/* get around an apparant bug in bison; YYSTYPE not copied into config.tab.h */
#define YYSTYPE void *
#include <config2.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <syslog.h>
#include "pam_console.h"

int lineno;
char *filename;

char *
strip_slash(char *);
%}
%%
\n			{ lineno++; return EOL; }
\\\n			{ lineno++; }
			/* do not return EOL, eat up escaped newline */
[ \t]+			/* ignore whitespace */
\<			{ return OBRACKET; }
\>=			{ return CBEQUALS; }
\>			{ return CBRACKET; }
([^\t\n #\<\>]|(\\#\\\<\\\>))+	{ yylval=strip_slash(yytext); return STRING; }
#.*\n			{ lineno++; return EOL; } /* ignore comments */
%%

void
lex_file (FILE *in) {
  /* yy_flex_debug = 1; */
  yyin = in;
  lineno = 1;
}

void
lex_set_filename(char *name) {
  filename = name;
}

int
yyerror (char *s) {
  _pam_log(LOG_ERR, 0, "%s line %d: %s: at `%s'\n",
	   filename, lineno, s, (char *)yylval);
  return 0;
}

char *
strip_slash(char *s) {
  char *r, *t;

  r = g_strdup(s);
  while ((t = strstr(s, "\\#")), t) {
    memmove(t, t+1, strlen(t));
  }
  return r;
}
