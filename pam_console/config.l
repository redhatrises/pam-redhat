%option noyywrap
%{
/* Copyright 1999,2000 Red Hat, Inc.
 * This software may be used under the terms of the GNU General Public
 * License, available in the file COPYING accompanying this file
 */
/* get around an apparant bug in bison; YYSTYPE not copied into config.tab.h */
#define YYSTYPE void *
#include "config.tab.h"
#include <stdio.h>
#include <string.h>
#include <glib.h>

static int lineno;
static char *filename;

STATIC char *
strip_slash(const char *);
%}
%%
\n			{ lineno++; return EOL; }
\\\n			{ lineno++; }
			/* do not return EOL, eat up escaped newline */
[ \t]+			/* ignore whitespace */
\<			{ return OBRACKET; }
\>=			{ return CBEQUALS; }
\>			{ return CBRACKET; }
([^\t\n #\<\>]|(\\#|\\\<|\\\>))+ { _pc_yylval=strip_slash(yytext); return STRING; }
#.*\n			{ lineno++; return EOL; } /* ignore comments */
%%

static void
lex_file (FILE *in) {
  /* yy_flex_debug = 1; */
  yyin = in;
  lineno = 1;
}

static void
lex_set_filename(char *name) {
  filename = name;
}

static int
_pc_yyerror (const char *s) {
  _pam_log(LOG_ERR, 0, "%s line %d: %s: at `%s'\n",
	   filename, lineno, s, (char *)_pc_yylval);
  return 0;
}

STATIC char *
strip_slash(const char *s) {
  char *r, *t;

  t = r = g_strdup(s);
  while ((t = strchr(t, '\\')) != NULL) {
    if (t[1] == '#' || t[1] == '<' || t[1] == '>') {
      memmove(t, t+1, strlen(t));
    }
    t++;
  }
  return r;
}
