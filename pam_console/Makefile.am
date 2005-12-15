#
# Copyright (c) 2005 Thorsten Kukuk <kukuk@suse.de>
# Copyright (c) 2005 Red Hat, Inc.
#

CLEANFILES = *~

CONFFILES = console.perms console.handlers 50-default.perms
MAN5 = console.apps.5 console.perms.5 console.handlers.5
MAN8 = pam_console.8 pam_console_apply.8

man_MANS = $(MAN5) $(MAN8)

EXTRA_DIST = README $(man_MANS) $(CONFFILES) sed-static configfile.y configfile.l

GLIB_CFLAGS = $(shell pkg-config --cflags glib-2.0)
# this ugly $(shell...) hack overrides automake checks when LDADD is used
GLIB_LIBS = $(shell echo '-Wl,-Bstatic') $(shell pkg-config '--libs' glib-2.0) $(shell echo '-Wl,-Bdynamic')

LOCKDIR = /var/run/console
LOCKMODE = 755

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)
permsddir = $(SCONFIGDIR)/console.perms.d

noinst_HEADERS = chmod.h configfile.h configfile.tab.h handlers.h modechange.h pam_console.h

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include \
	$(GLIB_CFLAGS) -DLOCKDIR=\"$(LOCKDIR)\"

pam_console_la_LDFLAGS = -no-undefined -avoid-version -module
if HAVE_VERSIONING
  pam_console_la_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif
pam_console_la_LIBADD = -L$(top_builddir)/libpam -lpam

# override extra dependencies otherwise we get GLIB_LIBS contents here
pam_console_apply_DEPENDENCIES =
# we can't use libtool (sorts linker options out of libraries)
pam_console_apply_LDADD = -L$(top_builddir)/libpam/.libs -lpam $(GLIB_LIBS)
pam_console_apply_LINK =  $(CCLD) $(AM_CFLAGS) $(CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -o $@

securelib_LTLIBRARIES = pam_console.la
sbin_PROGRAMS = pam_console_apply


secureconf_DATA = console.perms console.handlers
permsd_DATA = 50-default.perms

FLEX_OPTS = -Cr
BISON_OPTS = -d

pam_console_la_SOURCES = pam_console.c pam_console.h regerr.c handlers.c handlers.h
pam_console_apply_SOURCES = pam_console_apply.c pam_console.h chmod.c modechange.c regerr.c configfile.c configfile.h

pam_console_la_CFLAGS = $(AM_CFLAGS)
pam_console_apply_CFLAGS = $(AM_CFLAGS)

configfile.tab.c: configfile.y
	$(YACC) $(BISON_OPTS) -o $@ -p _pc_yy $<
	sh $(srcdir)/sed-static $@

configfile.lex.c: configfile.l configfile.tab.c
	$(LEX) $(FLEX_OPTS) -o$@ -P_pc_yy $<
	sh $(srcdir)/sed-static $@

configfile.c: configfile.tab.c configfile.lex.c

install-data-local:
	mkdir -p $(DESTDIR)$(secureconfdir)/console.apps
	mkdir -m $(LOCKMODE) -p -p $(DESTDIR)$(LOCKDIR)
