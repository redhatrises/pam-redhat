#
# Copyright (c) 2005 Thorsten Kukuk <kukuk@suse.de>
#

CLEANFILES = *~

EXTRA_DIST = README

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

noinst_HEADERS = tallylog.h

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include
AM_LDFLAGS = -no-undefined -L$(top_builddir)/libpam -lpam $(LIBAUDIT)

pam_tally2_la_LDFLAGS = -avoid-version -module
if HAVE_VERSIONING
  pam_tally2_la_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

securelib_LTLIBRARIES = pam_tally2.la
sbin_PROGRAMS = pam_tally2

pam_tally2_la_SOURCES = pam_tally.c
pam_tally2_SOURCES = pam_tally_app.c
