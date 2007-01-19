#
# Copyright (c) 2005 Thorsten Kukuk <kukuk@suse.de>
# Copyright (c) 2005 Red Hat, Inc.
#

CLEANFILES = *~

man_MANS = pam_timestamp.8 pam_timestamp_check.8
EXTRA_DIST = README $(man_MANS) hmactest.c

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

noinst_HEADERS = hmacsha1.h

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include
AM_LDFLAGS = -L$(top_builddir)/libpam -lpam

pam_timestamp_la_LDFLAGS = -no-undefined -avoid-version -module $(AM_LDFLAGS)
if HAVE_VERSIONING
  pam_timestamp_la_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

securelib_LTLIBRARIES = pam_timestamp.la
sbin_PROGRAMS = pam_timestamp_check

pam_timestamp_la_SOURCES = pam_timestamp.c hmacsha1.c sha1.c hmacsha1.h
pam_timestamp_la_CFLAGS = $(AM_CFLAGS)

pam_timestamp_check_SOURCES = pam_timestamp_check.c hmacsha1.c sha1.c hmacsha1.h
pam_timestamp_check_CFLAGS = $(AM_CFLAGS) -fPIE
pam_timestamp_check_LDFLAGS = $(AM_LDFLAGS) -pie

hmacfile_SOURCES = hmacfile.c hmacsha1.c sha1.c hmacsha1.h

noinst_PROGRAMS = hmacfile 
