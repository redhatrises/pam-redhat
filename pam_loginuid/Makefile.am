#
# Copyright (c) 2005 Thorsten Kukuk <kukuk@suse.de>
# Copyright (c) 2005 Red Hat, Inc.
#

CLEANFILES = *~

man_MANS = pam_loginuid.8
EXTRA_DIST = README $(man_MANS)

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include
AM_LDFLAGS = -no-undefined -avoid-version -module \
	-L$(top_builddir)/libpam -lpam @LIBAUDIT@
if HAVE_VERSIONING
  AM_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

securelib_LTLIBRARIES = pam_loginuid.la
