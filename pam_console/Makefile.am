include ../Makefile-module.am

AM_CFLAGS += @GLIB_CFLAGS@
AM_LDFLAGS += @GLIB_LIBS@

EXTRA_DIST = \
	console.apps.5 console.perms.5 \
	pam_console.8 pam_console_apply.8 \
	console.perms

securityconf_DATA = console.perms
consoleappsdir = $(securityconfdir)/console.apps
consolelockdir = $(LOCKDIR)/console

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(consoleappsdir)
	$(mkinstalldirs) $(DESTDIR)$(consolelockdir)

noinst_LTLIBRARIES = libpamconsole.la
libpamconsole_la_SOURCES = \
	chmod.c \
	chmod.h \
	config1.l \
	config2.y \
	modechange.c \
	modechange.h \
	pam_console.h \
	regerr.c

module_LTLIBRARIES = pam_console.la
pam_console_la_SOURCES = pam_console.c
pam_console_la_LDFLAGS = $(MODULE_LDFLAGS)
pam_console_la_LIBADD = libpamconsole.la ../lib/libmisc.la

sbin_PROGRAMS = pam_console_apply
pam_console_apply_SOURCES = pam_console_apply.c
pam_console_apply_LDADD = libpamconsole.la ../lib/libmisc.la -lpam -ldl

man5_MANS = console.apps.5 console.perms.5
man8_MANS = pam_console.8 pam_console_apply.8
