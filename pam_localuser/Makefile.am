include ../Makefile-module.am

EXTRA_DIST = pam_localuser.8

module_LTLIBRARIES = pam_localuser.la
pam_localuser_la_SOURCES = pam_localuser.c
pam_localuser_la_LIBADD = ../lib/libmisc.la
pam_localuser_la_LDFLAGS = $(MODULE_LDFLAGS)
man8_MANS = pam_localuser.8
