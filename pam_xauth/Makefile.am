include ../Makefile-module.am

EXTRA_DIST = pam_xauth.8

module_LTLIBRARIES = pam_xauth.la
pam_xauth_la_SOURCES = pam_xauth.c
pam_xauth_la_LIBADD = ../lib/libmisc.la
pam_xauth_la_LDFLAGS = $(MODULE_LDFLAGS)
man8_MANS = pam_xauth.8
