include ../Makefile-module.am

EXTRA_DIST = pam_saslauthd.8

module_LTLIBRARIES = pam_saslauthd.la
pam_saslauthd_la_SOURCES = pam_saslauthd.c
pam_saslauthd_la_LIBADD = ../lib/libmisc.la
pam_saslauthd_la_LDFLAGS = $(MODULE_LDFLAGS)
noinst_MANS = pam_saslauthd.8
