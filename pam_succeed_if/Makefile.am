include ../Makefile-module.am

EXTRA_DIST = pam_succeed_if.8

module_LTLIBRARIES = pam_succeed_if.la
pam_succeed_if_la_SOURCES = pam_succeed_if.c
pam_succeed_if_la_LIBADD = ../lib/libmisc.la
pam_succeed_if_la_LDFLAGS = $(MODULE_LDFLAGS)
man8_MANS = pam_succeed_if.8
