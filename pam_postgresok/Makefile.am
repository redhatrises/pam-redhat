include ../Makefile-module.am

EXTRA_DIST = pam_postgresok.8

module_LTLIBRARIES = pam_postgresok.la
pam_postgresok_la_SOURCES = pam_postgresok.c
pam_postgresok_la_LIBADD = ../lib/libmisc.la
pam_postgresok_la_LDFLAGS = $(MODULE_LDFLAGS)
man8_MANS = pam_postgresok.8
