include ../Makefile-module.am

EXTRA_DIST = pam_timestamp.8

noinst_LTLIBRARIES = libhmac.la
libhmac_la_SOURCES = \
	hmacsha1.c \
	hmacsha1.h \
	sha1.c \
	sha1.h \
	sha1sum.c

module_LTLIBRARIES = pam_timestamp.la
pam_timestamp_la_SOURCES = pam_timestamp.c
pam_timestamp_la_LDFLAGS = $(MODULE_LDFLAGS)
pam_timestamp_la_LIBADD = libhmac.la ../lib/libmisc.la

sbin_PROGRAMS = pam_timestamp_check
pam_timestamp_check_SOURCES = pam_timestamp_check.c
pam_timestamp_check_LDADD = libhmac.la ../lib/libmisc.la

EXTRA_PROGRAMS = hmactest hmacfile
hmactest_CFLAGS = @OPENSSL_CFLAGS@
hmactest_SOURCES = hmactest.c
hmactest_LDADD = libhmac.la ../lib/libmisc.la @OPENSSL_LIBS@
hmacfile_SOURCES = hmacfile.c
hmacfile_LDADD = libhmac.la ../lib/libmisc.la

man8_MANS = pam_timestamp.8
