include ../Makefile-module.am

EXTRA_DIST = chroot.conf

securityconf_DATA = chroot.conf
module_LTLIBRARIES = pam_chroot.la
pam_chroot_la_SOURCES = pam_chroot.c
pam_chroot_la_LDFLAGS = $(MODULE_LDFLAGS)
