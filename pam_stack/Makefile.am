EXTRA_DIST = pam_stack.8

if HAVE_PAMSRC

include ../Makefile-module.am

module_LTLIBRARIES = pam_stack.la
pam_stack_la_CFLAGS = -I$(PAMSRCDIR) @LAUS_CFLAGS@
pam_stack_la_SOURCES = pam_stack.c
pam_stack_la_LDFLAGS = $(MODULE_LDFLAGS) @LAUS_LIBS@
man8_MANS = pam_stack.8

endif
