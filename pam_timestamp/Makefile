#
# $Id$
#

include ../../Make.Rules

TITLE=pam_timestamp
APPLICATION=$(TITLE)_check
APPMODE=04511
MAN8=$(TITLE).8 $(TITLE)_check.8

MODULE_SIMPLE_INSTALL=$(MAKE) $(APPLICATION); $(INSTALL) -m $(APPMODE) $(APPLICATION) $(FAKEROOT)$(SUPLEMENTED)

include ../Simple.Rules

$(APPLICATION): $(APPLICATION).c
	$(CC) $(CFLAGS) -o $@ $^
