#
# $Id$
#

include ../../Make.Rules

TITLE=pam_timestamp
APPLICATION=$(TITLE)_check
APPMODE=04511
MAN8=$(TITLE).8 $(TITLE)_check.8
MODULE_SIMPLE_EXTRAFILES=sha1 hmacsha1

MODULE_SIMPLE_INSTALL=$(MAKE) $(APPLICATION); $(INSTALL) -m $(APPMODE) $(APPLICATION) $(FAKEROOT)$(SUPLEMENTED)
MODULE_SIMPLE_EXTRAFILES=sha1 hmacsha1

include ../Simple.Rules

$(APPLICATION): $(APPLICATION).c
	$(CC) $(CFLAGS) $(INCLUDE_PAMMODUTILS) -o $@ $^ $(LINK_PAMMODUTILS)

hmacfile: hmacfile.c hmacsha1.c sha1.c
	$(CC) $(CFLAGS) -DHMAC_ALLOW_SHORT_KEYS -o $@ $^
hmactest: hmactest.c
	$(CC) $(CFLAGS) -o $@ $^ -lcrypto
