#
# This Makefile controls a build process of $(TITLE) module for
# Linux-PAM. You should not modify this Makefile (unless you know
# what you are doing!).
#

include ../../Make.Rules

TITLE=pam_console

LOCKDIR = /var/lock/console
LOCKMODE = 755
MODULE_SIMPLE_EXTRALIBS +=  $(shell glib-config --libs)
MODULE_SIMPLE_INSTALL=$(MKDIR) -m $(LOCKMODE) $(FAKEROOT)$(LOCKDIR) $(FAKEROOT)/$(SCONFIGD)/console.apps && bash -f ../install_conf "$(FAKEROOT)" "$(SCONFIGD)" "$(INSTALLED_CONFILE)" "$(TITLE)" "$(LOCAL_CONFILE)"

LOCAL_CONFILE = console.perms
INSTALLED_CONFILE = $(SCONFIGD)/console.perms
MAN5 = console.apps.5 console.perms.5
MAN8 = pam_console.8

CFLAGS += $(shell glib-config --cflags) -D_GNU_SOURCE

FLEX_OPTS = -Cr
BISON_OPTS = -d

include ../Simple.Rules

config.tab.c: config.y
	bison $(BISON_OPTS) -p _pc_yy $<
	sh ./sed-static $@

config.lex.c: config.l config.tab.c
	flex $(FLEX_OPTS) -o$@ -P_pc_yy $<
	sh ./sed-static $@

$(LIBSRC): pam_console.h chmod.c modechange.c regerr.c config.lex.c config.tab.c
