# $Id$

include ../../Make.Rules

TITLE=pam_chroot

LOCAL_CONFILE=./chroot.conf
INSTALLED_CONFILE=$(SCONFIGD)/chroot.conf

MODULE_SIMPLE_INSTALL=bash -f ../install_conf "$(FAKEROOT)" "$(SCONFIGD)" "$(INSTALLED_CONFILE)" "$(TITLE)" "$(LOCAL_CONFILE)"
MODULE_SIMPLE_REMOVE=rm -f $(FAKEROOT)$(INSTALLED_CONFILE)
MODULE_SIMPLE_CLEAN=rm -f ./.ignore_age

include ../Simple.Rules
