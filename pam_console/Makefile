#
# This Makefile controls a build process of $(TITLE) module for
# Linux-PAM. You should not modify this Makefile (unless you know
# what you are doing!).
#

include ../../Make.Rules

TITLE=pam_console

LOCKDIR = /var/lock/console
LOCKMODE = 755
LDFLAGS +=  $(shell glib-config --libs)

BINARY = pam_console_apply
LOCAL_CONFILE = console.perms
INSTALLED_CONFILE = $(SCONFIGD)/console.perms
MAN5 = console.apps.5 console.perms.5
MAN8 = pam_console.8 pam_console_apply.8

CFLAGS += $(shell glib-config --cflags) -D_GNU_SOURCE

FLEX_OPTS = -Cr
BISON_OPTS = -d

LIBSRC = $(TITLE).c
LIBOBJ = $(TITLE).o
LIBOBJD = $(addprefix dynamic/,$(LIBOBJ))
LIBOBJS = $(addprefix static/,$(LIBOBJ))

ifdef DYNAMIC
LIBSHARED = $(TITLE).so
endif

ifdef STATIC
LIBSTATIC = lib$(TITLE).o
endif

####################### don't edit below #######################

all: dirs $(LIBSHARED) $(LIBSTATIC) register $(BINARY)

dynamic/%.o : %.c
	$(CC) $(CFLAGS) $(DYNAMIC) $(TARGET_ARCH) -c $< -o $@

static/%.o : %.c
	$(CC) $(CFLAGS) $(STATIC) $(TARGET_ARCH) -c $< -o $@

dirs:
ifdef DYNAMIC
	@$(MKDIR) ./dynamic
endif
ifdef STATIC
	@$(MKDIR) ./static
endif

register:
ifdef STATIC
	( cd .. ; ./register_static $(TITLE) $(TITLE)/$(LIBSTATIC) )
endif

ifdef DYNAMIC
$(LIBOBJD): $(LIBSRC)
endif

ifdef DYNAMIC
$(LIBSHARED):	$(LIBOBJD)
	$(LD_D) -o $@ $(LIBOBJD) $(LIBS) $(NEED_LINK_LIB_C)

endif

ifdef STATIC
$(LIBOBJS): $(LIBSRC)
endif

ifdef STATIC
$(LIBSTATIC): $(LIBOBJS)
	$(LD) -r -o $@ $(LIBOBJS) $(LIBS)
endif

install: all
	$(MKDIR) $(FAKEROOT)$(SECUREDIR)
ifdef DYNAMIC
	$(INSTALL) -m $(SHLIBMODE) $(LIBSHARED) $(FAKEROOT)$(SECUREDIR)
endif
ifdef MAN3
	test -d $(FAKEROOT)$(mandir)/man3 || $(MKDIR) $(FAKEROOT)$(mandir)/man3
	$(INSTALL) -m $(MANMODE) $(MAN3) $(FAKEROOT)$(mandir)/man3/
endif
ifdef MAN5
	test -d $(FAKEROOT)$(mandir)/man5 || $(MKDIR) $(FAKEROOT)$(mandir)/man5
	$(INSTALL) -m $(MANMODE) $(MAN5) $(FAKEROOT)$(mandir)/man5/
endif
ifdef MAN8
	test -d $(FAKEROOT)$(mandir)/man8 || $(MKDIR) $(FAKEROOT)$(mandir)/man8
	$(INSTALL) -m $(MANMODE) $(MAN8) $(FAKEROOT)$(mandir)/man8/
endif
	$(MKDIR) -m $(LOCKMODE) $(FAKEROOT)$(LOCKDIR) $(FAKEROOT)/$(SCONFIGD)/console.apps && bash -f ../install_conf "$(FAKEROOT)" "$(SCONFIGD)" "$(INSTALLED_CONFILE)" "$(TITLE)" "$(LOCAL_CONFILE)"
	install -m 555 $(BINARY) $(FAKEROOT)$(SUPLEMENTED)


remove:
	rm -f $(FAKEROOT)$(SECUREDIR)/$(TITLE).so

clean:
	rm -f $(BINARY) $(LIBOBJD) $(LIBOBJS) core *~
	rm -f *.a *.o *.so *.bak
	rm -rf dynamic static
	$(CLEAN)

.c.o:	
	$(CC) $(CFLAGS) -c $<

config.tab.c: config.y
	bison $(BISON_OPTS) -p _pc_yy $<
	sh ./sed-static $@

config.lex.c: config.l config.tab.c
	flex $(FLEX_OPTS) -o$@ -P_pc_yy $<
	sh ./sed-static $@

$(LIBSRC): pam_console.h chmod.c modechange.c regerr.c config.lex.c config.tab.c
