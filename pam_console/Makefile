#
# This Makefile controls a build process of $(TITLE) module for
# Linux-PAM. You should not modify this Makefile (unless you know
# what you are doing!).
#

include ../../Make.Rules

TITLE=pam_console

ifeq ($(PREFER_GLIB1),yes)
GLIB_CFLAGS = $(shell glib-config --cflags)
GLIB_LIBS = $(shell glib-config --libs)
else
GLIB_CFLAGS = $(shell pkg-config --cflags glib-2.0)
GLIB_LIBS = $(shell pkg-config --libs glib-2.0)
endif

LOCKDIR = /var/run/console
LOCKMODE = 755
LIBS +=  $(GLIB_LIBS) -L../pammodutil -lpammodutil


LOCAL_CONF1 = console.perms
INSTALLED_CONF1 = $(SCONFIGD)/console.perms
LOCAL_CONF2 = console.handlers
INSTALLED_CONF2 = $(SCONFIGD)/console.handlers
MAN5 = console.apps.5 console.perms.5 console.handlers.5
MAN8 = pam_console.8 pam_console_apply.8

CFLAGS += $(GLIB_CFLAGS) -DLOCKDIR=\"$(LOCKDIR)\" -I../pammodutil/include
FLEX_OPTS = -Cr
BISON_OPTS = -d

LIBSRC = pam_console.c pam_console.h chmod.c modechange.c regerr.c config.lex.c config.tab.c handlers.c
BINSRC = pam_console_apply.c pam_console.h chmod.c modechange.c regerr.c config.lex.c config.tab.c

BINOBJ = $(TITLE)_apply.o
BINARY = $(TITLE)_apply

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

$(BINARY): $(BINOBJ)
	$(LD) $(LDFLAGS) -o $@ $(BINOBJ) -Wl,-Bstatic $(LIBS) -Wl,-Bdynamic ../../libpam/libpam.so -lc

$(BINOBJ): $(BINSRC)

ifdef DYNAMIC
$(LIBOBJD): $(LIBSRC)
endif

ifdef DYNAMIC
$(LIBSHARED):	$(LIBOBJD)
	$(LD_D) $(LDFLAGS) -o $@ $(LIBOBJD) -Wl,--exclude-libs,ALL,-Bstatic $(LIBS) -Wl,-Bdynamic  $(NEED_LINK_LIB_C)

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
	test -d $(FAKEROOT)$(MANDIR)/man3 || $(MKDIR) $(FAKEROOT)$(MANDIR)/man3
	$(INSTALL) -m $(MANMODE) $(MAN3) $(FAKEROOT)$(MANDIR)/man3/
endif
ifdef MAN5
	test -d $(FAKEROOT)$(MANDIR)/man5 || $(MKDIR) $(FAKEROOT)$(MANDIR)/man5
	$(INSTALL) -m $(MANMODE) $(MAN5) $(FAKEROOT)$(MANDIR)/man5/
endif
ifdef MAN8
	test -d $(FAKEROOT)$(MANDIR)/man8 || $(MKDIR) $(FAKEROOT)$(MANDIR)/man8
	$(INSTALL) -m $(MANMODE) $(MAN8) $(FAKEROOT)$(MANDIR)/man8/
endif
	if $(MKDIR) -m $(LOCKMODE) $(FAKEROOT)$(LOCKDIR) $(FAKEROOT)/$(SCONFIGD)/console.apps ; then \
	    bash -f ../install_conf "$(FAKEROOT)" "$(SCONFIGD)" "$(INSTALLED_CONF1)" "$(TITLE)" "$(LOCAL_CONF1)" ;\
	    bash -f ../install_conf "$(FAKEROOT)" "$(SCONFIGD)" "$(INSTALLED_CONF2)" "$(TITLE)" "$(LOCAL_CONF2)" ;\
	fi
	test -d  $(FAKEROOT)$(SUPLEMENTED) || install -m 755 -d $(FAKEROOT)$(SUPLEMENTED)
	install -m 555 $(BINARY) $(FAKEROOT)$(SUPLEMENTED)


remove:
	rm -f $(FAKEROOT)$(SECUREDIR)/$(TITLE).so

clean:
	rm -f $(BINARY) $(LIBOBJD) $(LIBOBJS) core *~
	rm -f *.a *.o *.so *.bak
	rm -f config.tab.c config.tab.h config.lex.c
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

