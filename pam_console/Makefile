#
# This Makefile controls a build process of $(TITLE) module for
# Linux-PAM. You should not modify this Makefile (unless you know
# what you are doing!).
#

include ../../default.defs

TITLE=pam_console

#

LIBSRC = pam_console.c 
LIBOBJ = pam_console.o
LIBOBJD = $(addprefix dynamic/,$(LIBOBJ)) $(shell glib-config --libs) -lc
LIBOBJS = $(addprefix static/,$(LIBOBJ))
SECUREDIR = /lib/security/
CONFDIR = /etc/security
LOCKDIR = /var/lock/console
SHLIBMODE = 755
CONFMODE = 644
CONFDIRMODE = 755
MANMODE = 644
LOCKMODE = 755
CFLAGS = $(RPM_OPT_FLAGS) -DPAM_READ_BOTH_CONFS -D_GNU_SOURCE -DLINUX_PAM \
	$(shell glib-config --cflags) \
	-Wall -Wpointer-arith -Wcast-qual -Wcast-align\
	-Wtraditional -Wstrict-prototypes -Wmissing-prototypes \
	-Wnested-externs -Winline -Wshadow \
	-fPIC -Dlinux
DYNAMIC = -DPAM_DYNAMIC
MAN5 = console.apps.5 console.perms.5
MAN8 = pam_console.8
MAN5DIR = $(MANDIR)/man5
MAN8DIR = $(MANDIR)/man8
CONF = console.perms
MKDIR = mkdir -p
CHMOD = chmod
FLEX_OPTS = -Cr # -d
BISON_OPTS = -d
LD_D = gcc -shared

dynamic/%.o : %.c
	$(CC) $(CFLAGS) $(DYNAMIC) $(CPPFLAGS) $(TARGET_ARCH) -c $< -o $@

static/%.o : %.c
	$(CC) $(CFLAGS) $(STATIC) $(CPPFLAGS) $(TARGET_ARCH) -c $< -o $@


ifdef DYNAMIC
LIBSHARED = $(TITLE).so
endif

#ifdef STATIC
#LIBSTATIC = lib$(TITLE).o
#endif

####################### don't edit below #######################

#dummy:
#
#	@echo "**** This is not a top-level Makefile "
#	exit

all: dirs $(LIBSHARED) $(LIBSTATIC) 

config.tab.c: config.y
	bison $(BISON_OPTS) -p _pc_yy $<
	sh ./sed-static $@

config.lex.c: config.l config.tab.c
	flex $(FLEX_OPTS) -o$@ -P_pc_yy $<
	sh ./sed-static $@

dirs:
ifdef DYNAMIC
	$(MKDIR) ./dynamic
endif
ifdef STATIC
	$(MKDIR) ./static
endif

#register:
#ifdef STATIC
#	( cd .. ; ./register_static $(TITLE) $(TITLE)/$(LIBSTATIC) )
#endif

$(LIBSRC): pam_console.h chmod.c modechange.c regerr.c config.lex.c config.tab.c

ifdef DYNAMIC
$(LIBOBJD): $(LIBSRC)

$(LIBSHARED):	$(LIBOBJD)
		$(LD_D) -o $@ $(LIBOBJD)
endif

ifdef STATIC
$(LIBOBJS): $(LIBSRC)

$(LIBSTATIC): $(LIBOBJS)
	$(LD) -r -o $@ $(LIBOBJS)
endif

install: all
	$(MKDIR) $(FAKEROOT)$(SECUREDIR)
	$(MKDIR) $(FAKEROOT)$(CONFDIR)/console.apps
	$(CHMOD) $(CONFDIRMODE) $(FAKEROOT)$(CONFDIR)/console.apps
	$(MKDIR) $(FAKEROOT)$(MAN5DIR)
	$(MKDIR) $(FAKEROOT)$(MAN8DIR)
	$(INSTALL) -m $(CONFMODE) $(CONF) $(FAKEROOT)$(CONFDIR)
	$(INSTALL) -m $(MANMODE) $(MAN5) $(FAKEROOT)$(MAN5DIR)
	$(INSTALL) -m $(MANMODE) $(MAN8) $(FAKEROOT)$(MAN8DIR)
	$(INSTALL) -m $(LOCKMODE) -d $(FAKEROOT)$(LOCKDIR)
ifdef DYNAMIC
	$(INSTALL) -m $(SHLIBMODE) $(LIBSHARED) $(FAKEROOT)$(SECUREDIR)
endif

remove:
	rm -f $(FAKEROOT)$(SECUREDIR)/$(TITLE).so

clean:
	rm -rf dynamic static core *~
	rm -f config.tab.c config.tab.h config.lex.c

extraclean: clean
	rm -f *.a *.o *.so *.bak

.c.o:	
	$(CC) $(CFLAGS) -c $<

