#
# This Makefile controls a build process of $(TITLE) module for
# Linux-PAM. You should not modify this Makefile (unless you know
# what you are doing!).
#

TITLE=pam_stack

#

LIBSRC = pam_stack.c 
LIBOBJ = pam_stack.o
LIBOBJD = $(addprefix dynamic/,$(LIBOBJ)) -lc
LIBOBJS = $(addprefix static/,$(LIBOBJ))
SECUREDIR = /lib/security/
CONFDIR = /etc/security
SHLIBMODE = 755
CONFMODE = 644
CONFDIRMODE = 755
MANMODE = 644
LOCKMODE = 755
CFLAGS = $(RPM_OPT_FLAGS) -DPAM_READ_BOTH_CONFS -D_GNU_SOURCE -DLINUX_PAM \
	-Wall -Wpointer-arith -Wcast-qual -Wcast-align\
	-Wtraditional -Wstrict-prototypes -Wmissing-prototypes \
	-Wnested-externs -Winline -Wshadow \
	-fPIC -Dlinux
DYNAMIC = -DPAM_DYNAMIC
MAN8 = pam_stack.8
MAN8DIR = /usr/man/man8
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

ifdef STATIC
LIBSTATIC = lib$(TITLE).o
endif

####################### don't edit below #######################

#dummy:
#
#	@echo "**** This is not a top-level Makefile "
#	exit

all: dirs $(LIBSHARED) $(LIBSTATIC) 

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
	$(MKDIR) $(FAKEROOT)$(MAN8DIR)
ifdef DYNAMIC
	$(INSTALL) -m $(SHLIBMODE) $(LIBSHARED) $(FAKEROOT)$(SECUREDIR)
endif
	$(INSTALL) -m $(MANMODE) $(MAN8) $(FAKEROOT)$(MAN8DIR)

remove:
	rm -f $(FAKEROOT)$(SECUREDIR)/$(TITLE).so

clean:
	rm -rf dynamic static core *~
	rm -f config.tab.c config.tab.h config.lex.c

extraclean: clean
	rm -f *.a *.o *.so *.bak

.c.o:	
	$(CC) $(CFLAGS) -c $<

