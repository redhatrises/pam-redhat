#
# This Makefile controls a build process of $(TITLE) module for
# Linux-PAM. You should not modify this Makefile (unless you know
# what you are doing!).
#
# Created by Michael K. Johnson <johnsonm@redhat.com> 1999/04/10
#

TITLE=pam_xauth

LIBSRC = $(TITLE).c
LIBOBJ = $(TITLE).o
LIBOBJD = $(addprefix dynamic/,$(LIBOBJ))
#LIBOBJS = $(addprefix static/,$(LIBOBJ))
MANMODE = 644
MAN8 = pam_xauth.8
MAN8DIR = /usr/man/man8

dynamic/%.o : %.c
	$(CC) $(CFLAGS) $(DYNAMIC) $(CPPFLAGS) $(TARGET_ARCH) -c $< -o $@

#static/%.o : %.c
#	$(CC) $(CFLAGS) $(STATIC) $(CPPFLAGS) $(TARGET_ARCH) -c $< -o $@


ifdef DYNAMIC
LIBSHARED = $(TITLE).so
endif

#ifdef STATIC
#LIBSTATIC = lib$(TITLE).o
#endif

####################### don't edit below #######################

dummy:

	@echo "**** This is not a top-level Makefile "
	exit

all: dirs $(LIBSHARED) $(LIBSTATIC) register

dirs:
ifdef DYNAMIC
	$(MKDIR) ./dynamic
endif
#ifdef STATIC
#	$(MKDIR) ./static
#endif

register:
#ifdef STATIC
#	( cd .. ; ./register_static $(TITLE) $(TITLE)/$(LIBSTATIC) )
#endif

ifdef DYNAMIC
$(LIBOBJD): $(LIBSRC)

$(LIBSHARED):	$(LIBOBJD)
	$(LD_D) -o $@ $(LIBOBJD) $(EXTRALS)
endif

#ifdef STATIC
#$(LIBOBJS): $(LIBSRC)
#
#$(LIBSTATIC): $(LIBOBJS)
#	$(LD) -r -o $@ $(LIBOBJS) $(EXTRALS)
#endif

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
	rm -f $(LIBOBJD) $(LIBOBJS) core *~ *.so

extraclean: clean
	rm -f *.a *.o *.so *.bak dynamic/* static/*

.c.o:	
	$(CC) $(CFLAGS) -c $<

