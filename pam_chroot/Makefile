# $Id$
CFLAGS+=-D_REENTRANT
LDFLAGS=--shared

OUT=pam_chroot.so

all:	$(OUT)

%.so: %.o
	$(LD_D) -o $@ $<

clean:
	rm -f *.o $(OUT)

install:
	install -m755 $(OUT) $(FAKEROOT)$(SECUREDIR)
	install -m644 chroot.conf $(FAKEROOT)$(SCONFIGED)
