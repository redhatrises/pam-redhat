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
	install -m 755 $(OUT) $(FAKEROOT)$(SECUREDIR)
	install -m 644 chroot.conf $(FAKEROOT)$(SCONFIGED)
