# $Id$

CC=gcc
CFLAGS=-fPIC -O2 -Wall -Werror -pedantic
LDFLAGS=-x --shared -lpam

OUT=pam_chroot.so

all:	$(OUT)

%.so: %.o
	ld $(LDFLAGS) -o $@ $<

clean:
	rm -f *.o $(OUT)

install:
	install -s -o0 -g0 -m755 $(OUT) /lib/security
