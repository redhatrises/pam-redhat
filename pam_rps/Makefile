CFLAGS=-Wall
LIBTOOL=libtool --tag=CC

pam_rps.so: pam_rps.lo
	$(LIBTOOL) --mode=link    $(CC) -shared -o $@ $^ -lpam

pam_rps.lo: pam_rps.c
	$(LIBTOOL) --mode=compile $(CC) $(CFLAGS) -c -o $@ $^

clean:
	$(RM) *.o *.lo *.so
