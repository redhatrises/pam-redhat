CFLAGS=-Wall
LIBTOOL=libtool --tag=CC

pam_succeed_if.so: pam_succeed_if.lo
	$(LIBTOOL) --mode=link    $(CC) -shared -o $@ $^ -lpam

pam_succeed_if.lo: pam_succeed_if.c
	$(LIBTOOL) --mode=compile $(CC) $(CFLAGS) -c -o $@ $^

clean:
	$(RM) *.o *.lo *.so
