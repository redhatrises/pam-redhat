SUBDIRS = \
	lib \
	pam_chroot \
	pam_console \
	pam_localuser \
	pam_postgresok \
	pam_rps \
	pam_stack \
	pam_succeed_if \
	pam_timestamp \
	pam_xauth

CVSTAG=$(shell echo pam-redhat-$(VERSION) | sed s,\\.,-,g)
CVS_ROOT=$(shell cat CVS/Root)

tag:
	cvs tag -cR $(CVSTAG) .

force-tag:
	cvs tag -cFR $(CVSTAG) . 

archive: tag
	@rm -f pam-redhat-$(VERSION).tar.gz 
	@rm -rf /tmp/pam-redhat-$(VERSION)
	cd /tmp; cvs -d $(CVS_ROOT) export -r$(CVSTAG) -d pam-redhat-$(VERSION) pam-redhat
	@dir=$$PWD; cd /tmp/pam-redhat-$(VERSION); autoreconf; ./configure ; make dist ; cp -v pam-redhat-$(VERSION).tar.gz $$dir/
	@rm -rf /tmp/pam-redhat-$(VERSION)
	@echo "The archive is in pam-redhat-$(VERSION).tar.gz" 
