SUBDIRS = lib
if BUILD_PAM_CHROOT
SUBDIRS += pam_chroot
endif
if BUILD_PAM_CONSOLE
SUBDIRS += pam_console
endif
if BUILD_PAM_LOCALUSER
SUBDIRS += pam_localuser
endif
if BUILD_PAM_POSTGRESOK
SUBDIRS += pam_postgresok
endif
if BUILD_PAM_RPS
SUBDIRS += pam_rps
endif
if BUILD_PAM_SASLAUTHD
SUBDIRS += pam_saslauthd
endif
if BUILD_PAM_STACK
SUBDIRS += pam_stack
endif
if BUILD_PAM_SUCCEED_IF
SUBDIRS += pam_succeed_if
endif
if BUILD_PAM_TIMESTAMP
SUBDIRS += pam_timestamp
endif
if BUILD_PAM_XAUTH
SUBDIRS += pam_xauth
endif

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
	@dir=$$PWD; cd /tmp/pam-redhat-$(VERSION); autoreconf -i; ./configure ; make dist ; cp -v pam-redhat-$(VERSION).tar.gz $$dir/
	@rm -rf /tmp/pam-redhat-$(VERSION)
	@echo "The archive is in pam-redhat-$(VERSION).tar.gz" 
