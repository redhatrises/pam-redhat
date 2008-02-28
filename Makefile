VERSION=0.99.9
RELEASE=1
HGTAG=pam-redhat-$(shell echo $(VERSION) | sed s,\\.,-,g)-$(RELEASE)
CVS_ROOT=$(shell cat CVS/Root)

nothing:

tag:
	hg tag $(HGTAG)

force-tag:
	hg tag --force $(HGTAG)

archive: tag
	@rm -f pam-redhat-$(VERSION)-$(RELEASE).tar.bz2 
	hg archive -r $(HGTAG) -t tbz2 -X Makefile pam-redhat-$(VERSION)-$(RELEASE).tar.bz2
	@echo "The archive is in pam-redhat-$(VERSION)-$(RELEASE).tar.bz2" 
