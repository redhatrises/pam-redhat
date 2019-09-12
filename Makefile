VERSION=1.1.1
TAG=pam-redhat-$(VERSION)

nothing:

tag:
	git tag $(TAG)

force-tag:
	git tag --force $(TAG)

dist:
	@rm -f $(TAG).tar.bz2 
	git archive --format=tar --prefix=$(TAG)/ $(TAG) | bzip2 > $(TAG).tar.bz2
	@echo "The archive is in $(TAG).tar.bz2" 
