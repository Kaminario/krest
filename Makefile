

KREST_VERSION = $(shell grep ^Version: krest.spec | awk '{print $$2}')

TARBALL_DIR = krest-$(KREST_VERSION)
TARBALL = $(TARBALL_DIR).tar.gz

SPEC_FILE_NAME = krest.spec
RPMBUILD = /usr/bin/rpmbuild

all: rpm

tarball: clean
	touch $(TARBALL)  # to stop tar complaining about . being changed while reading
	tar --exclude .git --exclude $(TARBALL) \
		--transform='s|^\.|krest-$(KREST_VERSION)|' \
		-zcvf $(TARBALL) .

rpm: tarball
	${RPMBUILD} -bb ${SPEC_FILE_NAME} \
        --define "_sourcedir $$PWD" \
        --define "_rpmdir $$PWD/RPMS" \
        --define "_builddir $$PWD" \
        --define "_tmppath $$PWD/tmp" 

rpm_clean:
	rm -rf $(TARBALL_DIR) RPMS tmp
	
clean: rpm_clean
	rm -rf $(TARBALL)


.PHONY: all rpm clean rpm_clean tarball
