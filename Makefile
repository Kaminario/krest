
#
# (c) 2015 Kaminario Technologies, Ltd.
#
# This software is licensed solely under the terms of the Apache 2.0 license,
# the text of which is available at http://www.apache.org/licenses/LICENSE-2.0.
# All disclaimers and limitations of liability set forth in the Apache 2.0 license apply.
#

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
