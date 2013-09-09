AUTOMAKE_OPTIONS = gnu
# the "." here makes sure check-local builds gtest before it is used
SUBDIRS = . src

EXTRA_DIST = \
	autogen.sh \
	make_version \
	check_version \
	.git_version \
	src/test/run-cli-tests \
	src/test/run-cli-tests-maybe-unset-ccache \
	src/test/cli \
	src/test/downloads

CLEANFILES = \
	ceph_ver.h

include contrib/Makefile.am
include man/Makefile.am

all-local:
if WITH_DEBUG
#	We need gtest to build the rados-api tests. We only build those in
#	a debug build, though.
	@cd src/gtest && $(MAKE) $(AM_MAKEFLAGS) lib/libgtest.a lib/libgtest_main.a
endif

check-local:
#	We build gtest this way, instead of using SUBDIRS, because with that,
#	gtest's own tests would be run and that would slow us down.
	@cd src/gtest && $(MAKE) $(AM_MAKEFLAGS) lib/libgtest.a lib/libgtest_main.a
#	exercise cli tools
	$(srcdir)/src/test/run-cli-tests '$(top_builddir)/src/test'

# "make distclean" both runs this and recurses into src/gtest, if
# gtest is in DIST_SUBDIRS. Take extra care to not fail when
# effectively cleaned twice.
clean-local:
	@if test -e src/gtest/Makefile; then \
	  echo "Making clean in src/gtest"; \
	  cd src/gtest && $(MAKE) $(AM_MAKEFLAGS) clean; \
	fi

	@rm -rf src/test/virtualenv


# version stuff

FORCE:
.git_version: FORCE
	./check_version $(srcdir)/.git_version
ceph_ver.h: .git_version
	./make_version $(srcdir)/.git_version ceph_ver.h

dist-hook:
	./check_version $(srcdir)/.git_version


