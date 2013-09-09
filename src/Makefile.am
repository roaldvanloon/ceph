include Makefile-env.am

SUBDIRS += ocf java
DIST_SUBDIRS += gtest ocf libs3 java


# subdirs

include arch/Makefile.am
include auth/Makefile.am
include crush/Makefile.am
include mon/Makefile.am
include mds/Makefile.am
include os/Makefile.am
include osd/Makefile.am
include osdc/Makefile.am
include client/Makefile.am
include global/Makefile.am
include json_spirit/Makefile.am
include log/Makefile.am
include perfglue/Makefile.am
include common/Makefile.am
include msg/Makefile.am
include messages/Makefile.am
include include/Makefile.am
include librados/Makefile.am
include librbd/Makefile.am
include rgw/Makefile.am
include cls/Makefile.am
include key_value_store/Makefile.am
include test/Makefile.am
include tools/Makefile.am


# core daemons

ceph_mon_SOURCES = ceph_mon.cc
ceph_mon_LDADD = $(LIBMON) $(LIBOS) $(CEPH_GLOBAL)
bin_PROGRAMS += ceph-mon

ceph_osd_SOURCES = ceph_osd.cc
ceph_osd_LDADD = $(LIBOSD) $(CEPH_GLOBAL)
if LINUX
ceph_osd_LDADD += -ldl
endif # LINUX
bin_PROGRAMS += ceph-osd

ceph_mds_SOURCES = ceph_mds.cc
ceph_mds_LDADD = $(LIBMDS) $(LIBOSDC) $(CEPH_GLOBAL)
bin_PROGRAMS += ceph-mds


# admin tools


# user tools

mount_ceph_SOURCES = mount/mount.ceph.c
mount_ceph_LDADD = $(LIBCOMMON)
if LINUX
sbin_PROGRAMS += mount.ceph
endif # LINUX
sbin_SCRIPTS += mount.fuse.ceph

cephfs_SOURCES = cephfs.cc
cephfs_LDADD = $(LIBCOMMON)
bin_PROGRAMS += cephfs

librados_config_SOURCES = librados-config.cc
librados_config_LDADD = $(LIBRADOS) $(CEPH_GLOBAL)
bin_PROGRAMS += librados-config

ceph_syn_SOURCES = ceph_syn.cc
ceph_syn_SOURCES += client/SyntheticClient.cc # uses g_conf.. needs cleanup
ceph_syn_LDADD = $(LIBCLIENT) $(CEPH_GLOBAL)
bin_PROGRAMS += ceph-syn

rbd_SOURCES = rbd.cc 
rbd_LDADD = $(LIBRBD) $(LIBRADOS) $(CEPH_GLOBAL)
if LINUX
bin_PROGRAMS += rbd
endif #LINUX



# Fuse targets

if WITH_FUSE
ceph_fuse_SOURCES = ceph_fuse.cc
ceph_fuse_LDADD = $(LIBCLIENT_FUSE) $(CEPH_GLOBAL)
bin_PROGRAMS += ceph-fuse

rbd_fuse_SOURCES = rbd_fuse/rbd-fuse.c
rbd_fuse_LDADD = -lfuse $(LIBRBD) $(LIBRADOS) $(CEPH_GLOBAL)
bin_PROGRAMS += rbd-fuse
endif # WITH_FUSE


# libcephfs (this and libhadoopcephfs should go somewhere else in the future)

libcephfs_la_SOURCES = libcephfs.cc
libcephfs_la_LIBADD = $(LIBCLIENT) $(LIBCOMMON) $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(EXTRALIBS)
libcephfs_la_LDFLAGS = ${AM_LDFLAGS} -version-info 1:0:0 -export-symbols-regex '^ceph_.*'
lib_LTLIBRARIES += libcephfs.la

# order matters! this *must* come after libcephfs, or else you'll encounter something
# like "error: relink libhadoopcephfs.la with the above command before installing it"
if WITH_HADOOPCLIENT
JAVA_BASE = /usr/lib/jvm/java-6-sun
libhadoopcephfs_la_SOURCES = client/hadoop/CephFSInterface.cc
libhadoopcephfs_la_LIBADD = $(LIBCEPHFS)
libhadoopcephfs_la_LDFLAGS = ${AM_LDFLAGS} -version-info 1:0:0 -export-symbols-regex 'hadoopcephfs_.*'
lib_LTLIBRARIES += libhadoopcephfs.la
noinst_HEADERS += client/hadoop/CephFSInterface.h
endif # WITH_HADOOPCLIENT


# jni library (java source is in src/java)

if ENABLE_CEPHFS_JAVA
libcephfs_jni_la_SOURCES = \
	java/native/libcephfs_jni.cc \
	java/native/ScopedLocalRef.h \
	java/native/JniConstants.cpp \
	java/native/JniConstants.h
libcephfs_jni_la_LIBADD = $(LIBCEPHFS) $(EXTRALIBS)
libcephfs_jni_la_CPPFLAGS = $(JDK_CPPFLAGS)
libcephfs_jni_la_LDFLAGS = ${AM_LDFLAGS} -version-info 1:0:0
lib_LTLIBRARIES += libcephfs_jni.la
endif


# extra bits

EXTRA_DIST += \
	$(srcdir)/vstart.sh \
	$(srcdir)/stop.sh \
	$(srcdir)/test/encoding/readable.sh \
	$(srcdir)/test/encoding/check-generated.sh \
	src/test/run-cli-tests \
	src/test/run-cli-tests-maybe-unset-ccache \
	src/test/cli \
	src/test/downloads \
	unittest_bufferlist.sh \
	yasm-wrapper

EXTRA_DIST += \
	libs3/COPYING \
	libs3/ChangeLog \
	libs3/GNUmakefile \
	libs3/GNUmakefile.mingw \
	libs3/GNUmakefile.osx \
	libs3/INSTALL \
	libs3/LICENSE \
	libs3/README \
	libs3/TODO \
	libs3/archlinux \
	libs3/debian \
	libs3/doxyfile \
	libs3/inc \
	libs3/libs3.spec \
	libs3/mswin \
	libs3/src \
	libs3/test




# tests to actually run on "make check"; if you need extra, non-test,
# executables built, you need to replace this with manual assignments
# target by target

TESTS = $(check_PROGRAMS) unittest_bufferlist.sh

check-local:
	$(srcdir)/test/encoding/check-generated.sh
	$(srcdir)/test/encoding/readable.sh ../ceph-object-corpus


# base targets

core-daemons: ceph-mon ceph-osd ceph-mds radosgw
admin-tools: monmaptool osdmaptool crushtool ceph-authtool
base: core-daemons admin-tools \
	cephfs ceph-syn ceph-conf ceph_mon_store_converter \
	rados librados-config ceph-post-file


#ceph_ver.c: $(srcdir)/ceph_ver.h
#common/version.cc: $(srcdir)/ceph_ver.h
#test/encoding/ceph_dencoder.cc: $(srcdir)/src/ceph_ver.h



# cleaning

clean-local:
	-rm *.so *.gcno *.gcda


# everything else we want to include in a 'make dist'

noinst_HEADERS += \
	cls_acl.cc\
	cls_crypto.cc\
	mount/canonicalize.c \
	mount/mtab.c \
	objclass/objclass.h


# coverage

if ENABLE_COVERAGE
COV_DIR = $(DESTDIR)$(libdir)/ceph/coverage
COV_FILES = $(srcdir)/*.gcno
COV_LIB_FILES = $(srcdir)/.libs/*.gcno
endif

install-coverage:
if ENABLE_COVERAGE
	-mkdir -p $(COV_DIR)/.libs
	-$(INSTALL_DATA) $(COV_FILES) $(COV_DIR)
	-$(INSTALL_DATA) $(COV_LIB_FILES) $(COV_DIR)/.libs
endif

uninstall-coverage:
if ENABLE_COVERAGE
	-rm $(COV_DIR)/*.gcno
	-rm $(COV_DIR)/.libs/*.gcno
	-rmdir -p $(COV_DIR)/.libs
	-rmdir -p $(COV_DIR)
endif

check-coverage:
if ENABLE_COVERAGE
	-test/coverage.sh -d $(srcdir) -o check-coverage make check
endif

install-data-local: install-coverage
	-mkdir -p $(DESTDIR)$(sysconfdir)/ceph
	-mkdir -p $(DESTDIR)$(localstatedir)/log/ceph
	-mkdir -p $(DESTDIR)$(localstatedir)/lib/ceph/tmp

uninstall-local: uninstall-coverage
	-rmdir -p $(DESTDIR)$(sysconfdir)/ceph/
	-rmdir -p $(DESTDIR)$(localstatedir)/log/ceph
	-rmdir -p $(DESTDIR)$(localstatedir)/lib/ceph/tmp

#
# coverity rules expect:
#  - cov-build to be in the path
#  - password in ~/coverity.build.pass.txt
#  - ability to scp into the ceph.com directory
#
project.tgz: clean
	rm -rf cov-int
	cov-build --dir cov-int make
	echo Sage Weil sage@newdream.net ceph >> README
	tar czvf project.tgz README cov-int
	rm -f README

coverity-submit:
	scp project.tgz ceph.com:/home/ceph_site/ceph.com/coverity/`git describe`.tgz
	curl --data "project=ceph&password=`cat ~/coverity.build.pass.txt`&email=sage@newdream.net&url=http://ceph.com/coverity/`git describe`.tgz" http://scan5.coverity.com/cgi-bin/submit_build.py
