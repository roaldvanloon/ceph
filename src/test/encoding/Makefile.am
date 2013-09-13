## Dencoder test

ceph_dencoder_SOURCES = \
	test/encoding/ceph_dencoder.cc \
	$(DENCODER_SOURCES)
ceph_dencoder_LDADD = \
	$(LIBOSD) $(LIBMDS) $(LIBMON) \
	$(DENCODER_DEPS) $(CEPH_GLOBAL)

# These should always use explicit _CFLAGS/_CXXFLAGS so avoid basename conflicts
ceph_dencoder_CFLAGS = ${AM_CFLAGS}
ceph_dencoder_CXXFLAGS = ${AM_CXXFLAGS}

if COMPILER_HAS_VTA
ceph_dencoder_CFLAGS += -fno-var-tracking-assignments
ceph_dencoder_CXXFLAGS += -fno-var-tracking-assignments
endif

bin_PROGRAMS += ceph-dencoder

check_SCRIPTS += test/encoding/check-generated.sh

EXTRA_DIST += \
	test/encoding/readable.sh \
	test/encoding/check-generated.sh

check-local:
	test/encoding/readable.sh ../ceph-object-corpus

noinst_HEADERS += \
	test/encoding/types.h

