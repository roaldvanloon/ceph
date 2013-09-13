## Benchmarks

ceph_smalliobench_SOURCES = \
	test/bench/small_io_bench.cc \
	test/bench/rados_backend.cc \
	test/bench/detailed_stat_collector.cc \
	test/bench/bencher.cc
ceph_smalliobench_LDADD = $(LIBRADOS) -lboost_program_options $(CEPH_GLOBAL)
bin_DEBUGPROGRAMS += ceph_smalliobench

ceph_smalliobenchfs_SOURCES = \
	test/bench/small_io_bench_fs.cc \
	test/bench/testfilestore_backend.cc \
	test/bench/detailed_stat_collector.cc \
	test/bench/bencher.cc
ceph_smalliobenchfs_LDADD = $(LIBRADOS) -lboost_program_options $(LIBOS) $(CEPH_GLOBAL)
bin_DEBUGPROGRAMS += ceph_smalliobenchfs

ceph_smalliobenchdumb_SOURCES = \
	test/bench/small_io_bench_dumb.cc \
	test/bench/dumb_backend.cc \
	test/bench/detailed_stat_collector.cc \
	test/bench/bencher.cc
ceph_smalliobenchdumb_LDADD = $(LIBRADOS) -lboost_program_options $(LIBOS) $(CEPH_GLOBAL)
bin_DEBUGPROGRAMS += ceph_smalliobenchdumb

ceph_smalliobenchrbd_SOURCES = \
	test/bench/small_io_bench_rbd.cc \
	test/bench/rbd_backend.cc \
	test/bench/detailed_stat_collector.cc \
	test/bench/bencher.cc
ceph_smalliobenchrbd_LDADD = $(LIBRBD) $(LIBRADOS) -lboost_program_options $(CEPH_GLOBAL)
bin_DEBUGPROGRAMS += ceph_smalliobenchrbd

ceph_tpbench_SOURCES = \
	test/bench/tp_bench.cc \
	test/bench/detailed_stat_collector.cc
ceph_tpbench_LDADD = $(LIBRADOS) -lboost_program_options $(LIBOS) $(CEPH_GLOBAL)
bin_DEBUGPROGRAMS += ceph_tpbench

ceph_omapbench_SOURCES = test/bench/omap_bench.cc
ceph_omapbench_LDADD = $(LIBRADOS) $(CEPH_GLOBAL)
bin_DEBUGPROGRAMS += ceph_omapbench

ceph_kvstorebench_SOURCES = \
	test/bench/kv_store_bench.cc \
	key_value_store/kv_flat_btree_async.cc
ceph_kvstorebench_LDADD = $(LIBRADOS) $(CEPH_GLOBAL)
bin_DEBUGPROGRAMS += ceph_kvstorebench

ceph_bench_log_SOURCES = test/bench/bench_log.cc
ceph_bench_log_LDADD = $(CEPH_GLOBAL)
bin_DEBUGPROGRAMS += ceph_bench_log

ceph_xattr_bench_SOURCES = test/bench/xattr_bench.cc
ceph_xattr_bench_LDADD = $(LIBOS) $(UNITTEST_LDADD) $(CEPH_GLOBAL)
ceph_xattr_bench_CXXFLAGS = $(UNITTEST_CXXFLAGS)
bin_DEBUGPROGRAMS += ceph_xattr_bench

noinst_HEADERS += \
	test/bench/distribution.h \
	test/bench/rados_backend.h \
	test/bench/rbd_backend.h \
	test/bench/bencher.h \
	test/bench/backend.h \
	test/bench/dumb_backend.h \
	test/bench/stat_collector.h \
	test/bench/detailed_stat_collector.h \
	test/bench/testfilestore_backend.h \
	test/bench/kv_store_bench.h \
	test/bench/omap_bench.h

