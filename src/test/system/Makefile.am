## System tests

libsystest_la_SOURCES = \
	test/system/cross_process_sem.cc \
	test/system/systest_runnable.cc \
	test/system/systest_settings.cc
libsystest_la_LIBADD = $(CEPH_GLOBAL)
noinst_LTLIBRARIES += libsystest.la

ceph_test_rados_list_parallel_SOURCES = \
	test/system/rados_list_parallel.cc \
	test/system/st_rados_create_pool.cc \
	test/system/st_rados_list_objects.cc
ceph_test_rados_list_parallel_LDADD = $(LIBRADOS) libsystest.la $(PTHREAD_LIBS)
bin_DEBUGPROGRAMS += ceph_test_rados_list_parallel

ceph_test_rados_open_pools_parallel_SOURCES = \
	test/system/rados_open_pools_parallel.cc \
	test/system/st_rados_create_pool.cc
ceph_test_rados_open_pools_parallel_LDADD = $(LIBRADOS) libsystest.la $(PTHREAD_LIBS)
bin_DEBUGPROGRAMS += ceph_test_rados_open_pools_parallel

ceph_test_rados_delete_pools_parallel_SOURCES = \
	test/system/rados_delete_pools_parallel.cc \
	test/system/st_rados_create_pool.cc \
	test/system/st_rados_delete_pool.cc \
	test/system/st_rados_list_objects.cc
ceph_test_rados_delete_pools_parallel_LDADD = $(LIBRADOS) libsystest.la $(PTHREAD_LIBS)
bin_DEBUGPROGRAMS += ceph_test_rados_delete_pools_parallel

ceph_test_rados_watch_notify_SOURCES = \
	test/system/rados_watch_notify.cc \
	test/system/st_rados_create_pool.cc \
	test/system/st_rados_delete_pool.cc \
	test/system/st_rados_delete_objs.cc \
	test/system/st_rados_watch.cc \
	test/system/st_rados_notify.cc
ceph_test_rados_watch_notify_LDADD = $(LIBRADOS) libsystest.la $(PTHREAD_LIBS)
bin_DEBUGPROGRAMS += ceph_test_rados_watch_notify


noinst_HEADERS += \
	test/system/cross_process_sem.h \
	test/system/st_rados_create_pool.h \
	test/system/st_rados_list_objects.h \
	test/system/st_rados_delete_objs.h \
	test/system/st_rados_delete_pool.h \
	test/system/st_rados_notify.h \
	test/system/st_rados_watch.h \
	test/system/systest_runnable.h \
	test/system/systest_settings.h

