#!/bin/bash -x

set -e

expect_false()
{
	set -x
	if "$@"; then return 1; else return 0; fi
}


#create pools, set up tier relationship
ceph osd pool create base_pool 2
ceph osd pool create empty_cache 2
ceph osd pool create data_cache 2
ceph osd tier add base_pool empty_cache
ceph osd tier add base_pool data_cache

# populate base_pool and data_cache with some data
echo "foo" > foo.txt
echo "bar" > bar.txt
echo "baz" > baz.txt
rados -p base_pool put fooobj foo.txt
rados -p base_pool put barobj bar.txt
# data_cache is backwards so we can tell we read from it
rados -p data_cache put fooobj bar.txt
rados -p data_cache put barobj foo.txt

# get the objects back before setting a caching pool
rados -p base_pool get fooobj tmp.txt
diff -q tmp.txt foo.txt
rados -p base_pool get barobj tmp.txt
diff -q tmp.txt bar.txt

# set up redirect and make sure we get nothing
ceph osd tier set-overlay base_pool empty_cache
expect_false rados -p base_pool get fooobj tmp.txt
expect_false rados -p base_pool get barobj tmp.txt
#let's write as well
rados -p base_pool put fooobj baz.txt
rados -p base_pool put barobj baz.txt
#and make sure we can look at the cache pool directly
rados -p empty_cache get fooobj tmp.txt
diff -q tmp.txt baz.txt

# switch cache pools and make sure contents differ
ceph osd tier remove-overlay base_pool
ceph osd tier set-overlay base_pool data_cache
rados -p base_pool get fooobj tmp.txt
diff -q tmp.txt bar.txt
rados -p base_pool get barobj tmp.txt
diff -q tmp.txt foo.txt

# drop the cache entirely and make sure contents are still the same
ceph osd tier remove-overlay base_pool
rados -p base_pool get fooobj tmp.txt
diff -q tmp.txt foo.txt
rados -p base_pool get barobj tmp.txt
diff -q tmp.txt bar.txt
