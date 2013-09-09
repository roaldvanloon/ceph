ACLOCAL_AMFLAGS = -I contrib/m4

base: \
	contrib/init-ceph \
	contrib/mkcephfs \
	contrib/ceph-post-file


# why is it so hard to make autotools to this?
install-data-local:
	-mkdir -p $(DESTDIR)$(datadir)/ceph
	-install -m 644 contrib/share/known_hosts_drop.ceph.com $(DESTDIR)$(datadir)/ceph/known_hosts_drop.ceph.com
	-install -m 644 contrib/share/known_hosts_drop.ceph.com $(DESTDIR)$(datadir)/ceph/id_dsa_drop.ceph.com
	-install -m 644 contrib/share/known_hosts_drop.ceph.com $(DESTDIR)$(datadir)/ceph/id_dsa_drop.ceph.com.pub


editpaths = sed \
	-e 's|@bindir[@]|$(bindir)|g' \
	-e 's|@sbindir[@]|$(sbindir)|g' \
	-e 's|@libdir[@]|$(libdir)|g' \
	-e 's|@sysconfdir[@]|$(sysconfdir)|g' \
	-e 's|@datadir[@]|$(pkgdatadir)|g' \
	-e 's|@prefix[@]|$(prefix)|g' \
	-e 's|@@GCOV_PREFIX_STRIP[@][@]|$(GCOV_PREFIX_STRIP)|g'
shell_scripts = \
	contrib/ceph-debugpack \
	contrib/ceph-post-file \
	contrib/init-ceph \
	contrib/mkcephfs \
	contrib/ceph-coverage

$(shell_scripts): Makefile
$(shell_scripts): %: %.in
	rm -f $@ $@.tmp
	$(editpaths) '$(srcdir)/$@.in' >$@.tmp
	chmod +x $@.tmp
	chmod a-w $@.tmp
	mv $@.tmp $@

EXTRA_DIST += $(srcdir)/$(shell_scripts:%=%.in)
CLEANFILES += $(shell_scripts)

BUILT_SOURCES = contrib/init-ceph
sbin_SCRIPTS = contrib/mkcephfs


# assemble Python script with global version variables
# NB: depends on format of ceph_ver.h

contrib/ceph: contrib/ceph.in ceph_ver.h Makefile
	rm -f $@ $@.tmp
	echo "#!/usr/bin/python" >$@.tmp
	grep "#define CEPH_GIT_NICE_VER" ceph_ver.h | \
		sed -e 's/#define \(.*VER\) /\1=/' >>$@.tmp
	grep "#define CEPH_GIT_VER" ceph_ver.h | \
	  sed -e 's/#define \(.*VER\) /\1=/' -e 's/=\(.*\)$$/="\1"/' >>$@.tmp
	cat $@.in >>$@.tmp
	chmod a+x $@.tmp
	chmod a-w $@.tmp
	mv $@.tmp $@

EXTRA_DIST += \
	contrib/dist/rpm/ceph.spec.in \
	contrib/dist/rpm/ceph.spec \
	contrib/udev/50-rbd.rules \
	contrib/udev/60-ceph-partuuid-workaround.rules \
	contrib/udev/95-ceph-osd.rules \
	contrib/udev/95-ceph-osd-alt.rules \
	contrib/share/known_hosts_drop.ceph.com \
	contrib/share/id_dsa_drop.ceph.com \
	contrib/share/id_dsa_drop.ceph.com.pub \
	contrib/dist/upstart/ceph-all.conf \
	contrib/dist/upstart/ceph-mon.conf \
	contrib/dist/upstart/ceph-mon-all.conf \
	contrib/dist/upstart/ceph-mon-all-starter.conf \
	contrib/dist/upstart/ceph-create-keys.conf \
	contrib/dist/upstart/ceph-osd.conf \
	contrib/dist/upstart/ceph-osd-all.conf \
	contrib/dist/upstart/ceph-osd-all-starter.conf \
	contrib/dist/upstart/ceph-mds.conf \
	contrib/dist/upstart/ceph-mds-all.conf \
	contrib/dist/upstart/ceph-mds-all-starter.conf \
	contrib/dist/upstart/radosgw.conf \
	contrib/dist/upstart/radosgw-all.conf \
	contrib/dist/upstart/radosgw-all-starter.conf \
	contrib/ceph-run \
	contrib/verify-mds-journal.sh \
	contrib/ceph_common.sh \
	contrib/ceph-disk \
	contrib/ceph-disk-prepare \
	contrib/ceph-disk-activate \
	contrib/ceph-disk-udev \
	contrib/ceph-create-keys \
	contrib/ceph-rest-api \
	contrib/ceph-clsinfo \
	contrib/ceph-rbdnamer \
	contrib/ceph.in \
	contrib/init-radosgw \
	contrib/init-radosgw.sysv \
	contrib/init-rbdmap \
	contrib/mount.fuse.ceph \
	contrib/rbdmap


# fetch_config

contrib/sample.fetch_config: contrib/fetch_config
	cp -f $(srcdir)/contrib/fetch_config $(srcdir)/contrib/sample.fetch_config

EXTRA_DIST += contrib/sample.fetch_config


# work around old versions of automake that don't define $docdir
# NOTE: this won't work on suse, where docdir is /usr/share/doc/packages/$package.
docdir ?= ${datadir}/doc/ceph
doc_DATA = \
	contrib/sample.ceph.conf \
	contrib/sample.fetch_config

shell_commondir = $(libdir)/ceph
shell_common_SCRIPTS = \
	contrib/ceph_common.sh

bash_completiondir = $(sysconfdir)/bash_completion.d
bash_completion_DATA = \
	contrib/bash_completion/ceph \
	contrib/bash_completion/rados \
	contrib/bash_completion/rbd \
	contrib/bash_completion/radosgw-admin

ceph_sbindir = $(exec_prefix)$(sbindir)
ceph_sbin_SCRIPTS = \
	contrib/ceph-disk \
	contrib/ceph-disk-prepare \
	contrib/ceph-disk-activate \
	contrib/ceph-disk-udev \
	contrib/ceph-create-keys

bin_SCRIPTS = \
	contrib/ceph \
	contrib/ceph-run \
	contrib/ceph-rest-api \
	contrib/ceph-clsinfo \
	contrib/ceph-debugpack \
	contrib/ceph-rbdnamer \
	contrib/ceph-post-file \
	contrib/ceph-coverage


# pybind

python_PYTHON = \
	contrib/pybind/rados.py \
	contrib/pybind/rbd.py \
	contrib/pybind/cephfs.py \
	contrib/pybind/ceph_argparse.py \
	contrib/pybind/ceph_rest_api.py


# everything else we want to include in a 'make dist'

noinst_HEADERS = \
	contrib/fetch_config \
	contrib/logrotate.conf \
	contrib/sample.ceph.conf\
	contrib/bash_completion/ceph \
	contrib/bash_completion/rados \
	contrib/bash_completion/rbd \
	contrib/bash_completion/radosgw-admin


