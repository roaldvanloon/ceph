#ifndef CEPH_RGW_PLUGIN_KEYSTONE_PLUGIN_H
#define CEPH_RGW_PLUGIN_KEYSTONE_PLUGIN_H

#include "rgw/rgw_plugin.h"

extern "C" rgw_plugin* rgw_plugin_init();

int keystone_plugin_unload(rgw_plugin *plugindef);
int keystone_plugin_load(rgw_plugin *plugindef);

#endif /* CEPH_RGW_PLUGIN_KEYSTONE_PLUGIN_H */
