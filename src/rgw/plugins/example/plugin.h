#ifndef CEPH_RGW_PLUGIN_EXAMPLE_PLUGIN_H
#define CEPH_RGW_PLUGIN_EXAMPLE_PLUGIN_H

#include "rgw/rgw_plugin.h"

int example_plugin_unload(rgw_plugin *plugindef);
int example_plugin_load(rgw_plugin *plugindef);

#endif /* CEPH_RGW_PLUGIN_EXAMPLE_PLUGIN_H */
