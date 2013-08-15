#include "plugin.h"

#include "keystone.h"

int keystone_plugin_start(RGWPluginManager *pm, ...) {

  return 0;
}

void keystone_plugin_shutdown(RGWPluginManager *pm, ...) {

  return 0;
}


extern "C" rgw_plugin* rgw_plugin_init() {
  rgw_plugin *plugindef;
  plugindef = (rgw_plugin *) malloc(sizeof(rgw_plugin));
  plugindef->type = RGW_PLUGIN_TYPE_AUTH;
  plugindef->init = keystone_plugin_start;
  plugindef->exit = keystone_plugin_shutdown;
  return plugindef;
}

extern "C" void rgw_plugin_exit() {

}

