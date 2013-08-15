#ifndef CEPH_RGW_PLUGIN_H
#define CEPH_RGW_PLUGIN_H

#include <stdint.h>

#include "rgw_common.h"

#define RGW_PLUGIN_TYPE_REST_API   1
#define RGW_PLUGIN_TYPE_AUTH       2

struct rgw_plugin;

class RGWPluginManager {
public:
  RGWPluginManager(CephContext *_cct) : cct(_cct) {};
  ~RGWPluginManager() {};

private:
  CephContext *cct;
  map<string, list<rgw_plugin*> > plugin_map;

public:
  int load_plugins();
  int register_plugins(uint32_t type, void *owner);
  int unregister_plugins(uint32_t type, void *owner);

private:
  int link_plugin(const string& name, void *owner);
  int unlink_plugin(const string& name, void *owner);
};

struct rgw_plugin {
  const uint32_t type;
  const bool is_singular; // allow this plugin to be loaded multiple times
  int (* init)(rgw_plugin *);
  int (* exit)(rgw_plugin *);
  RGWPluginManager * plugin_manager;
  void * owner;
  CephContext *context;
};




#endif /* CEPH_RGW_PLUGIN_H */
