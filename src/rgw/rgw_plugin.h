#ifndef CEPH_RGW_PLUGIN_H
#define CEPH_RGW_PLUGIN_H

#include <stdint.h>
#include <string.h>
#include <string>
#include <map>

#include "rgw_common.h"

#define RGW_PLUGIN_IS_SINGULAR true

#define RGW_PLUGIN_TYPE_REST_API   1
#define RGW_PLUGIN_TYPE_AUTH       2

struct rgw_plugin;

typedef rgw_plugin* (*plugin_initfunc)();

map<string, plugin_initfunc> & static_plugins();

struct RGWStaticPluginRegistrar {
public:
  RGWStaticPluginRegistrar(string name, plugin_initfunc f) {
      static_plugins()[name] = f;
    }
};

/*
 * We can change this to #ifdef RGW_STATIC_PLUGINS later on
 * to also support dynamic loadable plugins, but not for now.
 */
#if 1
#define START_PLUGIN(name, type, is_singular) \
  rgw_plugin* name##_plugin_init() { \
    rgw_plugin name = { type, is_singular };
#define FINISH_PLUGIN(name) \
    rgw_plugin *plugindef = (rgw_plugin *) malloc(sizeof(rgw_plugin)); \
    if (plugindef == NULL) \
      return NULL; \
    memcpy(plugindef, &name, sizeof *plugindef); \
    return plugindef; \
  }; \
  static RGWStaticPluginRegistrar __rgw_static_plugin_##name(#name, name##_plugin_init);
#else
#define START_PLUGIN(name, type, is_singular) \
  extern "C" rgw_plugin* __rgw_plugin_init() { \
    rgw_plugin name = { type, is_singular };
#define FINISH_PLUGIN(name) \
    rgw_plugin *plugindef = (rgw_plugin *) malloc(sizeof(rgw_plugin)); \
    if (plugindef == NULL) \
      return NULL; \
    memcpy(plugindef, &name, sizeof *plugindef); \
    return plugindef; \
  };
#endif

class RGWPluginManager {
public:
  RGWPluginManager(CephContext *_cct) : cct(_cct) { };
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
