#ifndef CEPH_RGW_AUTH_H
#define CEPH_RGW_AUTH_H

#include "include/types.h"
#include "include/str_list.h"
#include "rgw_common.h"
#include "rgw_plugin.h"
#include "rgw_rados.h"
#include "rgw_op.h"

class RGWAuth {
public:
  RGWAuth();
  virtual ~RGWAuth() { };
  virtual int authorize(RGWRados *store, struct req_state *s) = 0;
};

class RGWAuthPipeline {
public:
  RGWAuthPipeline(RGWPluginManager *_pm) : plugin_manager(_pm) {};
  ~RGWAuthPipeline();

private:
  RGWPluginManager *plugin_manager;
  vector<string> pipeline;
  map<string, RGWAuth*> handlers;

public:
  int init(string auth_pipeline_config);
  int plug(const string& ident, RGWAuth* a);
  int unplug(const string& ident);
  int authorize(RGWRados *store, struct req_state *s);
};

class RGWRESTMgr;

class RGWAuthManager {
public:
  RGWAuthManager(RGWPluginManager *_pm) :
    plugin_manager(_pm) {};
  ~RGWAuthManager() {};

  RGWAuthPipeline* find_pipeline(RGWRESTMgr* mgr);

private:
  RGWPluginManager *plugin_manager;
  map<RGWRESTMgr*, RGWAuthPipeline *> pipelines;
};

#endif /* CEPH_RGW_AUTH_H */
