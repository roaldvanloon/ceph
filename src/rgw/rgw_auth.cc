#include "rgw_rest.h"

#include "rgw_auth.h"

#define dout_subsys ceph_subsys_rgw

/* We need this here so the symbol gets exported correctly (for auth plugins) */
RGWAuth::RGWAuth() { }

int RGWAuthPipeline::init(string auth_pipeline_config) {
  if (pipeline.size())
    return -EINVAL;

  dout(0) << "Initializing new pipeline based on config: " << auth_pipeline_config << dendl;

  list<string> auths;
  get_str_list(auth_pipeline_config, auths);

  for (list<string>::iterator li = auths.begin(); li != auths.end(); ++li) {
    pipeline.push_back(*li);
    handlers[*li] = NULL;
  }

  return handlers.size();
}

RGWAuthPipeline::~RGWAuthPipeline() {
  plugin_manager->unregister_plugins(RGW_PLUGIN_TYPE_AUTH, (void *) this);
}

int RGWAuthPipeline::plug(const string& ident, RGWAuth* a) {
  dout(20) << "Trying to plug into pipeline: " << ident << dendl;
  if (!handlers.count(ident))
    return -ENOENT;
  if (handlers[ident])
    return -EEXIST;
  handlers[ident] = a;
  dout(0) << "Plugged into pipeline: " << ident << dendl;
  return 0;
}

int RGWAuthPipeline::unplug(const string& ident) {
  dout(20) << "Trying to unplug from pipeline: " << ident << dendl;
  if (!handlers.count(ident))
    return -ENOENT;
  delete handlers[ident];
  handlers.erase(ident);
  dout(0) << "Unplugged from pipeline: " << ident << dendl;
  return 0;
}

int RGWAuthPipeline::authorize(RGWRados *store, struct req_state *s) {
  int ret;
  for (vector<string>::iterator li = pipeline.begin(); li != pipeline.end(); ++li) {
    if (!handlers[*li]) {
      dout(10) << "Trying to authorize against next in pipeline: " << *li << ", handler not found!" << dendl;
      continue;
    }
    dout(20) << "Trying to authorize against next in pipeline: " << *li << "" << dendl;
    /* stop authorization on explicit allow */
    if ((ret=handlers[*li]->authorize(store, s))==0)
      return 0;
    /* stop authorization on explicit -EPERM */
    if (ret==-EPERM)
      return -EPERM;

  }
  /* none of the auth handlers in the pipeline could handle this authorization request */
  return -EIO;
}

RGWAuthPipeline* RGWAuthManager::find_pipeline(RGWRESTMgr* mgr) {
  RGWAuthPipeline * pipeline;
  map<RGWRESTMgr*, RGWAuthPipeline *>::iterator it;

  if ((it=pipelines.find(mgr))==pipelines.end()) {
    pipeline = new RGWAuthPipeline(plugin_manager);
    if (mgr->init_auth_pipeline(pipeline) < 0) {
        delete pipeline;
        return NULL;
    }
    pipelines[mgr] = pipeline;
    dout(0) << "New pipeline created (number of pipelines: " << pipelines.size() << ")" << dendl;
    plugin_manager->register_plugins(RGW_PLUGIN_TYPE_AUTH, (void *) pipeline);
  }

  return pipelines[mgr];

};
