#include "rgw_api_gs.h"

extern "C" int gs_api_loader(void *p) {
  RGWREST* rest = (RGWREST *) p;
  RGWRESTMgr *mgr = new rgw::api::gs::RESTMgr;
  mgr->set_logging(true);
  rest->register_resource(g_conf->rgw_gs_url_prefix, mgr);
  return 0;
}

extern "C" rgw_plugin* rgw_plugin_init() {
  rgw_plugin *plugindef;
  plugindef = (rgw_plugin *) malloc(sizeof(rgw_plugin));
  plugindef->type = RGW_PLUGIN_TYPE_API;
  plugindef->loader = gs_api_loader;
  plugindef->version_hi = 1;
  plugindef->version_lo = 0;
  return plugindef;
}

extern "C" void rgw_plugin_exit() {

}
