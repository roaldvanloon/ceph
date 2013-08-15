#include <cstdarg>

#include "rgw/rgw_auth.h"

#include "handlers.h"
#include "plugin.h"
#include "cache.h"

static rgw::plugins::keystone::TokenCache *tokencache;

extern "C" rgw_plugin* rgw_plugin_init() {
  static rgw_plugin def = { RGW_PLUGIN_TYPE_AUTH, false };
  def.init = keystone_plugin_load;
  def.exit = keystone_plugin_unload;

  rgw_plugin *plugindef = (rgw_plugin *) malloc(sizeof(rgw_plugin));
  if (plugindef == NULL)
    return NULL;

  memcpy(plugindef, &def, sizeof *plugindef);
  return plugindef;
}

int keystone_plugin_load(rgw_plugin *plugindef) {
  RGWAuthPipeline *auth_pipeline = (RGWAuthPipeline *) plugindef->owner;
  if (auth_pipeline == NULL)
    return -EINVAL;

  tokencache = new rgw::plugins::keystone::TokenCache(
      plugindef->context, plugindef->context->_conf->rgw_keystone_token_cache_size);

  auth_pipeline->plug("keystone:check_cache", new rgw::plugins::keystone::TokenCacheValidator(tokencache));
  auth_pipeline->plug("keystone:request_v1token", new rgw::plugins::keystone::V1TokenRequest(tokencache));
  auth_pipeline->plug("keystone:request_s3token", new rgw::plugins::keystone::S3TokenRequest(tokencache));
  return 0;
}

int keystone_plugin_unload(rgw_plugin *plugindef) {
  delete tokencache;
  tokencache = NULL;
  RGWAuthPipeline *auth_pipeline = (RGWAuthPipeline *) plugindef->owner;
  if (auth_pipeline == NULL)
    return -EINVAL;

  auth_pipeline->unplug("keystone:check_cache");
  auth_pipeline->unplug("keystone:request_v1token");
  auth_pipeline->unplug("keystone:request_s3token");
  return 0;
}

