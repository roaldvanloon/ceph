#include "plugin.h"

START_PLUGIN(example, RGW_PLUGIN_TYPE_AUTH, !RGW_PLUGIN_IS_SINGULAR)
	example.init = example_plugin_load;
	example.exit = example_plugin_unload;
FINISH_PLUGIN(example)


int example_plugin_load(rgw_plugin *plugindef) {
  /*
   * We specified this is a RGW_PLUGIN_TYPE_AUTH plugin (see
   * rgw_plugin_init), so we may assume that our owner is a
   * RGWAuthPipeline
   */

  // RGWAuthPipeline *auth_pipeline = (RGWAuthPipeline *) plugindef->owner;
  // if (auth_pipeline == NULL)
  //   return -EINVAL;

  //auth_pipeline->plug("example");

  return 0;
}

int example_plugin_unload(rgw_plugin *plugindef) {
  // RGWAuthPipeline *auth_pipeline = (RGWAuthPipeline *) plugindef->owner;
  // if (auth_pipeline == NULL)
  //   return -EINVAL;

  // auth_pipeline->unplug("example");

  return 0;
}
