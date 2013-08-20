#include <dlfcn.h>

#include "include/str_list.h"

#include "rgw_plugin.h"

#define dout_subsys ceph_subsys_rgw

map<string, plugin_initfunc> & static_plugins() {
    static map<string, plugin_initfunc> static_plugins;
    return static_plugins;
}

int RGWPluginManager::load_plugins() {
  list<string> plugins;
  void *h;
  string libname;
  rgw_plugin* (*init_func)();
  char* err;

  get_str_list(g_conf->rgw_load_plugins, plugins);

  /* dynamic load libraries */
  for (list<string>::iterator li = plugins.begin(); li != plugins.end(); ++li) {
    if (plugin_map.count(*li)) {
      dout(0) << "WARNING: unable to load plugin " << *li << ": plugin already loaded" << dendl;
      continue;
    }

    for (map<string, plugin_initfunc>::iterator mi = static_plugins().begin(); mi != static_plugins().end(); ++mi) {
      dout(20) << "static_plugins contains: " << mi->first << dendl;
    }

    /* check if this is a statically linked plugin */
    if (static_plugins().count(*li)) {
      init_func = static_plugins()[*li];
    } else {
      /* try to dynamically load it */
      libname = string("librgw_") + *li + string(".so");
      h = dlopen(libname.c_str(), RTLD_LAZY);
      if (!h) {
        dout(0) << "WARNING: unable to load plugin " << *li << ": " << dlerror() << dendl;
        continue;
      }
      /* lookup init func in plugin  */
      *(void **) (&init_func) = dlsym(h, "__rgw_plugin_init");
      if ((err=dlerror()) != NULL)  {
        dout(0) << "WARNING: unable to initialize plugin " << *li << ": " << err << dendl;
        continue;
      }
    }

    /* run init func */
    rgw_plugin *p = (*init_func)();
    if (p==NULL) {
      dout(0) << "WARNING: unable to initialize plugin " << *li << ": plugin init failed" << dendl;
      continue;
    }

    /* add it to the map of known plugins, attach ourself as plugin_manager */
    p->plugin_manager = this;
    p->context = cct;
    plugin_map[*li] = list<rgw_plugin* >();
    plugin_map[*li].push_back(p);

    dout(5) << "Plugin loaded: " << *li << dendl;
  }

  /* clear errors */
  dlerror();

  return plugin_map.size();
}

int RGWPluginManager::link_plugin(const string& name, void *owner) {
  dout(0) << "Requested to link plugin with name <" << name << "> to new owner" << dendl;

  map<string, list<rgw_plugin*> >::iterator it = plugin_map.find(name);
  if (it==plugin_map.end()) {
    dout(0) << "Linking plugin: " << name << "... FAILED (plugin with this name does not exist)" << dendl;
    return -ENOENT; // plugin type with this name does not exists
  }

  int load_ret;
  list<rgw_plugin* > plugindefs = it->second;
  if (!plugindefs.size())
    return -EFAULT; // this shouldn't happen, the plugin map is correct!

  rgw_plugin* plugindef;
  if (plugindefs.front()->owner==NULL) {
    plugindef = plugindefs.front();
  } else {
    if (plugindefs.front()->is_singular) {
      dout(0) << "Linking plugin: " << name << "... FAILED (plugin is a singleton and already has an owner)" << dendl;
      return -EEXIST;
    }

    /* we're allowed to duplicate this plugindef */
    plugindef = (rgw_plugin *) malloc(sizeof(rgw_plugin));
    memcpy(plugindef, plugindefs.front(), sizeof *plugindef);
  }

  plugindef->owner = owner;
  if ((load_ret = plugindef->init(plugindef)) != 0) {
    dout(0) << "Linking plugin: " << name << "... FAILED (" << load_ret << ")" << dendl;
    return load_ret;
  }

  dout(0) << "Linking plugin: " << name << "... OK" << dendl;
  return 0;
}

int RGWPluginManager::unlink_plugin(const string& name, void *owner) {
  dout(0) << "Requested to unlink plugin with name <" << name << "> from owner" << dendl;

  map<string, list<rgw_plugin*> >::iterator it = plugin_map.find(name);
  if (it==plugin_map.end())
    return -ENOENT; // plugin type with this name does not exists

  int unload_ret = -ENOENT;
  list<rgw_plugin* > plugindefs = it->second;
  for (list<rgw_plugin* >::iterator li = plugindefs.begin(); li != plugindefs.end(); ++li) {
    if ((*li)->owner == owner) {
      if ((unload_ret = (*li)->exit(*li)) != 0) {
        dout(0) << "Unlinking plugin: " << name << "... FAILED (" << unload_ret << ")" << dendl;
        return unload_ret;
      }
    }
  }

  if (unload_ret == -ENOENT) {
    dout(0) << "Unlinking plugin: " << name << "... FAILED (could not find plugin)" << dendl;
    return -ENOENT;
  }

  dout(0) << "Unlinking plugin: " << name << "... OK" << dendl;
  return 0;
}

int RGWPluginManager::register_plugins(uint32_t type, void *owner) {
  int err;
  for (map<string, list<rgw_plugin* > >::iterator li = plugin_map.begin(); li != plugin_map.end(); ++li) {
    if (!li->second.size())
      continue; // list<T> in map is corrupt, skip this one
    if (li->second.front()->type == type) {
      if ((err=link_plugin(li->first, owner)) < 0) {
        dout(0) << "WARNING: plugin " << li->first << " returned error (" << err << ") while linking" << dendl;
        return err;
      }
    }
  }
  return 0;
}

int RGWPluginManager::unregister_plugins(uint32_t type, void *owner) {
  int err;
  for (map<string, list<rgw_plugin* > >::iterator li = plugin_map.begin(); li != plugin_map.end(); ++li) {
    if (!li->second.size())
      continue; // list<T> in map is corrupt, skip this one
    if (li->second.front()->type == type) {
      if ((err=unlink_plugin(li->first, owner)) < 0) {
        dout(0) << "WARNING: plugin " << li->first << " returned error (" << err << ") while unlinking" << dendl;
        return err;
      }
    }
  }
  return 0;
}
