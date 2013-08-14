#ifndef CEPH_RGW_PLUGIN_H
#define CEPH_RGW_PLUGIN_H

#include <stdint.h>

#define RGW_PLUGIN_TYPE_API  1

typedef struct rgw_plugin_t {
  uint32_t type;
  int (* loader)(void *);
  int (* unloader)(void *);
  uint32_t version_hi;
  uint32_t version_lo;
} rgw_plugin;

#endif /* CEPH_RGW_PLUGIN_H */
