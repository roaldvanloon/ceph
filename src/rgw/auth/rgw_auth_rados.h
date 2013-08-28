#ifndef CEPH_RGW_AUTH_KEYSTONE_H
#define CEPH_RGW_AUTH_KEYSTONE_H

#include "rgw/rgw_common.h"

#include "rgw_auth.h"


class RGWAuth_Rados : public RGWAuth {
public:
  RGWAuth_Rados(CephContext *_cct)
    : RGWAuth(_cct) {}

  int init();
  void finalize();

  int do_authorize(RGWRados *store, struct req_state *req_state);
  void do_revoke(RGWRados *store, RGWUser *user);
};

#endif
