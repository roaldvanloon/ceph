#ifndef CEPH_RGW_AUTH_AUTH_H
#define CEPH_RGW_AUTH_AUTH_H

#include <errno>

#include "common/errno.h"
#include "rgw/rgw_common.h"
#include "include/types.h"
#include "include/str_list.h"


class RGWAuth {
private:
  CephContext *cct;
  list<RGWAuth*> auth_handlers;

public:
  RGWAuth(CephContext *_cct);
  virtual ~RGWAuth();

  virtual int init() { return 0; }
  virtual void finalize();

  int authorize(RGWRados *store, struct req_state *req_state);
  void revoke(RGWRados *store, RGWUser *user);

private:
  virtual int do_authorize(RGWRados *store, struct req_state *req_state) { return -EINVAL; };
  virtual void do_revoke(RGWRados *store, RGWUser *user) { return 0; };

};

#endif
