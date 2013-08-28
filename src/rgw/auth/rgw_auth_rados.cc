#include <errno.h>

#include "common/errno.h"
#include "common/ceph_json.h"
#include "include/types.h"
#include "include/str_list.h"
#include "rgw/rgw_common.h"

#include "rgw_auth_rados.h"

#define dout_subsys ceph_subsys_rgw


int RGWAuth_Rados::init() {

  return 0;
}

void RGWAuth_Rados::finalize() {
  ldout(cct, 20) << "(RGWAuth:Rados) Going down... " << dendl;



  ldout(cct, 20) << "(RGWAuth:Rados) Done. " << dendl;
}

int RGWAuth_Rados::do_authorize(RGWRados *store, struct req_state *req_state) {

  return -EPERM;
}

void RGWAuth_Rados::do_revoke(RGWRados *store, RGWUser *user) {

}
