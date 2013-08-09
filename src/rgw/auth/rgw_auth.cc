#include "rgw_auth.h"

#define dout_subsys ceph_subsys_rgw

RGWAuth::RGWAuth(CephContext *_cct)
  : cct(_cct) {

  list<string> auth_pipes;
  get_str_list(cct->rgw_auth_pipeline, auth_pipes);
  for (list<string>::iterator li = auth_pipes.begin(); li != auth_pipes.end(); ++li) {
    if (strcmp((*li), "rados") == 0) {
      auth_handlers.push_back(new RGWAuth_Rados(cct));
    } else if (strcmp((*li), "keystone") == 0) {
      auth_handlers.push_back(new RGWAuth_Keystone(cct));
    } else {
      ldout(cct, 10) << "(RGWAuth) WARNING: unknown handler in pipeline: " << *li << dendl;
    }
  }

  if (auth_handlers.empty())
    ldout(cct, 10) << "(RGWAuth) WARNING: pipeline is empty, users will never authenticate!" << dendl;

}

RGWAuth::~RGWAuth() {
  ldout(cct, 20) << "(RGWAuth) Shutting down handlers... " << dendl;
  for (list<string>::iterator h = auth_handlers.begin(); h != auth_handlers.end(); ++li) {
    (*h).finalize();
  }
}

int RGWAuth::authorize(RGWRados *store, struct req_state *req_state) {
  int r = -EINVAL;
  for (list<string>::iterator h = auth_handlers.begin(); h != auth_handlers.end(); ++li) {
    r = (*h).do_authorize(store, req_state);

    /* stop on successful authentication or -EPERM (e.g., explicit deny) */
    if (r == 0 || r == -EPERM)
      return r;
  }

  return -EPERM;
}

void RGWAuth::revoke(RGWRados *store, RGWUser *user) {
  for (list<string>::iterator h = auth_handlers.begin(); h != auth_handlers.end(); ++li)
    (*h).do_revoke(store, user);

}
