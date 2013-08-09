
#ifndef CEPH_RGW_SWIFT_H
#define CEPH_RGW_SWIFT_H

#include "rgw_common.h"
#include "common/Cond.h"

class RGWRados;
class KeystoneToken;

struct rgw_swift_auth_info {
  int status;
  string auth_groups;
  string user;
  string display_name;
  long long ttl;

  rgw_swift_auth_info() : status(0), ttl(0) {}
};

class RGWSwift {
  CephContext *cct;
  RGWAuth *auth_handler;

  int validate_token(const char *token, struct rgw_swift_auth_info *info);
  int validate_keystone_token(RGWRados *store, const string& token, struct rgw_swift_auth_info *info,
			      RGWUserInfo& rgw_user);

  int parse_keystone_token_response(const string& token, bufferlist& bl, struct rgw_swift_auth_info *info,
		                    KeystoneToken& t);
  int update_user_info(RGWRados *store, struct rgw_swift_auth_info *info, RGWUserInfo& user_info);

  void init();
  void finalize();

public:

  RGWSwift(CephContext *_cct) : cct(_cct), auth_handler(NULL) {
    init();
  }
  ~RGWSwift() {
    finalize();
  }

  bool verify_swift_token(RGWRados *store, req_state *s);
};

extern RGWSwift *rgw_swift;
void swift_init(CephContext *cct);
void swift_finalize();

#endif

