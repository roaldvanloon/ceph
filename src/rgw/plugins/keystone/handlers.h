#ifndef CEPH_RGW_PLUGIN_KEYSTONE_HANDLERS_H
#define CEPH_RGW_PLUGIN_KEYSTONE_HANDLERS_H

#include "rgw/rgw_auth.h"
#include "rgw/rgw_rados.h"
#include "rgw/rgw_common.h"

#include "cache.h"

namespace rgw { namespace plugins { namespace keystone {

/*
 * This checks if the token supplied is cached and valid.
 * If the token is unknown, it will fall through. If the token
 * is expired, it will exit with -EPERM.
 * You can use it in the pipeline before any of the requests below,
 * e.g. rgw_swift_auth_pipeline = "keystone:check_cache keystone:request_token"
 */
class TokenCacheValidator : public RGWAuth {
public:
  TokenCacheValidator(TokenCache *_cache) : RGWAuth(), cache(_cache) {}
  virtual ~TokenCacheValidator() {}
  virtual int authorize(RGWRados *store, struct req_state *state);
private:
  TokenCache *cache;
};

/*
 * This requests a new token from Keystone based on username + password
 * headers (v1.0 api).
 * You can use it as a Keystone proxy for Swift authentication
 */
class V1TokenRequest : public RGWAuth {
public:
  V1TokenRequest(TokenCache *_cache) : RGWAuth(), cache(_cache) {}
  virtual ~V1TokenRequest() {}
  virtual int authorize(RGWRados *store, struct req_state *state);
private:
  TokenCache *cache;
};

/*
 * This requests a new token from Keystone based on S3 credentials
 * (e.g. access key, token, and signature)
 * You can use it to authenticate against S3/EC2 credentials in Keystone
 */
class S3TokenRequest : public RGWAuth {
public:
  S3TokenRequest(TokenCache *_cache) : RGWAuth(), cache(_cache) {}
  virtual ~S3TokenRequest() {}
  virtual int authorize(RGWRados *store, struct req_state *state);
private:
  TokenCache *cache;
};

}}}

#endif /* CEPH_RGW_PLUGIN_KEYSTONE_HANDLERS_H */
