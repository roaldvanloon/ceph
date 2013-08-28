#ifndef CEPH_RGW_AUTH_KEYSTONE_H
#define CEPH_RGW_AUTH_KEYSTONE_H

#include "rgw/rgw_common.h"

#include "rgw_auth.h"

class RGWAuth_Keystone;

class KeystoneToken {
public:
  string tenant_name;
  string tenant_id;
  string user_name;
  time_t expiration;

  map<string, bool> roles;

  KeystoneToken() : expiration(0) {}

  int parse(CephContext *cct, bufferlist& bl);

  bool expired() {
    uint64_t now = ceph_clock_now(NULL).sec();
    return (now < (uint64_t)expiration);
  }
};

struct token_entry {
  KeystoneToken token;
  list<string>::iterator lru_iter;
};

class KeystoneTokenCache {
  CephContext *cct;

  map<string, token_entry> tokens;
  list<string> tokens_lru;

  Mutex lock;

  size_t max;

public:
  KeystoneTokenCache(CephContext *_cct, int _max) : cct(_cct), lock("RGWAuth:Keystone:KeystoneTokenCache"), max(_max) {}

  bool find(const string& token_id, KeystoneToken& token);
  void add(const string& token_id, KeystoneToken& token);
  void invalidate(const string& token_id);

};

class KeystoneRevokeThread : public Thread {
private:
  CephContext *cct;
  RGWAuth_Keystone *auth_handler;
  Mutex lock;
  Cond cond;

  int check_revoked();

public:
  KeystoneRevokeThread(CephContext *_cct, RGWAuth_Keystone *_auth_handler)
    : cct(_cct), auth_handler(_auth_handler), lock("RGWAuth:Keystone:KeystoneRevokeThread") {}
  void *entry();
  void stop();
};

class ValidateKeystoneToken : public RGWHTTPClient {
  bufferlist *bl;
public:
  ValidateKeystoneToken(CephContext *_cct, bufferlist *_bl) : RGWHTTPClient(_cct), bl(_bl) {}

  int read_data(void *ptr, size_t len) {
    bl->append((char *)ptr, len);
    return 0;
  }
};

class GetRevokedTokens : public RGWHTTPClient {
  bufferlist *bl;
public:
  GetRevokedTokens(CephContext *_cct, bufferlist *_bl) : RGWHTTPClient(_cct), bl(_bl) {}

  int read_data(void *ptr, size_t len) {
    bl->append((char *)ptr, len);
    return 0;
  }
};

class RGWAuth_Keystone : public RGWAuth {
public:
  KeystoneTokenCache *token_cache;
  KeystoneRevokeThread *revoke_thread;

private:
  atomic_t down_flag;

public:
  RGWAuth_Keystone(CephContext *_cct)
    : RGWAuth(_cct), token_cache(NULL), revoke_thread(NULL) {}

  int init();
  void finalize();

  int authorize(RGWRados *store, struct req_state *req_state);
  void revoke(RGWRados *store, RGWUser *user);

private:
  bool going_down() { return (down_flag.read() != 0); }
};

#endif
