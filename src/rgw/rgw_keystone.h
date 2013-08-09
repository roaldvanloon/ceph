#ifndef CEPH_RGW_KEYSTONE_H
#define CEPH_RGW_KEYSTONE_H

#include "rgw_common.h"

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

class RGWKeystoneTokenCache {
  CephContext *cct;

  map<string, token_entry> tokens;
  list<string> tokens_lru;

  Mutex lock;

  size_t max;

public:
  RGWKeystoneTokenCache(CephContext *_cct, int _max) : cct(_cct), lock("RGWKeystoneTokenCache"), max(_max) {}

  bool find(const string& token_id, KeystoneToken& token);
  void add(const string& token_id, KeystoneToken& token);
  void invalidate(const string& token_id);
};


#endif
