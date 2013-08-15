#ifndef CEPH_RGW_PLUGIN_KEYSTONE_CACHE_H
#define CEPH_RGW_PLUGIN_KEYSTONE_CACHE_H

#include "include/types.h"
#include "include/str_list.h"
#include "common/Mutex.h"
#include "common/Cond.h"
#include "common/ceph_context.h"
#include "rgw/rgw_http_client.h"

#include "token.h"

#define PKI_ANS1_PREFIX "MII"

namespace rgw { namespace plugins { namespace keystone {

struct cache_entry {
  KeystoneToken token;
  list<string>::iterator lru_iter;
};

class TokenCache {
  CephContext *cct;
  map<string, cache_entry> tokens;
  list<string> tokens_lru;
  Mutex lock;
  size_t max;
  atomic_t down_flag;

  class TokenRevokeThread : public Thread {
    CephContext *cct;
    TokenCache *cache;
    Mutex lock;
    Cond cond;

  public:
    TokenRevokeThread(CephContext *_cct, TokenCache *_cache) : cct(_cct), cache(_cache), lock("RGW::Plugins::Keystone::TokenCache::RevokeThread") {}
    void *entry();
    void stop();
  };

  TokenRevokeThread *revoke_thread;

public:
  TokenCache(CephContext *_cct, int _max);
  ~TokenCache();

  bool find(KeystoneToken *token);
  bool find(const string& cache_key, KeystoneToken *token)

  void add(KeystoneToken& token);
  void invalidate(const string& token_id);

  bool going_down() { return (down_flag.read() != 0); }
  int size() { return tokens.size(); }

protected:
  void check_revoked();
  string get_cache_key(KeystoneToken *token);
};




}}}

#endif /* CEPH_RGW_PLUGIN_KEYSTONE_CACHE_H */
