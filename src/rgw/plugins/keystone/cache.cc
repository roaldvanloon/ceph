#include "rgw/rgw_common.h"

#include "httpclient.h"
#include "token.h"
#include "cache.h"

#define dout_subsys ceph_subsys_rgw
#undef dout_prefix
#define dout_prefix *_dout << "(rgw:plugin:keystone) "

namespace rgw { namespace plugins { namespace keystone {

TokenCache::TokenCache(CephContext *_cct, int _max)
    : cct(_cct), lock("RGW::Plugins::Keystone::TokenCache"),
      max(_max), revoke_thread(NULL) {

  revoke_thread = new TokenRevokeThread(cct, this);
  revoke_thread->create();
}

TokenCache::~TokenCache() {
  down_flag.set(1);
  if (revoke_thread) {
    revoke_thread->stop();
    revoke_thread->join();
  }
  delete revoke_thread;
  revoke_thread = NULL;
}

void *TokenCache::TokenRevokeThread::entry() {
  do {
    cache->check_revoked();

    if (cache->going_down())
      break;

    lock.Lock();
    cond.WaitInterval(cct, lock, utime_t(cct->_conf->rgw_keystone_revocation_interval, 0));
    lock.Unlock();
  } while (!cache->going_down());

  return NULL;
}

void TokenCache::TokenRevokeThread::stop()
{
  Mutex::Locker l(lock);
  cond.Signal();
}

string TokenCache::get_cache_key(KeystoneToken *token) {
  if (token->token.id.compare(0, sizeof(PKI_ANS1_PREFIX) - 1, PKI_ANS1_PREFIX)) {
    return token->token.id;
  }

  unsigned char m[CEPH_CRYPTO_MD5_DIGESTSIZE];

  MD5 hash;
  hash.Update((const byte *)token->token.id.c_str(), token->token.id.size());
  hash.Final(m);

  char calc_md5[CEPH_CRYPTO_MD5_DIGESTSIZE * 2 + 1];
  buf_to_hex(m, CEPH_CRYPTO_MD5_DIGESTSIZE, calc_md5);

  return string(calc_md5);
}

bool TokenCache::find(const string& cache_key, KeystoneToken *token) {
  lock.Lock();
  map<string, cache_entry>::iterator iter = tokens.find(cache_key);
  if (iter == tokens.end()) {
    lock.Unlock();
    if (perfcounter) perfcounter->inc(l_rgw_keystone_token_cache_miss);
    return false;
  }

  cache_entry& entry = iter->second;
  tokens_lru.erase(entry.lru_iter);

  if (entry.token.expired()) {
    tokens.erase(iter);
    lock.Unlock();
    if (perfcounter) perfcounter->inc(l_rgw_keystone_token_cache_hit);
    return false;
  }
  token = &(entry.token);

  tokens_lru.push_front(cache_key);
  entry.lru_iter = tokens_lru.begin();

  lock.Unlock();
  if (perfcounter) perfcounter->inc(l_rgw_keystone_token_cache_hit);

  return true;
}

bool TokenCache::find(KeystoneToken *token) {
  return find(get_cache_key(token), token);
}

void TokenCache::add(KeystoneToken& token)
{
  lock.Lock();
  string cache_key = get_cache_key(&token);
  map<string, cache_entry>::iterator iter = tokens.find(cache_key);
  if (iter != tokens.end()) {
    cache_entry& e = iter->second;
    tokens_lru.erase(e.lru_iter);
  }

  tokens_lru.push_front(cache_key);
  cache_entry& entry = tokens[cache_key];
  entry.token = token;
  entry.lru_iter = tokens_lru.begin();

  while (tokens_lru.size() > max) {
    list<string>::reverse_iterator riter = tokens_lru.rbegin();
    iter = tokens.find(*riter);
    assert(iter != tokens.end());
    tokens.erase(iter);
    tokens_lru.pop_back();
  }

  lock.Unlock();
}

void TokenCache::invalidate(const string& cache_key)
{
  Mutex::Locker l(lock);
  map<string, cache_entry>::iterator iter = tokens.find(cache_key);
  if (iter == tokens.end())
    return;

  cache_entry& e = iter->second;
  tokens_lru.erase(e.lru_iter);
  tokens.erase(iter);
}

void TokenCache::check_revoked() {
  bufferlist bl;
  KeystoneRevokedTokensClient keystone_client(cct, "v2.0/tokens/revoked");
  int keystone_result = keystone_client.dispatch();

  if (keystone_result < 0)
    return;

  /* invalidate revoked tokens in cache */
  list<string>::iterator iter;
  for (iter = keystone_client.response.revoked_tokens.begin(); iter != keystone_client.response.revoked_tokens.end(); ++iter) {
    invalidate(*iter);
  }
}

}}}
