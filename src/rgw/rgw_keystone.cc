#include <errno.h>

#include "common/errno.h"
#include "common/ceph_json.h"
#include "include/types.h"
#include "include/str_list.h"

#include "rgw_common.h"
#include "rgw_keystone.h"

#define dout_subsys ceph_subsys_rgw

int KeystoneToken::parse(CephContext *cct, bufferlist& bl)
{
  JSONParser parser;

  if (!parser.parse(bl.c_str(), bl.length())) {
    ldout(cct, 0) << "malformed json" << dendl;
    return -EINVAL;
  }

  JSONObjIter iter = parser.find_first("access");
  if (iter.end()) {
    ldout(cct, 0) << "token response is missing access section" << dendl;
    return -EINVAL;
  }

  JSONObj *access_obj = *iter;
  JSONObj *user = access_obj->find_obj("user");
  if (!user) {
    ldout(cct, 0) << "token response is missing user section" << dendl;
    return -EINVAL;
  }

  if (!user->get_data("username", &user_name)) {
    ldout(cct, 0) << "token response is missing user username field" << dendl;
    return -EINVAL;
  }

  JSONObj *roles_obj = user->find_obj("roles");
  if (!roles_obj) {
    ldout(cct, 0) << "token response is missing roles section, or section empty" << dendl;
    return -EINVAL;
  }

  JSONObjIter riter = roles_obj->find_first();
  if (riter.end()) {
    ldout(cct, 0) << "token response has an empty roles list" << dendl;
    return -EINVAL;
  }

  for (; !riter.end(); ++riter) {
    JSONObj *role_obj = *riter;
    if (!role_obj) {
      ldout(cct, 0) << "ERROR: role object is NULL" << dendl;
      return -EINVAL;
    }

    JSONObj *role_name = role_obj->find_obj("name");
    if (!role_name) {
      ldout(cct, 0) << "token response is missing role name section" << dendl;
      return -EINVAL;
    }
    string role = role_name->get_data();
    roles[role] = true;
  }

  JSONObj *token = access_obj->find_obj("token");
  if (!token) {
    ldout(cct, 0) << "missing token section in response" << dendl;
    return -EINVAL;
  }

  string expires;

  if (!token->get_data("expires", &expires)) {
    ldout(cct, 0) << "token response is missing expiration field" << dendl;
    return -EINVAL;
  }

  struct tm t;
  if (!parse_iso8601(expires.c_str(), &t)) {
    ldout(cct, 0) << "failed to parse token expiration (" << expires << ")" << dendl;
    return -EINVAL;
  }

  expiration = timegm(&t);

  JSONObj *tenant = token->find_obj("tenant");
  if (!tenant) {
    ldout(cct, 0) << "token response is missing tenant section" << dendl;
    return -EINVAL;
  }

  if (!tenant->get_data("id", &tenant_id)) {
    ldout(cct, 0) << "tenant is missing id field" << dendl;
    return -EINVAL;
  }


  if (!tenant->get_data("name", &tenant_name)) {
    ldout(cct, 0) << "tenant is missing name field" << dendl;
    return -EINVAL;
  }

  return 0;
}

bool RGWKeystoneTokenCache::find(const string& token_id, KeystoneToken& token)
{
  lock.Lock();
  map<string, token_entry>::iterator iter = tokens.find(token_id);
  if (iter == tokens.end()) {
    lock.Unlock();
    if (perfcounter) perfcounter->inc(l_rgw_keystone_token_cache_miss);
    return false;
  }

  token_entry& entry = iter->second;
  tokens_lru.erase(entry.lru_iter);

  if (entry.token.expired()) {
    tokens.erase(iter);
    lock.Unlock();
    if (perfcounter) perfcounter->inc(l_rgw_keystone_token_cache_hit);
    return false;
  }
  token = entry.token;

  tokens_lru.push_front(token_id);
  entry.lru_iter = tokens_lru.begin();

  lock.Unlock();
  if (perfcounter) perfcounter->inc(l_rgw_keystone_token_cache_hit);

  return true;
}

void RGWKeystoneTokenCache::add(const string& token_id, KeystoneToken& token)
{
  lock.Lock();
  map<string, token_entry>::iterator iter = tokens.find(token_id);
  if (iter != tokens.end()) {
    token_entry& e = iter->second;
    tokens_lru.erase(e.lru_iter);
  }

  tokens_lru.push_front(token_id);
  token_entry& entry = tokens[token_id];
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

void RGWKeystoneTokenCache::invalidate(const string& token_id)
{
  Mutex::Locker l(lock);
  map<string, token_entry>::iterator iter = tokens.find(token_id);
  if (iter == tokens.end())
    return;

  ldout(cct, 20) << "invalidating revoked token id=" << token_id << dendl;
  token_entry& e = iter->second;
  tokens_lru.erase(e.lru_iter);
  tokens.erase(iter);
}
