#include <errno.h>

#include "common/errno.h"
#include "common/ceph_json.h"
#include "include/types.h"
#include "include/str_list.h"
#include "rgw/rgw_common.h"

#define dout_subsys ceph_subsys_rgw

static RGWKeystoneTokenCache *keystone_token_cache = NULL;

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

bool KeystoneTokenCache::find(const string& token_id, KeystoneToken& token)
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

void KeystoneTokenCache::add(const string& token_id, KeystoneToken& token)
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

void KeystoneTokenCache::invalidate(const string& token_id)
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


static int open_cms_envelope(CephContext *cct, string& src, string& dst)
{
#define BEGIN_CMS "-----BEGIN CMS-----"
#define END_CMS "-----END CMS-----"

  int start = src.find(BEGIN_CMS);
  if (start < 0) {
    ldout(cct, 0) << "failed to find " << BEGIN_CMS << " in response" << dendl;
    return -EINVAL;
  }
  start += sizeof(BEGIN_CMS) - 1;

  int end = src.find(END_CMS);
  if (end < 0) {
    ldout(cct, 0) << "failed to find " << END_CMS << " in response" << dendl;
    return -EINVAL;
  }

  string s = src.substr(start, end - start);

  int pos = 0;

  do {
    int next = s.find('\n', pos);
    if (next < 0) {
      dst.append(s.substr(pos));
      break;
    } else {
      dst.append(s.substr(pos, next - pos));
    }
    pos = next + 1;
  } while (pos < (int)s.size());

  return 0;
}

static int decode_b64_cms(CephContext *cct, const string& signed_b64, bufferlist& bl)
{
  bufferptr signed_ber(signed_b64.size() * 2);
  char *dest = signed_ber.c_str();
  const char *src = signed_b64.c_str();
  size_t len = signed_b64.size();
  char buf[len + 1];
  buf[len] = '\0';
  for (size_t i = 0; i < len; i++, src++) {
    if (*src != '-')
      buf[i] = *src;
    else
      buf[i] = '/';
  }
  int ret = ceph_unarmor(dest, dest + signed_ber.length(), buf, buf + signed_b64.size());
  if (ret < 0) {
    ldout(cct, 0) << "ceph_unarmor() failed, ret=" << ret << dendl;
    return ret;
  }

  bufferlist signed_ber_bl;
  signed_ber_bl.append(signed_ber);

  ret = ceph_decode_cms(cct, signed_ber_bl, bl);
  if (ret < 0) {
    ldout(cct, 0) << "ceph_decode_cms returned " << ret << dendl;
    return ret;
  }

  return 0;
}

int KeystoneRevokeThread::check_revoked() {
  bufferlist bl;
  GetRevokedTokens req(cct, &bl);

  string url = cct->_conf->rgw_keystone_url;
  if (url.empty()) {
    ldout(cct, 0) << "ERROR: keystone url is not configured" << dendl;
    return -EINVAL;
  }
  if (url[url.size() - 1] != '/')
    url.append("/");
  url.append("v2.0/tokens/revoked");

  req.append_header("X-Auth-Token", cct->_conf->rgw_keystone_admin_token);

  int ret = req.process(url.c_str());
  if (ret < 0)
    return ret;

  bl.append((char)0); // NULL terminate for debug output

  ldout(cct, 10) << "request returned " << bl.c_str() << dendl;

  JSONParser parser;

  if (!parser.parse(bl.c_str(), bl.length())) {
    ldout(cct, 0) << "malformed json" << dendl;
    return -EINVAL;
  }

  JSONObjIter iter = parser.find_first("signed");
  if (iter.end()) {
    ldout(cct, 0) << "revoked tokens response is missing signed section" << dendl;
    return -EINVAL;
  }

  JSONObj *signed_obj = *iter;

  string signed_str = signed_obj->get_data();

  ldout(cct, 10) << "signed=" << signed_str << dendl;

  string signed_b64;
  ret = open_cms_envelope(cct, signed_str, signed_b64);
  if (ret < 0)
    return ret;

  ldout(cct, 10) << "content=" << signed_b64 << dendl;

  bufferlist json;
  ret = decode_b64_cms(cct, signed_b64, json);
  if (ret < 0) {
    return ret;
  }

  ldout(cct, 10) << "ceph_decode_cms: decoded: " << json.c_str() << dendl;

  JSONParser list_parser;
  if (!list_parser.parse(json.c_str(), json.length())) {
    ldout(cct, 0) << "malformed json" << dendl;
    return -EINVAL;
  }

  JSONObjIter revoked_iter = list_parser.find_first("revoked");
  if (revoked_iter.end()) {
    ldout(cct, 0) << "no revoked section in json" << dendl;
    return -EINVAL;
  }

  JSONObj *revoked_obj = *revoked_iter;

  JSONObjIter tokens_iter = revoked_obj->find_first();
  for (; !tokens_iter.end(); ++tokens_iter) {
    JSONObj *o = *tokens_iter;

    JSONObj *token = o->find_obj("id");
    if (!token) {
      ldout(cct, 0) << "bad token in array, missing id" << dendl;
      continue;
    }

    string token_id = token->get_data();
    auth_handler->token_cache->invalidate(token_id);
  }

  return 0;
}

void *KeystoneRevokeThread::entry() {
  do {
    dout(2) << "Keystone revoke thread start" << dendl;
    int r = check_revoked();
    if (r < 0) {
      dout(0) << "ERROR: keystone revocation processing returned error r=" << r << dendl;
    }

    if (auth_handler->going_down())
      break;

    lock.Lock();
    cond.WaitInterval(cct, lock, utime_t(cct->_conf->rgw_keystone_revocation_interval, 0));
    lock.Unlock();
  } while (!auth_handler->going_down());

  return NULL;
}

void KeystoneRevokeThread::stop()
{
  Mutex::Locker l(lock);
  cond.Signal();
}

int RGWAuth_Keystone::init() {
  token_cache = new KeystoneTokenCache(cct, cct->_conf->rgw_keystone_token_cache_size);
  revoke_thread = new KeystoneRevokeThread(cct, this);
  revoke_thread->create();
  return 0;
}

void RGWAuth_Keystone::finalize() {
  ldout(cct, 20) << "(RGWAuth:Keystone) Going down... " << dendl;

  delete token_cache;
  token_cache = NULL;

  down_flag.set(1);
  if (revoke_thread) {
    revoke_thread->stop();
    revoke_thread->join();
  }
  delete revoke_thread;
  revoke_thread = NULL;

  ldout(cct, 20) << "(RGWAuth:Keystone) Done. " << dendl;
}

int RGWAuth_Keystone::do_authorize(RGWRados *store, struct req_state *req_state) {

  return -EPERM;
}

void RGWAuth_Keystone::do_revoke(RGWRados *store, RGWUser *user) {

}
