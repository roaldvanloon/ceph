#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "common/ceph_json.h"
#include "rgw_common.h"
#include "rgw_swift.h"
#include "rgw_swift_auth.h"
#include "rgw_user.h"
#include "rgw_http_client.h"

#include "include/str_list.h"

#include "common/ceph_crypto_cms.h"
#include "common/armor.h"

#define dout_subsys ceph_subsys_rgw

//static list<string> roles_list;
//
//class RGWKeystoneTokenCache;
//
//class RGWValidateSwiftToken : public RGWHTTPClient {
//  struct rgw_swift_auth_info *info;
//
//protected:
//  RGWValidateSwiftToken() : RGWHTTPClient(NULL), info(NULL) {}
//public:
//  RGWValidateSwiftToken(CephContext *_cct, struct rgw_swift_auth_info *_info) : RGWHTTPClient(_cct), info(_info) {}
//
//  int receive_header(void *ptr, size_t len);
//  int receive_data(void *ptr, size_t len) {
//    return 0;
//  }
//  int send_data(void *ptr, size_t len) {
//    return 0;
//  }
//
//  friend class RGWKeystoneTokenCache;
//};
//
//int RGWValidateSwiftToken::receive_header(void *ptr, size_t len)
//{
//  char line[len + 1];
//
//  char *s = (char *)ptr, *end = (char *)ptr + len;
//  char *p = line;
//  ldout(cct, 10) << "read_http_header" << dendl;
//
//  while (s != end) {
//    if (*s == '\r') {
//      s++;
//      continue;
//    }
//    if (*s == '\n') {
//      *p = '\0';
//      ldout(cct, 10) << "os_auth:" << line << dendl;
//      // TODO: fill whatever data required here
//      char *l = line;
//      char *tok = strsep(&l, " \t:");
//      if (tok) {
//        while (l && *l == ' ')
//          l++;
//
//        if (strcmp(tok, "HTTP") == 0) {
//          info->status = atoi(l);
//        } else if (strcasecmp(tok, "X-Auth-Groups") == 0) {
//          info->auth_groups = l;
//          char *s = strchr(l, ',');
//          if (s) {
//            *s = '\0';
//            info->user = l;
//          }
//        } else if (strcasecmp(tok, "X-Auth-Ttl") == 0) {
//          info->ttl = atoll(l);
//        }
//      }
//    }
//    if (s != end)
//      *p++ = *s++;
//  }
//  return 0;
//}

//static int open_cms_envelope(CephContext *cct, string& src, string& dst)
//{
//#define BEGIN_CMS "-----BEGIN CMS-----"
//#define END_CMS "-----END CMS-----"
//
//  int start = src.find(BEGIN_CMS);
//  if (start < 0) {
//    ldout(cct, 0) << "failed to find " << BEGIN_CMS << " in response" << dendl;
//    return -EINVAL;
//  }
//  start += sizeof(BEGIN_CMS) - 1;
//
//  int end = src.find(END_CMS);
//  if (end < 0) {
//    ldout(cct, 0) << "failed to find " << END_CMS << " in response" << dendl;
//    return -EINVAL;
//  }
//
//  string s = src.substr(start, end - start);
//
//  int pos = 0;
//
//  do {
//    int next = s.find('\n', pos);
//    if (next < 0) {
//      dst.append(s.substr(pos));
//      break;
//    } else {
//      dst.append(s.substr(pos, next - pos));
//    }
//    pos = next + 1;
//  } while (pos < (int)s.size());
//
//  return 0;
//}
//
//static int decode_b64_cms(CephContext *cct, const string& signed_b64, bufferlist& bl)
//{
//  bufferptr signed_ber(signed_b64.size() * 2);
//  char *dest = signed_ber.c_str();
//  const char *src = signed_b64.c_str();
//  size_t len = signed_b64.size();
//  char buf[len + 1];
//  buf[len] = '\0';
//  for (size_t i = 0; i < len; i++, src++) {
//    if (*src != '-')
//      buf[i] = *src;
//    else
//      buf[i] = '/';
//  }
//  int ret = ceph_unarmor(dest, dest + signed_ber.length(), buf, buf + signed_b64.size());
//  if (ret < 0) {
//    ldout(cct, 0) << "ceph_unarmor() failed, ret=" << ret << dendl;
//    return ret;
//  }
//
//  bufferlist signed_ber_bl;
//  signed_ber_bl.append(signed_ber);
//
//  ret = ceph_decode_cms(cct, signed_ber_bl, bl);
//  if (ret < 0) {
//    ldout(cct, 0) << "ceph_decode_cms returned " << ret << dendl;
//    return ret;
//  }
//
//  return 0;
//}

//#define PKI_ANS1_PREFIX "MII"

//static bool is_pki_token(const string& token)
//{
//  return token.compare(0, sizeof(PKI_ANS1_PREFIX) - 1, PKI_ANS1_PREFIX) == 0;
//}
//
//static void get_token_id(const string& token, string& token_id)
//{
//  if (!is_pki_token(token)) {
//    token_id = token;
//    return;
//  }
//
//  unsigned char m[CEPH_CRYPTO_MD5_DIGESTSIZE];
//
//  MD5 hash;
//  hash.Update((const byte *)token.c_str(), token.size());
//  hash.Final(m);
//
//
//  char calc_md5[CEPH_CRYPTO_MD5_DIGESTSIZE * 2 + 1];
//  buf_to_hex(m, CEPH_CRYPTO_MD5_DIGESTSIZE, calc_md5);
//  token_id = calc_md5;
//}
//
//static bool decode_pki_token(CephContext *cct, const string& token, bufferlist& bl)
//{
//  if (!is_pki_token(token))
//    return false;
//
//  int ret = decode_b64_cms(cct, token, bl);
//  if (ret < 0)
//    return false;
//
//  ldout(cct, 20) << "successfully decoded pki token" << dendl;
//
//  return true;
//}

//int RGWSwift::validate_keystone_token(RGWRados *store, const string& token, struct rgw_swift_auth_info *info,
//				      RGWUserInfo& rgw_user)
//{
//  KeystoneToken t;
//
//  string token_id;
//  get_token_id(token, token_id);
//
//  ldout(cct, 20) << "token_id=" << token_id << dendl;
//
//  /* check cache first */
//  if (keystone_token_cache->find(token_id, t)) {
//    rgw_set_keystone_token_auth_info(t, info);
//
//    ldout(cct, 20) << "cached token.tenant_id=" << t.tenant_id << dendl;
//
//    int ret = update_user_info(store, info, rgw_user);
//    if (ret < 0)
//      return ret;
//
//    return 0;
//  }
//
//  bufferlist bl;
//
//  /* check if that's a self signed token that we can decode */
//  if (!decode_pki_token(cct, token, bl)) {
//
//    /* can't decode, just go to the keystone server for validation */
//
//    RGWValidateKeystoneToken validate(cct, &bl);
//
//    string url = g_conf->rgw_keystone_url;
//    if (url.empty()) {
//      ldout(cct, 0) << "ERROR: keystone url is not configured" << dendl;
//      return -EINVAL;
//    }
//    if (url[url.size() - 1] != '/')
//      url.append("/");
//    url.append("v2.0/tokens/");
//    url.append(token);
//
//    validate.append_header("X-Auth-Token", g_conf->rgw_keystone_admin_token);
//
//    int ret = validate.process(url.c_str());
//    if (ret < 0)
//      return ret;
//  }
//
//  bl.append((char)0); // NULL terminate for debug output
//
//  ldout(cct, 20) << "received response: " << bl.c_str() << dendl;
//
//  int ret = parse_keystone_token_response(token, bl, info, t);
//  if (ret < 0)
//    return ret;
//
//  ret = update_user_info(store, info, rgw_user);
//  if (ret < 0)
//    return ret;
//
//  return 0;
//}


//bool RGWSwift::verify_swift_token(RGWRados *store, req_state *s)
//{
//  if (!s->os_auth_token)
//    return false;
//
//  if (strncmp(s->os_auth_token, "AUTH_rgwtk", 10) == 0) {
//    int ret = rgw_swift_verify_signed_token(s->cct, store, s->os_auth_token, s->user);
//    if (ret < 0)
//      return false;
//
//    return  true;
//  }
//
//  struct rgw_swift_auth_info info;
//
//  info.status = 401; // start with access denied, validate_token might change that
//
//  int ret;
//
//  if (supports_keystone()) {
//    ret = validate_keystone_token(store, s->os_auth_token, &info, s->user);
//    return (ret >= 0);
//  }
//
//  ret = validate_token(s->os_auth_token, &info);
//  if (ret < 0)
//    return false;
//
//  if (info.user.empty()) {
//    ldout(cct, 5) << "swift auth didn't authorize a user" << dendl;
//    return false;
//  }
//
//  s->swift_user = info.user;
//  s->swift_groups = info.auth_groups;
//
//  string swift_user = s->swift_user;
//
//  ldout(cct, 10) << "swift user=" << s->swift_user << dendl;
//
//  if (rgw_get_user_info_by_swift(store, swift_user, s->user) < 0) {
//    ldout(cct, 0) << "NOTICE: couldn't map swift user" << dendl;
//    return false;
//  }
//
//  ldout(cct, 10) << "user_id=" << s->user.user_id << dendl;
//
//  return true;
//}

//void RGWSwift::init()
//{
//  get_str_list(cct->_conf->rgw_keystone_accepted_roles, roles_list);
//  if (supports_keystone())
//      init_keystone();
//}


//void RGWSwift::init_keystone()
//{
//  keystone_token_cache = new RGWKeystoneTokenCache(cct, cct->_conf->rgw_keystone_token_cache_size);
//
//  keystone_revoke_thread = new KeystoneRevokeThread(cct, this);
//  keystone_revoke_thread->create();
//}


//void RGWSwift::finalize()
//{
//  if (supports_keystone())
//    finalize_keystone();
//}
//
//void RGWSwift::finalize_keystone()
//{
//  delete keystone_token_cache;
//  keystone_token_cache = NULL;
//
//  down_flag.set(1);
//  if (keystone_revoke_thread) {
//    keystone_revoke_thread->stop();
//    keystone_revoke_thread->join();
//  }
//  delete keystone_revoke_thread;
//  keystone_revoke_thread = NULL;
//}
//
//RGWSwift *rgw_swift = NULL;
//
//void swift_init(CephContext *cct)
//{
//  rgw_swift = new RGWSwift(cct);
//}
//
//void swift_finalize()
//{
//  delete rgw_swift;
//}
//
//bool RGWSwift::going_down()
//{
//  return (down_flag.read() != 0);
//}
//
//void *RGWSwift::KeystoneRevokeThread::entry() {
//  do {
//    dout(2) << "keystone revoke thread: start" << dendl;
//    int r = swift->check_revoked();
//    if (r < 0) {
//      dout(0) << "ERROR: keystone revocation processing returned error r=" << r << dendl;
//    }
//
//    if (swift->going_down())
//      break;
//
//    lock.Lock();
//    cond.WaitInterval(cct, lock, utime_t(cct->_conf->rgw_keystone_revocation_interval, 0));
//    lock.Unlock();
//  } while (!swift->going_down());
//
//  return NULL;
//}
//
//void RGWSwift::KeystoneRevokeThread::stop()
//{
//  Mutex::Locker l(lock);
//  cond.Signal();
//}

