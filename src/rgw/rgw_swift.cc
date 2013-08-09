#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "common/ceph_json.h"
#include "rgw_common.h"
#include "rgw_swift.h"
#include "rgw_swift_auth.h"
#include "rgw_user.h"
#include "rgw_http_client.h"
#include "rgw_keystone.h"

#include "include/str_list.h"

#include "common/ceph_crypto_cms.h"
#include "common/armor.h"

#define dout_subsys ceph_subsys_rgw

static list<string> roles_list;

class RGWValidateSwiftToken : public RGWHTTPClient {
  struct rgw_swift_auth_info *info;

protected:
  RGWValidateSwiftToken() : RGWHTTPClient(NULL), info(NULL) {}
public:
  RGWValidateSwiftToken(CephContext *_cct, struct rgw_swift_auth_info *_info) : RGWHTTPClient(_cct), info(_info) {}

  int read_header(void *ptr, size_t len);

  friend class RGWKeystoneTokenCache;
};

int RGWValidateSwiftToken::read_header(void *ptr, size_t len)
{
  char line[len + 1];

  char *s = (char *)ptr, *end = (char *)ptr + len;
  char *p = line;
  ldout(cct, 10) << "read_http_header" << dendl;

  while (s != end) {
    if (*s == '\r') {
      s++;
      continue;
    }
    if (*s == '\n') {
      *p = '\0';
      ldout(cct, 10) << "os_auth:" << line << dendl;
      // TODO: fill whatever data required here
      char *l = line;
      char *tok = strsep(&l, " \t:");
      if (tok) {
        while (l && *l == ' ')
          l++;
 
        if (strcmp(tok, "HTTP") == 0) {
          info->status = atoi(l);
        } else if (strcasecmp(tok, "X-Auth-Groups") == 0) {
          info->auth_groups = l;
          char *s = strchr(l, ',');
          if (s) {
            *s = '\0';
            info->user = l;
          }
        } else if (strcasecmp(tok, "X-Auth-Ttl") == 0) {
          info->ttl = atoll(l);
        }
      }
    }
    if (s != end)
      *p++ = *s++;
  }
  return 0;
}

int RGWSwift::validate_token(const char *token, struct rgw_swift_auth_info *info)
{
  if (g_conf->rgw_swift_auth_url.empty())
    return -EINVAL;

  string auth_url = g_conf->rgw_swift_auth_url;
  if (auth_url[auth_url.size() - 1] != '/')
    auth_url.append("/");
  auth_url.append("token");
  char url_buf[auth_url.size() + 1 + strlen(token) + 1];
  sprintf(url_buf, "%s/%s", auth_url.c_str(), token);

  RGWValidateSwiftToken validate(cct, info);

  ldout(cct, 10) << "rgw_swift_validate_token url=" << url_buf << dendl;

  int ret = validate.process(url_buf);
  if (ret < 0)
    return ret;

  return 0;
}




static void rgw_set_keystone_token_auth_info(KeystoneToken& token, struct rgw_swift_auth_info *info)
{
  info->user = token.tenant_id;
  info->display_name = token.tenant_name;
  info->status = 200;
}

int RGWSwift::parse_keystone_token_response(const string& token, bufferlist& bl, struct rgw_swift_auth_info *info, KeystoneToken& t)
{
  int ret = t.parse(cct, bl);
  if (ret < 0)
    return ret;

  bool found = false;
  list<string>::iterator iter;
  for (iter = roles_list.begin(); iter != roles_list.end(); ++iter) {
    const string& role = *iter;
    if (t.roles.find(role) != t.roles.end()) {
      found = true;
      break;
    }
  }

  if (!found) {
    ldout(cct, 0) << "user does not hold a matching role; required roles: " << g_conf->rgw_keystone_accepted_roles << dendl;
    return -EPERM;
  }

  ldout(cct, 0) << "validated token: " << t.tenant_name << ":" << t.user_name << " expires: " << t.expiration << dendl;

  rgw_set_keystone_token_auth_info(t, info);

  return 0;
}

int RGWSwift::update_user_info(RGWRados *store, struct rgw_swift_auth_info *info, RGWUserInfo& user_info)
{
  if (rgw_get_user_info_by_uid(store, info->user, user_info) < 0) {
    ldout(cct, 0) << "NOTICE: couldn't map swift user" << dendl;
    user_info.user_id = info->user;
    user_info.display_name = info->display_name;

    int ret = rgw_store_user_info(store, user_info, NULL, NULL, 0, true);
    if (ret < 0) {
      ldout(cct, 0) << "ERROR: failed to store new user's info: ret=" << ret << dendl;
      return ret;
    }
  }
  return 0;
}

#define PKI_ANS1_PREFIX "MII"

static bool is_pki_token(const string& token)
{
  return token.compare(0, sizeof(PKI_ANS1_PREFIX) - 1, PKI_ANS1_PREFIX) == 0;
}

static void get_token_id(const string& token, string& token_id)
{
  if (!is_pki_token(token)) {
    token_id = token;
    return;
  }

  unsigned char m[CEPH_CRYPTO_MD5_DIGESTSIZE];

  MD5 hash;
  hash.Update((const byte *)token.c_str(), token.size());
  hash.Final(m);


  char calc_md5[CEPH_CRYPTO_MD5_DIGESTSIZE * 2 + 1];
  buf_to_hex(m, CEPH_CRYPTO_MD5_DIGESTSIZE, calc_md5);
  token_id = calc_md5;
}

static bool decode_pki_token(CephContext *cct, const string& token, bufferlist& bl)
{
  if (!is_pki_token(token))
    return false;

  int ret = decode_b64_cms(cct, token, bl);
  if (ret < 0)
    return false;

  ldout(cct, 20) << "successfully decoded pki token" << dendl;

  return true;
}

int RGWSwift::validate_keystone_token(RGWRados *store, const string& token, struct rgw_swift_auth_info *info,
				      RGWUserInfo& rgw_user)
{
  KeystoneToken t;

  string token_id;
  get_token_id(token, token_id);

  ldout(cct, 20) << "token_id=" << token_id << dendl;

  /* check cache first */
  if (keystone_token_cache->find(token_id, t)) {
    rgw_set_keystone_token_auth_info(t, info);

    ldout(cct, 20) << "cached token.tenant_id=" << t.tenant_id << dendl;

    int ret = update_user_info(store, info, rgw_user);
    if (ret < 0)
      return ret;

    return 0;
  }

  bufferlist bl;

  /* check if that's a self signed token that we can decode */
  if (!decode_pki_token(cct, token, bl)) {

    /* can't decode, just go to the keystone server for validation */

    RGWValidateKeystoneToken validate(cct, &bl);

    string url = g_conf->rgw_keystone_url;
    if (url.empty()) {
      ldout(cct, 0) << "ERROR: keystone url is not configured" << dendl;
      return -EINVAL;
    }
    if (url[url.size() - 1] != '/')
      url.append("/");
    url.append("v2.0/tokens/");
    url.append(token);

    validate.append_header("X-Auth-Token", g_conf->rgw_keystone_admin_token);

    int ret = validate.process(url.c_str());
    if (ret < 0)
      return ret;
  }

  bl.append((char)0); // NULL terminate for debug output

  ldout(cct, 20) << "received response: " << bl.c_str() << dendl;

  int ret = parse_keystone_token_response(token, bl, info, t);
  if (ret < 0)
    return ret;

  ret = update_user_info(store, info, rgw_user);
  if (ret < 0)
    return ret;

  return 0;
}


bool RGWSwift::verify_swift_token(RGWRados *store, req_state *s)
{
  if (!s->os_auth_token)
    return false;

  if (strncmp(s->os_auth_token, "AUTH_rgwtk", 10) == 0) {
    int ret = rgw_swift_verify_signed_token(s->cct, store, s->os_auth_token, s->user);
    if (ret < 0)
      return false;

    return  true;
  }

  struct rgw_swift_auth_info info;

  info.status = 401; // start with access denied, validate_token might change that

  int ret;

  if (supports_keystone()) {
    ret = validate_keystone_token(store, s->os_auth_token, &info, s->user);
    return (ret >= 0);
  }

  ret = validate_token(s->os_auth_token, &info);
  if (ret < 0)
    return false;

  if (info.user.empty()) {
    ldout(cct, 5) << "swift auth didn't authorize a user" << dendl;
    return false;
  }

  s->swift_user = info.user;
  s->swift_groups = info.auth_groups;

  string swift_user = s->swift_user;

  ldout(cct, 10) << "swift user=" << s->swift_user << dendl;

  if (rgw_get_user_info_by_swift(store, swift_user, s->user) < 0) {
    ldout(cct, 0) << "NOTICE: couldn't map swift user" << dendl;
    return false;
  }

  ldout(cct, 10) << "user_id=" << s->user.user_id << dendl;

  return true;
}

RGWSwift *rgw_swift = NULL;

void swift_init(CephContext *cct)
{
  rgw_swift = new RGWSwift(cct);
}

void swift_finalize()
{
  delete rgw_swift;
}

