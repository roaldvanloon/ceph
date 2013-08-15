#include "rgw/rgw_auth_s3.h"

#include "httpclient.h"
#include "token.h"

#include "handlers.h"

#define dout_subsys ceph_subsys_rgw
#undef dout_prefix
#define dout_prefix *_dout << "(rgw:plugin:keystone) "

namespace rgw { namespace plugins { namespace keystone {

static int store_user_info_from_token(RGWRados *store, struct req_state *s, KeystoneToken *t) {
  s->user.user_id = t->token.tenant.id;
  s->user.display_name = t->token.tenant.name;

  /* try to store user if it not already exists */
  int ret = 0;
  if (rgw_get_user_info_by_uid(store, t->token.tenant.id, s->user) < 0) {
    int ret = rgw_store_user_info(store, s->user, NULL, NULL, 0, true);
    if (ret < 0)
      dout(10) << "Failed to store new user's info: ret=" << ret << dendl;
  }
  return ret;
}

int S3TokenRequest::authorize(RGWRados *store, struct req_state *s) {
  int keystone_result = -EINVAL;
  string token;
  bool qsr = false;
  JSONFormatter credentials(false);
  time_t now;

  time(&now);

  /* Prepare credentials request */
  credentials.open_object_section("");
  credentials.open_object_section("credentials");

  /* Read S3 authentication stuff from request */
  string auth_id;
  string auth_sign;
  if (!s->http_auth || !(*s->http_auth)) {
    auth_id = s->info.args.get("AWSAccessKeyId");
    if (auth_id.size()) {
      auth_sign = s->info.args.get("Signature");

      string date = s->info.args.get("Expires");
      time_t exp = atoll(date.c_str());
      if (now >= exp)
        return -EPERM;

      qsr = true;
    } else {
      /* anonymous access */
      rgw_get_anon_user(s->user);
      s->perm_mask = RGW_PERM_FULL_CONTROL;
      return 0;
    }
  } else {
    if (strncmp(s->http_auth, "AWS ", 4))
      return -EINVAL;
    string auth_str(s->http_auth + 4);
    int pos = auth_str.find(':');
    if (pos < 0)
      return -EINVAL;

    auth_id = auth_str.substr(0, pos);
    auth_sign = auth_str.substr(pos + 1);
  }
  credentials.dump_string("access", auth_id);
  credentials.dump_string("signature", auth_sign);

  /* Create token + encode it*/
  bufferlist token_buff;
  bufferlist token_encoded;
  if (!rgw_create_s3_canonical_header(s->info, &s->header_time, token, qsr)) {
      dout(10) << "failed to create auth header\n" << token << dendl;
      return -EINVAL;
  }
  token_buff.append(token);
  token_buff.encode_base64(token_encoded);
  token_encoded.append((char)0);
  credentials.dump_string("token", token_encoded.c_str());

  /* Finish credentials request + dispatch it */
  KeystoneAuthClient keystone_client(store->ctx(), "v2.0/s3tokens");
  credentials.close_section();
  credentials.close_section();
  keystone_client.set_json_body(&credentials);
  keystone_result = keystone_client.dispatch();

  if (keystone_result == 0) {
    store_user_info_from_token(store, s, &(keystone_client.response));
    s->perm_mask = RGW_PERM_FULL_CONTROL;
  }

  return keystone_result;
};

int V1TokenRequest::authorize(RGWRados *store, struct req_state *s) {
  int keystone_result = -EINVAL;
  JSONFormatter credentials(false);

  /* Prepare credentials request */
  credentials.open_object_section("");
  credentials.open_object_section("auth");

  /* Read authentication stuff from request */
  credentials.open_object_section("passwordCredentials");
  credentials.dump_string("username", s->info.env->get("HTTP_X_AUTH_USER", ""));
  credentials.dump_string("password", s->info.env->get("HTTP_X_AUTH_KEY", ""));
  credentials.close_section();

  /* Finish credentials request + dispatch it */
  KeystoneAuthClient keystone_client(store->ctx(), "v2.0/tokens");
  credentials.close_section();
  credentials.close_section();
  keystone_client.set_json_body(&credentials);
  keystone_result = keystone_client.dispatch();

  if (keystone_result == 0) {
    store_user_info_from_token(store, s, &(keystone_client.response));
    cache->add(keystone_client.response);
    s->perm_mask = RGW_PERM_FULL_CONTROL;
  }

  return keystone_result;
}

int TokenCacheValidator::authorize(RGWRados *store, struct req_state *s) {
  const char *token_id = s->info.env->get("HTTP_X_AUTH_TOKEN");
  KeystoneToken *token;
  if (token_id == NULL)
    return -EINVAL;

  dout(10) << "Found HTTP_X_AUTH_TOKEN, checking cache.." << dendl;

  if (!cache->find(token_id, token))
    return -EINVAL;

  dout(10) << "Found cache entry, token: " << token->token.id << " (user: " << token->user.user_name << ")" << dendl;

  if (store_user_info_from_token(store, s, token))
    return -EPERM;

  dout(10) << "User info stored, auth from cache OK." << dendl;

  return 0;
}




}}}
