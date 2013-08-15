#include <errno.h>

#include "common/errno.h"
#include "common/armor.h"
#include "common/ceph_crypto_cms.h"
#include "rgw/rgw_common.h"

#include "token.h"

#define dout_subsys ceph_subsys_rgw
#undef dout_prefix
#define dout_prefix *_dout << "(rgw:plugin:keystone) "

namespace rgw { namespace plugins { namespace keystone {

bool KeystoneToken::User::has_role(const string& r) {
  list<Role>::iterator iter;
  for (iter = roles.begin(); iter != roles.end(); ++iter) {
    if (r.compare((*iter).name) == 0)
      return true;
  }
  return false;
}

int KeystoneToken::parse(CephContext *cct, bufferlist& bl)
{
  JSONParser parser;
  if (!parser.parse(bl.c_str(), bl.length())) {
    return -EINVAL;
  }

  try {
    JSONDecoder::decode_json("access", *this, &parser);
  } catch (JSONDecoder::err& err) {
    return -EINVAL;
  }

  return 0;
}

void KeystoneToken::Metadata::decode_json(JSONObj *obj)
{
  JSONDecoder::decode_json("is_admin", is_admin, obj);
}

void KeystoneToken::Service::Endpoint::decode_json(JSONObj *obj)
{
  JSONDecoder::decode_json("id", id, obj);
  JSONDecoder::decode_json("adminURL", admin_url, obj);
  JSONDecoder::decode_json("publicURL", public_url, obj);
  JSONDecoder::decode_json("internalURL", internal_url, obj);
  JSONDecoder::decode_json("region", region, obj);
}

void KeystoneToken::Service::decode_json(JSONObj *obj)
{
  JSONDecoder::decode_json("type", type, obj, true);
  JSONDecoder::decode_json("name", name, obj, true);
  JSONDecoder::decode_json("endpoints", endpoints, obj);
}

void KeystoneToken::Token::Tenant::decode_json(JSONObj *obj)
{
  JSONDecoder::decode_json("id", id, obj, true);
  JSONDecoder::decode_json("name", name, obj, true);
  JSONDecoder::decode_json("description", description, obj);
  JSONDecoder::decode_json("enabled", enabled, obj);
}

void KeystoneToken::Token::decode_json(JSONObj *obj)
{
  string expires_iso8601;
  struct tm t;

  JSONDecoder::decode_json("id", id, obj, true);
  JSONDecoder::decode_json("tenant", tenant, obj, true);
  JSONDecoder::decode_json("expires", expires_iso8601, obj, true);

  if (parse_iso8601(expires_iso8601.c_str(), &t)) {
    expires = timegm(&t);
  } else {
    expires = 0;
    throw JSONDecoder::err("Failed to parse ISO8601 expiration date from Keystone response.");
  }
}

void KeystoneToken::User::Role::decode_json(JSONObj *obj)
{
  JSONDecoder::decode_json("id", id, obj);
  JSONDecoder::decode_json("name", name, obj);
}

void KeystoneToken::User::decode_json(JSONObj *obj)
{
  JSONDecoder::decode_json("id", id, obj, true);
  JSONDecoder::decode_json("name", name, obj);
  JSONDecoder::decode_json("username", user_name, obj, true);
  JSONDecoder::decode_json("roles", roles, obj);
}

void KeystoneToken::decode_json(JSONObj *access_obj)
{
  JSONDecoder::decode_json("metadata", metadata, access_obj);
  JSONDecoder::decode_json("token", token, access_obj, true);
  JSONDecoder::decode_json("user", user, access_obj, true);
  JSONDecoder::decode_json("serviceCatalog", service_catalog, access_obj);
}

int KeystoneSignedEnveloppe::parse(CephContext *cct, bufferlist& bl)
{
  JSONParser parser;
  if (!parser.parse(bl.c_str(), bl.length())) {
    return -EINVAL;
  }

  try {
    JSONDecoder::decode_json("signed", signed_certificate, &parser);
  } catch (JSONDecoder::err& err) {
    return -EINVAL;
  }

  /* open CMS enveloppe */
  int start = signed_certificate.find(BEGIN_CMS);
  if (start < 0)
    return -EINVAL;
  start += sizeof(BEGIN_CMS) - 1;

  int end = signed_certificate.find(END_CMS);
  if (end < 0)
    return -EINVAL;

  base64encoded.clear();
  string s = signed_certificate.substr(start, end - start);
  int pos = 0;

  do {
    int next = s.find('\n', pos);
    if (next < 0) {
      base64encoded.append(s.substr(pos));
      break;
    } else {
      base64encoded.append(s.substr(pos, next - pos));
    }
    pos = next + 1;
  } while (pos < (int)s.size());


  /* now decode base64 string */
  bufferptr signed_ber(base64encoded.size() * 2);
  char *dest = signed_ber.c_str();
  const char *src = base64encoded.c_str();
  size_t len = base64encoded.size();
  char buf[len + 1];
  buf[len] = '\0';
  for (size_t i = 0; i < len; i++, src++) {
    if (*src != '-')
      buf[i] = *src;
    else
      buf[i] = '/';
  }
  int ret = ceph_unarmor(dest, dest + signed_ber.length(), buf, buf + base64encoded.size());
  if (ret < 0)
    return ret;

  /* finally decode the cms into a json bufferlist */
  bufferlist signed_ber_bl;
  bufferlist json;
  signed_ber_bl.append(signed_ber);

  ret = ceph_decode_cms(cct, signed_ber_bl, json);
  if (ret < 0)
    return ret;

  /* json-decode the result (this should be rewritten to the JSONDecoder stuff one day) */
  JSONParser list_parser;
  if (!list_parser.parse(json.c_str(), json.length()))
    return -EINVAL;

  JSONObjIter revoked_iter = list_parser.find_first("revoked");
  if (revoked_iter.end())
    return -EINVAL;

  revoked_tokens.clear();
  JSONObj *revoked_obj = *revoked_iter;
  JSONObjIter tokens_iter = revoked_obj->find_first();
  for (; !tokens_iter.end(); ++tokens_iter) {
    JSONObj *o = *tokens_iter;

    JSONObj *token = o->find_obj("id");
    if (!token)
      continue;

    revoked_tokens.push_back(token->get_data());
  }

  return 0;
}

}}}
