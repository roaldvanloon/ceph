#include "rgw_api_gs.h"

#define dout_subsys ceph_subsys_rgw
#undef dout_prefix
#define dout_prefix *_dout << "(rgw:api:gs) "

namespace rgw { namespace api { namespace gs {

static bool looks_like_ip_address(const char *bucket)
{
  int num_periods = 0;
  bool expect_period = false;
  for (const char *b = bucket; *b; ++b) {
    if (*b == '.') {
      if (!expect_period)
  return false;
      ++num_periods;
      if (num_periods > 3)
  return false;
      expect_period = false;
    }
    else if (isdigit(*b)) {
      expect_period = true;
    }
    else {
      return false;
    }
  }
  return (num_periods == 3);
}

int create_policy(struct req_state *s, RGWRados *store, AccessControlPolicy& gspolicy)
{
  if (s->has_acl_header) {
    if (!s->canned_acl.empty())
      return -ERR_INVALID_REQUEST;

    return gspolicy.create_from_headers(store, s->info.env, s->owner);
  }

  return gspolicy.create_canned(s->owner, s->bucket_owner, s->canned_acl);
}

static void next_tok(string& str, string& tok, char delim)
{
  if (str.size() == 0) {
    tok = "";
    return;
  }
  tok = str;
  int pos = str.find(delim);
  if (pos > 0) {
    tok = str.substr(0, pos);
    str = str.substr(pos + 1);
  } else {
    str = "";
  }
}

int Handler::init_from_header(struct req_state *s, int default_formatter, bool configurable_format)
{
  string req;
  string first;

  const char *req_name = s->relative_uri.c_str();
  const char *p;

  if (*req_name == '?') {
    p = req_name;
  } else {
    p = s->info.request_params.c_str();
  }

  s->info.args.set(p);
  s->info.args.parse();

  /* must be called after the args parsing */
  int ret = allocate_formatter(s, default_formatter, configurable_format);
  if (ret < 0)
    return ret;

  if (*req_name != '/')
    return 0;

  req_name++;

  if (!*req_name)
    return 0;
  req = req_name;

  /* remove prefix path */
  int pos = req.find('/');
  if (pos >= 0) {
    bool cut_url = g_conf->rgw_gs_url_prefix.length();
    first = req.substr(0, pos);
    if (first.compare(g_conf->rgw_gs_url_prefix) == 0) {
      if (cut_url) {
        next_tok(req, first, '/');
      }
    }
    s->info.effective_uri = req[0] != '/' ? string("/").append(req) : req;
  } else {
    if (req.compare(g_conf->rgw_gs_url_prefix) == 0) {
      s->formatter = new RGWFormatter_Plain;
      return -ERR_BAD_URL;
    }
    first = req;
  }

  pos = req.find('/');
  if (pos >= 0) {
    first = req.substr(0, pos);
  } else {
    first = req;
  }

  if (!s->bucket_name) {
    s->bucket_name_str = first;
    s->bucket_name = strdup(s->bucket_name_str.c_str());

    if (pos >= 0) {
      string encoded_obj_str = req.substr(pos+1);
      s->object_str = encoded_obj_str;

      if (s->object_str.size() > 0) {
        s->object = strdup(s->object_str.c_str());
      }
    }
  } else {
    s->object_str = req_name;
    s->object = strdup(s->object_str.c_str());
  }

  /* reparse x-meta-args without replacing the x-goog- prefix with x-amz- */
  s->info.init_meta_info(NULL, false);

  /* now check out api-version (and remove it, we dont want it as canonical header) */
  map<string, string>::iterator iter;
  string api_version;
  iter = s->info.x_meta_map.find("x-goog-api-version");
  if (iter == s->info.x_meta_map.end())
    return -ERR_MALFORMED_HEADER;
  api_version = iter->second;
  if (api_version != "1" && api_version != "2") // currently only allow v1.0 and v2.0
    return -EINVAL;
  s->info.x_meta_map.erase(iter);

  dout(0) << "Using API version " << api_version << dendl;

  return 0;
}

int Handler::validate_bucket_name(const string& bucket, bool relaxed_names)
{
  int ret = RGWHandler_ObjStore::validate_bucket_name(bucket);
  if (ret < 0)
    return ret;

  if (bucket.size() == 0)
    return 0;

  // bucket names must start with a number, letter, or underscore
  if (!(isalpha(bucket[0]) || isdigit(bucket[0]))) {
    if (!relaxed_names)
      return -ERR_INVALID_BUCKET_NAME;
    else if (!(bucket[0] == '_' || bucket[0] == '.' || bucket[0] == '-'))
      return -ERR_INVALID_BUCKET_NAME;
  }

  for (const char *s = bucket.c_str(); *s; ++s) {
    char c = *s;
    if (isdigit(c) || (c == '.'))
      continue;
    if (isalpha(c))
      continue;
    if ((c == '-') || (c == '_'))
      continue;
    // Invalid character
    return -ERR_INVALID_BUCKET_NAME;
  }

  if (looks_like_ip_address(bucket.c_str()))
    return -ERR_INVALID_BUCKET_NAME;

  return 0;
}

int Handler::init(RGWRados *store, struct req_state *s, RGWClientIO *cio)
{
  dout(10) << "s->object=" << (s->object ? s->object : "<NULL>") << " s->bucket=" << (s->bucket_name ? s->bucket_name : "<NULL>") << dendl;

  bool relaxed_names = s->cct->_conf->rgw_relaxed_gs_bucket_names;
  int ret = validate_bucket_name(s->bucket_name_str, relaxed_names);
  if (ret)
    return ret;
  ret = validate_object_name(s->object_str);
  if (ret)
    return ret;

  const char *cacl = s->info.env->get("HTTP_X_GOOG_ACL");
  if (cacl)
    s->canned_acl = cacl;

  s->copy_source = s->info.env->get("HTTP_X_GOOG_COPY_SOURCE");

  s->dialect = "gs";

  return RGWHandler_ObjStore::init(store, s, cio);
}

}}}
