#include "rgw/rgw_auth_s3.h"

#include "rgw_api_gs.h"
#include "cors.h"

#define dout_subsys ceph_subsys_rgw
#undef dout_prefix
#define dout_prefix *_dout << "(rgw:api:gs) "

#define RGW_AUTH_GRACE_MINS 15

namespace rgw { namespace api { namespace gs {

int Auth::authorize_aws_signature(RGWRados *store, struct req_state *s)
{
  bool qsr = false;
  string auth_id;
  string auth_sign;
  time_t now;

  time(&now);

  string auth_str(s->http_auth + 4);
  int pos = auth_str.find(':');
  if (pos < 0)
    return -EINVAL;

  auth_id = auth_str.substr(0, pos);
  auth_sign = auth_str.substr(pos + 1);

  /* first get the user info */
  if (rgw_get_user_info_by_access_key(store, auth_id, s->user) < 0) {
    dout(5) << "error reading user info, uid=" << auth_id << " can't authenticate" << dendl;
    return -EPERM;
  }

  /* now verify signature */
  string auth_hdr;
  if (!rgw_create_s3_canonical_header(s->info, &s->header_time, auth_hdr, qsr)) {
    dout(10) << "failed to create auth header\n" << auth_hdr << dendl;
    return -EPERM;
  }
  dout(10) << "auth_hdr:\n" << auth_hdr << dendl;

  time_t req_sec = s->header_time.sec();
  if ((req_sec < now - RGW_AUTH_GRACE_MINS * 60 ||
      req_sec > now + RGW_AUTH_GRACE_MINS * 60) && !qsr) {
    dout(10) << "req_sec=" << req_sec << " now=" << now << "; now - RGW_AUTH_GRACE_MINS=" << now - RGW_AUTH_GRACE_MINS * 60 << "; now + RGW_AUTH_GRACE_MINS=" << now + RGW_AUTH_GRACE_MINS * 60 << dendl;
    dout(0) << "NOTICE: request time skew too big now=" << utime_t(now, 0) << " req_time=" << s->header_time << dendl;
    return -ERR_REQUEST_TIME_SKEWED;
  }

  map<string, RGWAccessKey>::iterator iter = s->user.access_keys.find(auth_id);
  if (iter == s->user.access_keys.end()) {
    dout(0) << "ERROR: access key not encoded in user info" << dendl;
    return -EPERM;
  }
  RGWAccessKey& k = iter->second;

  if (!k.subuser.empty()) {
    map<string, RGWSubUser>::iterator uiter = s->user.subusers.find(k.subuser);
    if (uiter == s->user.subusers.end()) {
      dout(0) << "NOTICE: could not find subuser: " << k.subuser << dendl;
      return -EPERM;
    }
    RGWSubUser& subuser = uiter->second;
    s->perm_mask = subuser.perm_mask;
  } else
    s->perm_mask = RGW_PERM_FULL_CONTROL;

  string digest;
  int ret = rgw_get_s3_header_digest(auth_hdr, k.key, digest);
  if (ret < 0) {
    return -EPERM;
  }

  dout(15) << "calculated digest=" << digest << dendl;
  dout(15) << "auth_sign=" << auth_sign << dendl;
  dout(15) << "compare=" << auth_sign.compare(digest) << dendl;

  if (auth_sign != digest)
    return -EPERM;

  if (s->user.system) {
    s->system_request = true;
    dout(20) << "system request" << dendl;
    s->info.args.set_system();
    string effective_uid = s->info.args.get(RGW_SYS_PARAM_PREFIX "uid");
    RGWUserInfo effective_user;
    if (!effective_uid.empty()) {
      ret = rgw_get_user_info_by_uid(store, effective_uid, effective_user);
      if (ret < 0) {
        ldout(s->cct, 0) << "User lookup failed!" << dendl;
        return -ENOENT;
      }
      s->user = effective_user;
    }
  }

  // populate the owner info
  s->owner.set_id(s->user.user_id);
  s->owner.set_name(s->user.display_name);
  return 0;
}

int Auth::authorize_goog1_signature(RGWRados *store, struct req_state *s)
{
  dout(5) << "GOOG1 signatures not implemented, yet." << dendl;
  return -EPERM;
}

int Auth::authorize_oauth_signature(RGWRados *store, struct req_state *s)
{
  dout(5) << "OAUTH signatures not implemented, yet." << dendl;
  return -EPERM;
}

int Auth::authorize(RGWRados *store, struct req_state *s)
{

  if (!s->http_auth || !(*s->http_auth)) {
    /* anonymous access */
    rgw_get_anon_user(s->user);
    s->perm_mask = 0; // TODO
    return 0;
  }

  if (strncmp(s->http_auth, "AWS ", 4)==0)
    return authorize_aws_signature(store, s);

  if (strncmp(s->http_auth, "GOOG1 ", 6)==0)
    return authorize_goog1_signature(store, s);

  if (strncmp(s->http_auth, "OAuth ", 6)==0)
    return authorize_oauth_signature(store, s);

  return -EPERM;
}

int AuthHandler::init(RGWRados *store, struct req_state *state, RGWClientIO *cio)
{
  int ret = Handler::init_from_header(state, RGW_FORMAT_JSON, true);
  if (ret < 0)
    return ret;

  return RGWHandler_ObjStore::init(store, state, cio);
}

}}}
