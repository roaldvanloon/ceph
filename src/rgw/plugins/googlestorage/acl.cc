#include "rgw_api_gs.h"

#include "acl.h"

#define dout_subsys ceph_subsys_rgw
#undef dout_prefix
#define dout_prefix *_dout << "(rgw:api:gs) "

#define RGW_URI_ALL_USERS "http://acs.amazonaws.com/groups/global/AllUsers"
#define RGW_URI_AUTH_USERS  "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"

namespace rgw { namespace api { namespace gs {

static string rgw_uri_all_users = RGW_URI_ALL_USERS;
static string rgw_uri_auth_users = RGW_URI_AUTH_USERS;

void ACLPermission::to_xml(ostream& out)
{
  if ((flags & RGW_PERM_FULL_CONTROL) == RGW_PERM_FULL_CONTROL) {
   out << "<Permission>FULL_CONTROL</Permission>";
  } else {
    if (flags & RGW_PERM_READ)
      out << "<Permission>READ</Permission>";
    if (flags & RGW_PERM_WRITE)
      out << "<Permission>WRITE</Permission>";
    if (flags & RGW_PERM_READ_ACP)
      out << "<Permission>READ_ACP</Permission>";
    if (flags & RGW_PERM_WRITE_ACP)
      out << "<Permission>WRITE_ACP</Permission>";
  }
}

bool ACLPermission::xml_end(const char *el)
{
  const char *s = data.c_str();
  if (strcasecmp(s, "READ") == 0) {
    flags |= RGW_PERM_READ;
    return true;
  } else if (strcasecmp(s, "WRITE") == 0) {
    flags |= RGW_PERM_WRITE;
    return true;
  } else if (strcasecmp(s, "READ_ACP") == 0) {
    flags |= RGW_PERM_READ_ACP;
    return true;
  } else if (strcasecmp(s, "WRITE_ACP") == 0) {
    flags |= RGW_PERM_WRITE_ACP;
    return true;
  } else if (strcasecmp(s, "FULL_CONTROL") == 0) {
    flags |= RGW_PERM_FULL_CONTROL;
    return true;
  }
  return false;
}


class ACLGranteeType {
public:
  static const char *to_string(::ACLGranteeType& type) {
    switch (type.get_type()) {
    case ACL_TYPE_CANON_USER:
      return "CanonicalUser";
    case ACL_TYPE_EMAIL_USER:
      return "CustomerByEmail";
    case ACL_TYPE_GROUP:
      return "Group";
     default:
      return "unknown";
    }
  }

  static void set(const char *s, ::ACLGranteeType& type) {
    if (!s) {
      type.set(ACL_TYPE_UNKNOWN);
      return;
    }
    if (strcmp(s, "CanonicalUser") == 0)
      type.set(ACL_TYPE_CANON_USER);
    else if (strcmp(s, "CustomerByEmail") == 0)
      type.set(ACL_TYPE_EMAIL_USER);
    else if (strcmp(s, "Group") == 0)
      type.set(ACL_TYPE_GROUP);
    else
      type.set(ACL_TYPE_UNKNOWN);
  }
};

class ACLID : public XMLObj
{
public:
  ACLID() {}
  ~ACLID() {}
  string& to_str() { return data; }
};

class ACLURI : public XMLObj
{
public:
  ACLURI() {}
  ~ACLURI() {}
};

class ACLEmail : public XMLObj
{
public:
  ACLEmail() {}
  ~ACLEmail() {}
};

class ACLDisplayName : public XMLObj
{
public:
 ACLDisplayName() {}
 ~ACLDisplayName() {}
};

bool ACLOwner::xml_end(const char *el) {
  ACLID *acl_id = static_cast<ACLID *>(find_first("ID"));
  ACLID *acl_name = static_cast<ACLID *>(find_first("DisplayName"));

  // ID is mandatory
  if (!acl_id)
    return false;
  id = acl_id->get_data();

  // DisplayName is optional
  if (acl_name)
    display_name = acl_name->get_data();
  else
    display_name = "";

  return true;
}

bool ACLGrant::xml_end(const char *el) {
  ACLGrantee *acl_grantee;
  ACLID *acl_id;
  ACLURI *acl_uri;
  ACLEmail *acl_email;
  ACLPermission *acl_permission;
  ACLDisplayName *acl_name;
  string uri;

  acl_grantee = static_cast<ACLGrantee *>(find_first("Grantee"));
  if (!acl_grantee)
    return false;
  string type_str;
  if (!acl_grantee->get_attr("xsi:type", type_str))
    return false;
  ACLGranteeType::set(type_str.c_str(), type);

  acl_permission = static_cast<ACLPermission *>(find_first("Permission"));
  if (!acl_permission)
    return false;

  permission = *acl_permission;

  id.clear();
  name.clear();
  email.clear();

  switch (type.get_type()) {
  case ACL_TYPE_CANON_USER:
    acl_id = static_cast<ACLID *>(acl_grantee->find_first("ID"));
    if (!acl_id)
      return false;
    id = acl_id->to_str();
    acl_name = static_cast<ACLDisplayName *>(acl_grantee->find_first("DisplayName"));
    if (acl_name)
      name = acl_name->get_data();
    break;
  case ACL_TYPE_GROUP:
    acl_uri = static_cast<ACLURI *>(acl_grantee->find_first("URI"));
    if (!acl_uri)
      return false;
    uri = acl_uri->get_data();
    group = uri_to_group(uri);
    break;
  case ACL_TYPE_EMAIL_USER:
    acl_email = static_cast<ACLEmail *>(acl_grantee->find_first("EmailAddress"));
    if (!acl_email)
      return false;
    email = acl_email->get_data();
    break;
  default:
    // unknown user type
    return false;
  };
  return true;
}

void ACLGrant::to_xml(CephContext *cct, ostream& out) {
  ACLPermission& perm = static_cast<ACLPermission &>(permission);

  /* only show GS compatible permissions */
  if (!(perm.get_permissions() & (RGW_PERM_READ | RGW_PERM_WRITE)))
    return;

  string uri;

  out << "<Grant>" <<
         "<Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"" << ACLGranteeType::to_string(type) << "\">";
  switch (type.get_type()) {
  case ACL_TYPE_CANON_USER:
    out << "<ID>" << id << "</ID>";
    if (name.size()) {
      out << "<DisplayName>" << name << "</DisplayName>";
    }
    break;
  case ACL_TYPE_EMAIL_USER:
    out << "<EmailAddress>" << email << "</EmailAddress>";
    break;
  case ACL_TYPE_GROUP:
    if (!group_to_uri(group, uri)) {
      ldout(cct, 0) << "ERROR: group_to_uri failed with group=" << (int)group << dendl;
      break;
    }
    out << "<URI>" << uri << "</URI>";
    break;
  default:
    break;
  }
  out << "</Grantee>";
  perm.to_xml(out);
  out << "</Grant>";
}

bool ACLGrant::group_to_uri(ACLGroupTypeEnum group, string& uri)
{
  switch (group) {
  case ACL_GROUP_ALL_USERS:
    uri = rgw_uri_all_users;
    return true;
  case ACL_GROUP_AUTHENTICATED_USERS:
    uri = rgw_uri_auth_users;
    return true;
  default:
    return false;
  }
}

ACLGroupTypeEnum ACLGrant::uri_to_group(string& uri)
{
  if (uri.compare(rgw_uri_all_users) == 0)
    return ACL_GROUP_ALL_USERS;
  else if (uri.compare(rgw_uri_auth_users) == 0)
    return ACL_GROUP_AUTHENTICATED_USERS;

  return ACL_GROUP_NONE;
}

bool AccessControlList::xml_end(const char *el) {
  XMLObjIter iter = find("Grant");
  ACLGrant *grant = static_cast<ACLGrant *>(iter.get_next());
  while (grant) {
    add_grant(grant);
    grant = static_cast<ACLGrant *>(iter.get_next());
  }
  return true;
}

struct acl_header {
  int rgw_perm;
  const char *http_header;
};

static const char *get_acl_header(RGWEnv *env, const struct acl_header *perm) {
  const char *header = perm->http_header;
  return env->get(header, NULL);
}

static int parse_grantee_str(RGWRados *store, string& grantee_str,
        const struct acl_header *perm, ::ACLGrant& grant)
{
  string id_type, id_val_quoted;
  int rgw_perm = perm->rgw_perm;
  int ret;

  RGWUserInfo info;

  ret = parse_key_value(grantee_str, id_type, id_val_quoted);
  if (ret < 0)
    return ret;

  string id_val = rgw_trim_quotes(id_val_quoted);

  if (strcasecmp(id_type.c_str(), "emailAddress") == 0) {
    ret = rgw_get_user_info_by_email(store, id_val, info);
    if (ret < 0)
      return ret;

    grant.set_canon(info.user_id, info.display_name, rgw_perm);
  } else if (strcasecmp(id_type.c_str(), "id") == 0) {
    ret = rgw_get_user_info_by_uid(store, id_val, info);
    if (ret < 0)
      return ret;

    grant.set_canon(info.user_id, info.display_name, rgw_perm);
  } else if (strcasecmp(id_type.c_str(), "uri") == 0) {
    ACLGroupTypeEnum gid = grant.uri_to_group(id_val);
    if (gid == ACL_GROUP_NONE)
      return -EINVAL;

    grant.set_group(gid, rgw_perm);
  } else {
    return -EINVAL;
  }

  return 0;
}

static int parse_acl_header(RGWRados *store, RGWEnv *env,
         const struct acl_header *perm, std::list< ::ACLGrant >& _grants)
{
  std::list<string> grantees;
  std::string hacl_str;

  const char *hacl = get_acl_header(env, perm);
  if (hacl == NULL)
    return 0;

  hacl_str = hacl;
  get_str_list(hacl_str, ",", grantees);

  for (list<string>::iterator it = grantees.begin(); it != grantees.end(); ++it) {
    ::ACLGrant grant;
    int ret = parse_grantee_str(store, *it, perm, grant);
    if (ret < 0)
      return ret;

    _grants.push_back(grant);
  }

  return 0;
}

int AccessControlList::create_canned(::ACLOwner& owner, ::ACLOwner& bucket_owner, const string& canned_acl)
{
  acl_user_map.clear();
  grant_map.clear();

  ::ACLGrant owner_grant;

  string bid = bucket_owner.get_id();
  string bname = bucket_owner.get_display_name();

  /* owner gets full control */
  owner_grant.set_canon(owner.get_id(), owner.get_display_name(), RGW_PERM_FULL_CONTROL);
  add_grant(&owner_grant);

  if (canned_acl.size() == 0 || canned_acl.compare("private") == 0) {
    return 0;
  }

  ::ACLGrant bucket_owner_grant;
  ::ACLGrant group_grant;
  if (canned_acl.compare("public-read") == 0) {
    group_grant.set_group(ACL_GROUP_ALL_USERS, RGW_PERM_READ);
    add_grant(&group_grant);
  } else if (canned_acl.compare("public-read-write") == 0) {
    group_grant.set_group(ACL_GROUP_ALL_USERS, RGW_PERM_READ);
    add_grant(&group_grant);
    group_grant.set_group(ACL_GROUP_ALL_USERS, RGW_PERM_WRITE);
    add_grant(&group_grant);
  } else if (canned_acl.compare("authenticated-read") == 0) {
    group_grant.set_group(ACL_GROUP_AUTHENTICATED_USERS, RGW_PERM_READ);
    add_grant(&group_grant);
  } else if (canned_acl.compare("bucket-owner-read") == 0) {
    bucket_owner_grant.set_canon(bid, bname, RGW_PERM_READ);
    if (bid.compare(owner.get_id()) != 0)
      add_grant(&bucket_owner_grant);
  } else if (canned_acl.compare("bucket-owner-full-control") == 0) {
    bucket_owner_grant.set_canon(bid, bname, RGW_PERM_FULL_CONTROL);
    if (bid.compare(owner.get_id()) != 0)
      add_grant(&bucket_owner_grant);
  } else {
    return -EINVAL;
  }

  return 0;
}

int AccessControlList::create_from_grants(std::list< ::ACLGrant >& grants)
{
  if (grants.empty())
    return -EINVAL;

  acl_user_map.clear();
  grant_map.clear();

  for (std::list< ::ACLGrant >::iterator it = grants.begin(); it != grants.end(); ++it) {
    ::ACLGrant g = *it;
    add_grant(&g);
  }

  return 0;
}

bool AccessControlPolicy::xml_end(const char *el) {
  AccessControlList *gsacl = static_cast<AccessControlList *>(find_first("AccessControlList"));
  if (!gsacl)
    return false;

  acl = *gsacl;

  ::ACLOwner *owner_p = static_cast<ACLOwner *>(find_first("Owner"));
  if (!owner_p)
    return false;
  owner = *owner_p;
  return true;
}

static const acl_header acl_header_perms[] = {
  {RGW_PERM_READ, "HTTP_X_AMZ_GRANT_READ"},
  {RGW_PERM_WRITE, "HTTP_X_AMZ_GRANT_WRITE"},
  {RGW_PERM_READ_ACP,"HTTP_X_AMZ_GRANT_READ_ACP"},
  {RGW_PERM_WRITE_ACP, "HTTP_X_AMZ_GRANT_WRITE_ACP"},
  {RGW_PERM_FULL_CONTROL, "HTTP_X_AMZ_GRANT_FULL_CONTROL"},
  {0, NULL}
};

int AccessControlPolicy::create_from_headers(RGWRados *store, RGWEnv *env, ::ACLOwner& _owner)
{
  std::list< ::ACLGrant > grants;

  for (const struct acl_header *p = acl_header_perms; p->rgw_perm; p++) {
    if (parse_acl_header(store, env, p, grants) < 0)
      return false;
  }

  AccessControlList& _acl = static_cast<AccessControlList &>(acl);
  int r = _acl.create_from_grants(grants);

  owner = _owner;

  return r;
}

/*
  can only be called on object that was parsed
 */
int AccessControlPolicy::rebuild(RGWRados *store, ::ACLOwner *owner, RGWAccessControlPolicy& dest)
{
  if (!owner)
    return -EINVAL;

  ::ACLOwner *requested_owner = static_cast<ACLOwner *>(find_first("Owner"));
  if (requested_owner && requested_owner->get_id().compare(owner->get_id()) != 0) {
    return -EPERM;
  }

  RGWUserInfo owner_info;
  if (rgw_get_user_info_by_uid(store, owner->get_id(), owner_info) < 0) {
    ldout(cct, 10) << "owner info does not exist" << dendl;
    return -EINVAL;
  }
  ::ACLOwner& dest_owner = dest.get_owner();
  dest_owner.set_id(owner->get_id());
  dest_owner.set_name(owner_info.display_name);

  ldout(cct, 20) << "owner id=" << owner->get_id() << dendl;
  ldout(cct, 20) << "dest owner id=" << dest.get_owner().get_id() << dendl;

  RGWAccessControlList& dst_acl = dest.get_acl();

  multimap<string, ::ACLGrant>& grant_map = acl.get_grant_map();
  multimap<string, ::ACLGrant>::iterator iter;
  for (iter = grant_map.begin(); iter != grant_map.end(); ++iter) {
    ::ACLGrant& src_grant = iter->second;
    ::ACLGranteeType& type = src_grant.get_type();
    ::ACLGrant new_grant;
    bool grant_ok = false;
    string uid;
    RGWUserInfo grant_user;
    switch (type.get_type()) {
    case ACL_TYPE_EMAIL_USER:
      {
        string email;
        if (!src_grant.get_id(email)) {
          ldout(cct, 0) << "ERROR: src_grant.get_id() failed" << dendl;
          return -EINVAL;
        }
        ldout(cct, 10) << "grant user email=" << email << dendl;
        if (rgw_get_user_info_by_email(store, email, grant_user) < 0) {
          ldout(cct, 10) << "grant user email not found or other error" << dendl;
          return -ERR_UNRESOLVABLE_EMAIL;
        }
        uid = grant_user.user_id;
      }
    case ACL_TYPE_CANON_USER:
      {
        if (type.get_type() == ACL_TYPE_CANON_USER) {
          if (!src_grant.get_id(uid)) {
            ldout(cct, 0) << "ERROR: src_grant.get_id() failed" << dendl;
            return -EINVAL;
          }
        }

        if (grant_user.user_id.empty() && rgw_get_user_info_by_uid(store, uid, grant_user) < 0) {
          ldout(cct, 10) << "grant user does not exist:" << uid << dendl;
          return -EINVAL;
        } else {
          ::ACLPermission& perm = src_grant.get_permission();
          new_grant.set_canon(uid, grant_user.display_name, perm.get_permissions());
          grant_ok = true;
          string new_id;
          new_grant.get_id(new_id);
          ldout(cct, 10) << "new grant: " << new_id << ":" << grant_user.display_name << dendl;
        }
      }
      break;
    case ACL_TYPE_GROUP:
      {
        string uri;
        if (ACLGrant::group_to_uri(src_grant.get_group(), uri)) {
          new_grant = src_grant;
          grant_ok = true;
          ldout(cct, 10) << "new grant: " << uri << dendl;
        } else {
          ldout(cct, 10) << "bad grant group:" << (int)src_grant.get_group() << dendl;
          return -EINVAL;
        }
      }
    default:
      break;
    }
    if (grant_ok) {
      dst_acl.add_grant(&new_grant);
    }
  }

  return 0;
}

bool AccessControlPolicy::compare_group_name(string& id, ACLGroupTypeEnum group)
{
  switch (group) {
  case ACL_GROUP_ALL_USERS:
    return (id.compare(rgw_uri_all_users) == 0);
  case ACL_GROUP_AUTHENTICATED_USERS:
    return (id.compare(rgw_uri_auth_users) == 0);
  default:
    return id.empty();
  }

  // shouldn't get here
  return false;
}

XMLObj *ACLXMLParser::alloc_obj(const char *el)
{
  XMLObj * obj = NULL;
  if (strcmp(el, "AccessControlPolicy") == 0) {
    obj = new AccessControlPolicy(cct);
  } else if (strcmp(el, "Owner") == 0) {
    obj = new ACLOwner();
  } else if (strcmp(el, "AccessControlList") == 0) {
    obj = new AccessControlList(cct);
  } else if (strcmp(el, "ID") == 0) {
    obj = new ACLID();
  } else if (strcmp(el, "DisplayName") == 0) {
    obj = new ACLDisplayName();
  } else if (strcmp(el, "Grant") == 0) {
    obj = new ACLGrant();
  } else if (strcmp(el, "Grantee") == 0) {
    obj = new ACLGrantee();
  } else if (strcmp(el, "Permission") == 0) {
    obj = new ACLPermission();
  } else if (strcmp(el, "URI") == 0) {
    obj = new ACLURI();
  } else if (strcmp(el, "EmailAddress") == 0) {
    obj = new ACLEmail();
  }

  return obj;
}

}}}
