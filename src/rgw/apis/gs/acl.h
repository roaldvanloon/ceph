#ifndef CEPH_RGW_APIS_GS_ACL_H
#define CEPH_RGW_APIS_GS_ACL_H

#include <map>
#include <string>
#include <iostream>
#include <include/types.h>
#include <expat.h>

#include "include/str_list.h"
#include "rgw/rgw_xml.h"
#include "rgw/rgw_acl.h"

class RGWRados;
class RGWEnv;

namespace rgw { namespace api { namespace gs {

class ACLPermission : public ::ACLPermission, public XMLObj
{
public:
  ACLPermission() {}
  ~ACLPermission() {}

  bool xml_end(const char *el);
  void to_xml(ostream& out);
};

class ACLGrantee : public ::ACLGrantee, public XMLObj
{
public:
  ACLGrantee() {}
  ~ACLGrantee() {}

  bool xml_start(const char *el, const char **attr);
};


class ACLGrant : public ::ACLGrant, public XMLObj
{
public:
  ACLGrant() {}
  ~ACLGrant() {}

  void to_xml(CephContext *cct, ostream& out);
  bool xml_end(const char *el);
  bool xml_start(const char *el, const char **attr);

  static ACLGroupTypeEnum uri_to_group(string& uri);
  static bool group_to_uri(ACLGroupTypeEnum group, string& uri);
};

class AccessControlList : public RGWAccessControlList, public XMLObj
{
public:
  AccessControlList(CephContext *_cct) : RGWAccessControlList(_cct) {}
  ~AccessControlList() {}

  bool xml_end(const char *el);
  void to_xml(ostream& out) {
    multimap<string, ::ACLGrant>::iterator iter;
    out << "<AccessControlList>";
    for (iter = grant_map.begin(); iter != grant_map.end(); ++iter) {
      ACLGrant& grant = static_cast<ACLGrant &>(iter->second);
      grant.to_xml(cct, out);
    }
    out << "</AccessControlList>";
  }

  int create_canned(::ACLOwner& owner, ::ACLOwner& bucket_owner, const string& canned_acl);
  int create_from_grants(std::list< ::ACLGrant>& grants);
};

class ACLOwner : public ::ACLOwner, public XMLObj
{
public:
  ACLOwner() {}
  ~ACLOwner() {}

  bool xml_end(const char *el);
  void to_xml(ostream& out) {
    if (id.empty())
      return;
    out << "<Owner>" << "<ID>" << id << "</ID>";
    if (!display_name.empty())
      out << "<DisplayName>" << display_name << "</DisplayName>";
    out << "</Owner>";
  }
};

class AccessControlPolicy : public RGWAccessControlPolicy, public XMLObj
{
public:
  AccessControlPolicy(CephContext *_cct) : RGWAccessControlPolicy(_cct) {}
  ~AccessControlPolicy() {}

  bool xml_end(const char *el);

  void to_xml(ostream& out) {
    out << "<AccessControlPolicy xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">";
    ACLOwner& _owner = static_cast<ACLOwner &>(owner);
    AccessControlList& _acl = static_cast<AccessControlList &>(acl);
    _owner.to_xml(out);
    _acl.to_xml(out);
    out << "</AccessControlPolicy>";
  }
  int rebuild(RGWRados *store, ::ACLOwner *owner, RGWAccessControlPolicy& dest);
  bool compare_group_name(string& id, ACLGroupTypeEnum group);

  virtual int create_canned(::ACLOwner& _owner, ::ACLOwner& bucket_owner, string canned_acl) {
    AccessControlList& _acl = static_cast<AccessControlList &>(acl);
    int ret = _acl.create_canned(_owner, bucket_owner, canned_acl);
    owner = _owner;
    return ret;
  }
  int create_from_headers(RGWRados *store, RGWEnv *env, ::ACLOwner& _owner);
};

/**
 * Interfaces with the webserver's XML handling code
 * to parse it in a way that makes sense for the rgw.
 */
class ACLXMLParser : public RGWXMLParser
{
  CephContext *cct;

  XMLObj *alloc_obj(const char *el);
public:
  ACLXMLParser(CephContext *_cct) : cct(_cct) {}
};

}}}

#endif /* CEPH_RGW_APIS_GS_ACL_H */
