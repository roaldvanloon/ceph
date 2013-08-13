#ifndef CEPH_RGW_API_GS_H
#define CEPH_RGW_API_GS_H

#include "rgw/rgw_rest.h"

#include "acl.h"
#include "cors.h"

namespace rgw { namespace api { namespace gs {

class RGW_Auth_GS {
public:
  static int authorize(RGWRados *store, struct req_state *s);
  static int authorize_aws_signature(RGWRados *store, struct req_state *s);
  static int authorize_goog1_signature(RGWRados *store, struct req_state *s);
  static int authorize_oauth_signature(RGWRados *store, struct req_state *s);
};

class RGWHandler_ObjStore_GS : public RGWHandler_ObjStore {
  friend class RGWRESTMgr_GS;
public:
  RGWHandler_ObjStore_GS() : RGWHandler_ObjStore() {}
  virtual ~RGWHandler_ObjStore_GS() {}
  virtual int validate_bucket_name(const string& bucket) {
    return 0;
  }

  static int init_from_header(struct req_state *s, int default_formatter, bool configurable_format);
  int validate_bucket_name(const string& bucket, bool relaxed_names);
  virtual int init(RGWRados *store, struct req_state *state, RGWClientIO *cio);
  virtual int authorize() {
    return RGW_Auth_GS::authorize(store, s);
  }
};

class RGWHandler_Auth_GS : public RGWHandler_ObjStore {
  friend class RGWRESTMgr_GS;
public:
  RGWHandler_Auth_GS() : RGWHandler_ObjStore() {}
  virtual ~RGWHandler_Auth_GS() {}

  virtual int validate_bucket_name(const string& bucket) {
    return 0;
  }

  virtual int validate_object_name(const string& bucket) { return 0; }

  virtual int init(RGWRados *store, struct req_state *state, RGWClientIO *cio);
  virtual int authorize() {
    return RGW_Auth_GS::authorize(store, s);
  }
};

class RGWRESTMgr_GS : public RGWRESTMgr {
public:
  RGWRESTMgr_GS() {}
  virtual ~RGWRESTMgr_GS() {}

  virtual RGWRESTMgr *get_resource_mgr(struct req_state *s, const string& uri, string *out_uri) {
    return this;
  }
  virtual RGWRESTMgr *get_resource_mgr(struct req_state *s, const string& uri) {
    return this;
  }
  virtual RGWHandler *get_handler(struct req_state *s);
};

/*
 * This should probably be generic
 */


class RGWLocationConstraint : public XMLObj
{
public:
  RGWLocationConstraint() {}
  ~RGWLocationConstraint() {}
  bool xml_end(const char *el) {
    if (!el)
      return false;

    location_constraint = get_data();

    return true;
  }

  string location_constraint;
};

class RGWCreateBucketConfig : public XMLObj
{
public:
  RGWCreateBucketConfig() {}
  ~RGWCreateBucketConfig() {}
};

class RGWCreateBucketParser : public RGWXMLParser
{
  XMLObj *alloc_obj(const char *el) {
    return new XMLObj;
  }

public:
  RGWCreateBucketParser() {}
  ~RGWCreateBucketParser() {}

  bool get_location_constraint(string& region) {
    XMLObj *config = find_first("CreateBucketConfiguration");
    if (!config)
      return false;

    XMLObj *constraint = config->find_first("LocationConstraint");
    if (!constraint)
      return false;

    region = constraint->get_data();

    return true;
  }
};

}}}

#endif
