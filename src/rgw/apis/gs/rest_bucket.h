#ifndef CEPH_RGW_API_GS_REST_BUCKET_H
#define CEPH_RGW_API_GS_REST_BUCKET_H

#include "rgw_api_gs.h"

namespace rgw { namespace api { namespace gs {

class RGWListBucket_ObjStore_GS : public RGWListBucket_ObjStore {
public:
  RGWListBucket_ObjStore_GS() {
    default_max = 1000;
  }
  ~RGWListBucket_ObjStore_GS() {}

  int get_params();
  void send_response();
};

class RGWCreateBucket_ObjStore_GS : public RGWCreateBucket_ObjStore {
public:
  RGWCreateBucket_ObjStore_GS() {}
  ~RGWCreateBucket_ObjStore_GS() {}

  int get_params();
  void send_response();
};

class RGWDeleteBucket_ObjStore_GS : public RGWDeleteBucket_ObjStore {
public:
  RGWDeleteBucket_ObjStore_GS() {}
  ~RGWDeleteBucket_ObjStore_GS() {}

  void send_response();
};

class RGWGetBucketLogging_ObjStore_GS : public RGWGetBucketLogging {
public:
  RGWGetBucketLogging_ObjStore_GS() {}
  ~RGWGetBucketLogging_ObjStore_GS() {}

  void send_response();
};

class RGWStatBucket_ObjStore_GS : public RGWStatBucket_ObjStore {
public:
  RGWStatBucket_ObjStore_GS() {}
  ~RGWStatBucket_ObjStore_GS() {}

  void send_response();
};

class RGWGetBucketACLs_ObjStore_GS : public RGWGetACLs_ObjStore {
public:
  RGWGetBucketACLs_ObjStore_GS() {}
  ~RGWGetBucketACLs_ObjStore_GS() {}

  void send_response();
};

class RGWPutBucketACLs_ObjStore_GS : public RGWPutACLs_ObjStore {
public:
  RGWPutBucketACLs_ObjStore_GS() {}
  ~RGWPutBucketACLs_ObjStore_GS() {}

  int get_policy_from_state(RGWRados *store, struct req_state *s, stringstream& ss);
  void send_response();
};

class RGWGetBucketCORS_ObjStore_GS : public RGWGetCORS_ObjStore {
public:
  RGWGetBucketCORS_ObjStore_GS() {}
  ~RGWGetBucketCORS_ObjStore_GS() {}

  void send_response();
};

class RGWPutBucketCORS_ObjStore_GS : public RGWPutCORS_ObjStore {
public:
  RGWPutBucketCORS_ObjStore_GS() {}
  ~RGWPutBucketCORS_ObjStore_GS() {}

  int get_params();
  void send_response();
};

class RGWHandler_ObjStore_Bucket_GS : public RGWHandler_ObjStore_GS {
public:
  RGWHandler_ObjStore_Bucket_GS() {}
  virtual ~RGWHandler_ObjStore_Bucket_GS() {}
protected:
  bool is_websiteconfig_op() { return s->info.args.exists("websiteConfig"); }
  bool is_versioning_op() { return s->info.args.exists("versioning"); }
  bool is_lifecycle_op() { return s->info.args.exists("lifecycle"); }
  bool is_logging_op() { return s->info.args.exists("logging"); }
  bool is_acl_op() { return s->info.args.exists("acl"); }
  bool is_cors_op() { return s->info.args.exists("cors"); }
  RGWOp *op_get();
  RGWOp *op_put();
  RGWOp *op_delete();
};

}}}

#endif /* CEPH_RGW_API_GS_REST_BUCKET_H */
