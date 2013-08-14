#ifndef CEPH_RGW_API_GS_REST_BUCKET_H
#define CEPH_RGW_API_GS_REST_BUCKET_H

#include "rgw_api_gs.h"

namespace rgw { namespace api { namespace gs {

class ListBucket : public RGWListBucket_ObjStore {
public:
  ListBucket() {
    default_max = 1000;
  }
  ~ListBucket() {}

  int get_params();
  void send_response();
};

class CreateBucket : public RGWCreateBucket_ObjStore {
public:
  CreateBucket() {}
  ~CreateBucket() {}

  int get_params();
  void send_response();
};

class DeleteBucket : public RGWDeleteBucket_ObjStore {
public:
  DeleteBucket() {}
  ~DeleteBucket() {}

  void send_response();
};

class GetBucketLogging : public RGWGetBucketLogging {
public:
  GetBucketLogging() {}
  ~GetBucketLogging() {}

  void send_response();
};

class StatBucket : public RGWStatBucket_ObjStore {
public:
  StatBucket() {}
  ~StatBucket() {}

  void send_response();
};

class GetBucketACLs : public RGWGetACLs_ObjStore {
public:
  GetBucketACLs() {}
  ~GetBucketACLs() {}

  void send_response();
};

class PutBucketACLs : public RGWPutACLs_ObjStore {
public:
  PutBucketACLs() {}
  ~PutBucketACLs() {}

  int get_policy_from_state(RGWRados *store, struct req_state *s, stringstream& ss);
  void send_response();
};

class GetBucketCORS : public RGWGetCORS_ObjStore {
public:
  GetBucketCORS() {}
  ~GetBucketCORS() {}

  void send_response();
};

class PutBucketCORS : public RGWPutCORS_ObjStore {
public:
  PutBucketCORS() {}
  ~PutBucketCORS() {}

  int get_params();
  void send_response();
};

class BucketHandler : public Handler {
public:
  BucketHandler() {}
  virtual ~BucketHandler() {}
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
