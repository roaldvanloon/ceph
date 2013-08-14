#ifndef CEPH_RGW_API_GS_REST_SERVICE_H
#define CEPH_RGW_API_GS_REST_SERVICE_H

#include "rgw_api_gs.h"

namespace rgw { namespace api { namespace gs {

class ListBuckets : public RGWListBuckets_ObjStore {
public:
  ListBuckets() {}
  ~ListBuckets() {}

  int get_params() {
    limit = 0; /* no limit */
    return 0;
  }
  virtual void send_response_begin(bool has_buckets);
  virtual void send_response_data(RGWUserBuckets& buckets);
  virtual void send_response_end();
};

class ServiceHandler : public Handler {
public:
  ServiceHandler() {}
  virtual ~ServiceHandler() {}
protected:
  RGWOp *op_get();
};

}}}

#endif /* CEPH_RGW_API_GS_REST_SERVICE_H */
