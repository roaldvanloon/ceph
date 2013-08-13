#ifndef CEPH_RGW_API_GS_REST_SERVICE_H
#define CEPH_RGW_API_GS_REST_SERVICE_H

#include "rgw_api_gs.h"

namespace rgw { namespace api { namespace gs {

class RGWListBuckets_ObjStore_GS : public RGWListBuckets_ObjStore {
public:
  RGWListBuckets_ObjStore_GS() {}
  ~RGWListBuckets_ObjStore_GS() {}

  int get_params() {
    limit = 0; /* no limit */
    return 0;
  }
  virtual void send_response_begin(bool has_buckets);
  virtual void send_response_data(RGWUserBuckets& buckets);
  virtual void send_response_end();
};

class RGWHandler_ObjStore_Service_GS : public RGWHandler_ObjStore_GS {
public:
  RGWHandler_ObjStore_Service_GS() {}
  virtual ~RGWHandler_ObjStore_Service_GS() {}
protected:
  RGWOp *op_get();
};

}}}

#endif /* CEPH_RGW_API_GS_REST_SERVICE_H */
