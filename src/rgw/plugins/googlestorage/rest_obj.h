#ifndef CEPH_RGW_API_GS_REST_OBJ_H
#define CEPH_RGW_API_GS_REST_OBJ_H

#include "rgw_api_gs.h"

namespace rgw { namespace api { namespace gs {

class CopyObj : public RGWCopyObj_ObjStore {
  bool sent_header;
public:
  CopyObj() : sent_header(false) {}
  ~CopyObj() {}

  int init_dest_policy();
  int get_params();
  void send_partial_response(off_t ofs);
  void send_response();
};

class StatObj : public RGWGetObj_ObjStore {
public:
  StatObj() {}
  ~StatObj() {}

  int send_response_data(bufferlist& bl, off_t ofs, off_t len);
};

class DeleteObj : public RGWDeleteObj_ObjStore {
public:
  DeleteObj() {}
  ~DeleteObj() {}

  void send_response();
};

class GetObj : public RGWGetObj_ObjStore
{
public:
  GetObj() {}
  ~GetObj() {}

  int send_response_data(bufferlist& bl, off_t ofs, off_t len);
};

class PutObj : public RGWPutObj_ObjStore {
public:
  PutObj() {}
  ~PutObj() {}

  int get_params();
  void send_response();
};

class GetObjACLs : public RGWGetACLs_ObjStore {
public:
  GetObjACLs() {}
  ~GetObjACLs() {}

  void send_response();
};

class PutObjACLs : public RGWPutACLs_ObjStore {
public:
  PutObjACLs() {}
  ~PutObjACLs() {}

  int get_policy_from_state(RGWRados *store, struct req_state *s, stringstream& ss);
  void send_response();
};

class GetObjCORS : public RGWGetCORS_ObjStore {
public:
  GetObjCORS() {}
  ~GetObjCORS() {}

  void send_response();
};

class PutObjCORS : public RGWPutCORS_ObjStore {
public:
  PutObjCORS() {}
  ~PutObjCORS() {}

  int get_params();
  void send_response();
};

class ObjHandler : public Handler {
public:
  ObjHandler() {}
  virtual ~ObjHandler() {}
protected:
  bool is_acl_op() { return s->info.args.exists("acl"); }
  bool is_cors_op() { return s->info.args.exists("cors"); }
  RGWOp *op_get();
  RGWOp *op_head();
  RGWOp *op_put();
  RGWOp *op_post();
  RGWOp *op_delete();
};

}}}

#endif /* CEPH_RGW_API_GS_REST_OBJ_H */
