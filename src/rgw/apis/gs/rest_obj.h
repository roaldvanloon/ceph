#ifndef CEPH_RGW_API_GS_REST_OBJ_H
#define CEPH_RGW_API_GS_REST_OBJ_H

#include "rgw_api_gs.h"

namespace rgw { namespace api { namespace gs {

class RGWCopyObj_ObjStore_GS : public RGWCopyObj_ObjStore {
  bool sent_header;
public:
  RGWCopyObj_ObjStore_GS() : sent_header(false) {}
  ~RGWCopyObj_ObjStore_GS() {}

  int init_dest_policy();
  int get_params();
  void send_partial_response(off_t ofs);
  void send_response();
};

class RGWStatObj_ObjStore_GS : public RGWGetObj_ObjStore {
public:
  RGWStatObj_ObjStore_GS() {}
  ~RGWStatObj_ObjStore_GS() {}

  int send_response_data(bufferlist& bl, off_t ofs, off_t len);
};

class RGWDeleteObj_ObjStore_GS : public RGWDeleteObj_ObjStore {
public:
  RGWDeleteObj_ObjStore_GS() {}
  ~RGWDeleteObj_ObjStore_GS() {}

  void send_response();
};

class RGWGetObj_ObjStore_GS : public RGWGetObj_ObjStore
{
public:
  RGWGetObj_ObjStore_GS() {}
  ~RGWGetObj_ObjStore_GS() {}

  int send_response_data(bufferlist& bl, off_t ofs, off_t len);
};

class RGWPutObj_ObjStore_GS : public RGWPutObj_ObjStore {
public:
  RGWPutObj_ObjStore_GS() {}
  ~RGWPutObj_ObjStore_GS() {}

  int get_params();
  void send_response();
};

class RGWGetObjACLs_ObjStore_GS : public RGWGetACLs_ObjStore {
public:
  RGWGetObjACLs_ObjStore_GS() {}
  ~RGWGetObjACLs_ObjStore_GS() {}

  void send_response();
};

class RGWPutObjACLs_ObjStore_GS : public RGWPutACLs_ObjStore {
public:
  RGWPutObjACLs_ObjStore_GS() {}
  ~RGWPutObjACLs_ObjStore_GS() {}

  int get_policy_from_state(RGWRados *store, struct req_state *s, stringstream& ss);
  void send_response();
};

class RGWGetObjCORS_ObjStore_GS : public RGWGetCORS_ObjStore {
public:
  RGWGetObjCORS_ObjStore_GS() {}
  ~RGWGetObjCORS_ObjStore_GS() {}

  void send_response();
};

class RGWPutObjCORS_ObjStore_GS : public RGWPutCORS_ObjStore {
public:
  RGWPutObjCORS_ObjStore_GS() {}
  ~RGWPutObjCORS_ObjStore_GS() {}

  int get_params();
  void send_response();
};

class RGWHandler_ObjStore_Obj_GS : public RGWHandler_ObjStore_GS {
public:
  RGWHandler_ObjStore_Obj_GS() {}
  virtual ~RGWHandler_ObjStore_Obj_GS() {}
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
