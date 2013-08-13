#include "rgw_api_gs.h"
#include "rest_service.h"
#include "rest_bucket.h"
#include "rest_obj.h"

#define dout_subsys ceph_subsys_rgw
#undef dout_prefix
#define dout_prefix *_dout << "(rgw:api:gs) "

namespace rgw { namespace api { namespace gs {


RGWHandler *RGWRESTMgr_GS::get_handler(struct req_state *s)
{
  int ret = RGWHandler_ObjStore_GS::init_from_header(s, RGW_FORMAT_XML, false);
  if (ret < 0)
    return NULL;

  if (!s->bucket_name)
    return new RGWHandler_ObjStore_Service_GS;

  if (!s->object)
    return new RGWHandler_ObjStore_Bucket_GS;

  return new RGWHandler_ObjStore_Obj_GS;
}

}}}
