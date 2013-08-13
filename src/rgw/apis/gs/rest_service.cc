#include "rest_service.h"

#define dout_subsys ceph_subsys_rgw
#undef dout_prefix
#define dout_prefix *_dout << "(rgw:api:gs) "

namespace rgw { namespace api { namespace gs {

static void __list_all_buckets_start(struct req_state *s)
{
  s->formatter->open_array_section_in_ns("ListAllMyBucketsResult",
            "http://s3.amazonaws.com/doc/2006-03-01/");
}

static void __list_all_buckets_end(struct req_state *s)
{
  s->formatter->close_section();
}

static void __dump_bucket(struct req_state *s, RGWBucketEnt& obj)
{
  s->formatter->open_object_section("Bucket");
  s->formatter->dump_string("Name", obj.bucket.name);
  dump_time(s, "CreationDate", &obj.creation_time);
  s->formatter->close_section();
}

RGWOp *ServiceHandler::op_get()
{
  return new ListBuckets;
}

void ListBuckets::send_response_begin(bool has_buckets)
{
  if (ret)
    set_req_state_err(s, ret);
  dump_errno(s);
  dump_start(s);
  end_header(s, "application/xml");

  if (!ret) {
    __list_all_buckets_start(s);
    dump_owner(s, s->user.user_id, s->user.display_name);
    s->formatter->open_array_section("Buckets");
    sent_data = true;
  }
}

void ListBuckets::send_response_data(RGWUserBuckets& buckets)
{
  if (!sent_data)
    return;

  map<string, RGWBucketEnt>& m = buckets.get_buckets();
  map<string, RGWBucketEnt>::iterator iter;

  for (iter = m.begin(); iter != m.end(); ++iter) {
    RGWBucketEnt obj = iter->second;
    __dump_bucket(s, obj);
  }
  rgw_flush_formatter(s, s->formatter);
}

void ListBuckets::send_response_end()
{
  if (sent_data) {
    s->formatter->close_section();
    __list_all_buckets_end(s);
    rgw_flush_formatter_and_reset(s, s->formatter);
  }
}

}}}
