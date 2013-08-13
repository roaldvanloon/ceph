#include "common/ceph_json.h"
#include "rgw/rgw_client_io.h"

#include "rest_bucket.h"

#define dout_subsys ceph_subsys_rgw
#undef dout_prefix
#define dout_prefix *_dout << "(rgw:api:gs) "

namespace rgw { namespace api { namespace gs {

extern int create_gs_policy(struct req_state *s, RGWRados *store, RGWAccessControlPolicy_GS& gspolicy);

int RGWListBucket_ObjStore_GS::get_params()
{
  prefix = s->info.args.get("prefix");
  marker = s->info.args.get("marker");
  max_keys = s->info.args.get("max-keys");
  ret = parse_max_keys();
  if (ret < 0) {
    return ret;
  }
  delimiter = s->info.args.get("delimiter");
  return 0;
}

void RGWListBucket_ObjStore_GS::send_response()
{
  if (ret < 0)
    set_req_state_err(s, ret);
  dump_errno(s);

  end_header(s, "application/xml");
  dump_start(s);
  if (ret < 0)
    return;

  s->formatter->open_object_section_in_ns("ListBucketResult",
            "http://doc.s3.amazonaws.com/2006-03-01");
  s->formatter->dump_string("Name", s->bucket_name);
  if (!prefix.empty())
    s->formatter->dump_string("Prefix", prefix);
  s->formatter->dump_string("Marker", marker);
  s->formatter->dump_int("MaxKeys", max);
  if (!delimiter.empty())
    s->formatter->dump_string("Delimiter", delimiter);

  s->formatter->dump_string("IsTruncated", (max && is_truncated ? "true" : "false"));

  if (ret >= 0) {
    vector<RGWObjEnt>::iterator iter;
    for (iter = objs.begin(); iter != objs.end(); ++iter) {
      s->formatter->open_array_section("Contents");
      s->formatter->dump_string("Key", iter->name);
      time_t mtime = iter->mtime.sec();
      dump_time(s, "LastModified", &mtime);
      s->formatter->dump_format("ETag", "\"%s\"", iter->etag.c_str());
      s->formatter->dump_int("Size", iter->size);
      s->formatter->dump_string("StorageClass", "STANDARD");
      dump_owner(s, iter->owner, iter->owner_display_name);
      s->formatter->close_section();
    }
    if (common_prefixes.size() > 0) {
      map<string, bool>::iterator pref_iter;
      for (pref_iter = common_prefixes.begin(); pref_iter != common_prefixes.end(); ++pref_iter) {
        s->formatter->open_array_section("CommonPrefixes");
        s->formatter->dump_string("Prefix", pref_iter->first);
        s->formatter->close_section();
      }
    }
  }
  s->formatter->close_section();
  rgw_flush_formatter_and_reset(s, s->formatter);
}

int RGWCreateBucket_ObjStore_GS::get_params()
{
  RGWAccessControlPolicy_GS gspolicy(s->cct);

  int r = create_gs_policy(s, store, gspolicy);
  if (r < 0)
    return r;

  policy = gspolicy;

  int len = 0;
  char *data;
#define CREATE_BUCKET_MAX_REQ_LEN (512 * 1024) /* this is way more than enough */
  ret = rgw_rest_read_all_input(s, &data, &len, CREATE_BUCKET_MAX_REQ_LEN);
  if ((ret < 0) && (ret != -ERR_LENGTH_REQUIRED))
    return ret;

  bufferptr in_ptr(data, len);
  in_data.append(in_ptr);

  if (len) {
    RGWCreateBucketParser parser;

    if (!parser.init()) {
      ldout(s->cct, 0) << "ERROR: failed to initialize parser" << dendl;
      return -EIO;
    }

    bool success = parser.parse(data, len, 1);
    ldout(s->cct, 20) << "create bucket input data=" << data << dendl;

    if (!success) {
      ldout(s->cct, 0) << "failed to parse input: " << data << dendl;
      free(data);
      return -EINVAL;
    }
    free(data);

    if (!parser.get_location_constraint(location_constraint)) {
      ldout(s->cct, 0) << "provided input did not specify location constraint correctly" << dendl;
      return -EINVAL;
    }

    ldout(s->cct, 10) << "create bucket location constraint: " << location_constraint << dendl;
  }

  int pos = location_constraint.find(':');
  if (pos >= 0) {
    placement_rule = location_constraint.substr(pos + 1);
    location_constraint = location_constraint.substr(0, pos);
  }

  return 0;
}

void RGWCreateBucket_ObjStore_GS::send_response()
{
  if (ret == -ERR_BUCKET_EXISTS)
    ret = 0;
  if (ret)
    set_req_state_err(s, ret);
  dump_errno(s);
  end_header(s);

  if (ret < 0)
    return;

  if (s->system_request) {
    JSONFormatter f; /* use json formatter for system requests output */

    f.open_object_section("info");
    encode_json("entry_point_object_ver", ep_objv, &f);
    encode_json("object_ver", info.objv_tracker.read_version, &f);
    encode_json("bucket_info", info, &f);
    f.close_section();
    rgw_flush_formatter_and_reset(s, &f);
  }
}

void RGWDeleteBucket_ObjStore_GS::send_response()
{
  int r = ret;
  if (!r)
    r = STATUS_NO_CONTENT;

  set_req_state_err(s, r);
  dump_errno(s);
  end_header(s);

  if (s->system_request) {
    JSONFormatter f; /* use json formatter for system requests output */

    f.open_object_section("info");
    encode_json("object_ver", objv_tracker.read_version, &f);
    f.close_section();
    rgw_flush_formatter_and_reset(s, &f);
  }
}

void RGWGetBucketLogging_ObjStore_GS::send_response()
{
  dump_errno(s);
  end_header(s, "application/xml");
  dump_start(s);

  s->formatter->open_object_section_in_ns("BucketLoggingStatus",
            "http://doc.s3.amazonaws.com/2006-03-01");
  s->formatter->close_section();
  rgw_flush_formatter_and_reset(s, s->formatter);
}

static void dump_bucket_metadata(struct req_state *s, RGWBucketEnt& bucket)
{
  char buf[32];
  snprintf(buf, sizeof(buf), "%lld", (long long)bucket.count);
  s->cio->print("X-RGW-Object-Count: %s\n", buf);
  snprintf(buf, sizeof(buf), "%lld", (long long)bucket.size);
  s->cio->print("X-RGW-Bytes-Used: %s\n", buf);
}

void RGWStatBucket_ObjStore_GS::send_response()
{
  if (ret >= 0) {
    dump_bucket_metadata(s, bucket);
  }

  set_req_state_err(s, ret);
  dump_errno(s);

  end_header(s);
  dump_start(s);
}

void RGWGetBucketACLs_ObjStore_GS::send_response()
{
  if (ret)
    set_req_state_err(s, ret);
  dump_errno(s);
  end_header(s, "application/xml");
  dump_start(s);
  s->cio->write(acls.c_str(), acls.size());
}

int RGWPutBucketACLs_ObjStore_GS::get_policy_from_state(RGWRados *store, struct req_state *s, stringstream& ss)
{
  RGWAccessControlPolicy_GS gspolicy(s->cct);

  // bucket-* canned acls do not apply to bucket
  if (s->object_str.empty()) {
    if (s->canned_acl.find("bucket") != string::npos)
      s->canned_acl.clear();
  }

  int r = create_gs_policy(s, store, gspolicy);
  if (r < 0)
    return r;

  gspolicy.to_xml(ss);

  return 0;
}

void RGWPutBucketACLs_ObjStore_GS::send_response()
{
  if (ret)
    set_req_state_err(s, ret);
  dump_errno(s);
  end_header(s, "application/xml");
  dump_start(s);
}

void RGWGetBucketCORS_ObjStore_GS::send_response()
{
  if (ret) {
    if (ret == -ENOENT)
      set_req_state_err(s, ERR_NOT_FOUND);
    else
      set_req_state_err(s, ret);
  }
  dump_errno(s);
  end_header(s, "application/xml");
  dump_start(s);
  if (!ret) {
    string cors;
    RGWCORSConfiguration_GS *gscors = static_cast<RGWCORSConfiguration_GS *>(&bucket_cors);
    stringstream ss;

    gscors->to_xml(ss);
    cors = ss.str();
    s->cio->write(cors.c_str(), cors.size());
  }
}

int RGWPutBucketCORS_ObjStore_GS::get_params()
{
  int r;
  char *data = NULL;
  int len = 0;
  size_t cl = 0;
  RGWCORSXMLParser_GS parser(s->cct);
  RGWCORSConfiguration_GS *cors_config;

  if (s->length)
    cl = atoll(s->length);
  if (cl) {
    data = (char *)malloc(cl + 1);
    if (!data) {
       r = -ENOMEM;
       goto done_err;
    }
    int read_len;
    r = s->cio->read(data, cl, &read_len);
    len = read_len;
    if (r < 0)
      goto done_err;
    data[len] = '\0';
  } else {
    len = 0;
  }

  if (!parser.init()) {
    r = -EINVAL;
    goto done_err;
  }

  if (!parser.parse(data, len, 1)) {
    r = -EINVAL;
    goto done_err;
  }
  cors_config = static_cast<RGWCORSConfiguration_GS *>(parser.find_first("CORSConfiguration"));
  if (!cors_config) {
    r = -EINVAL;
    goto done_err;
  }

  if (s->cct->_conf->subsys.should_gather(ceph_subsys_rgw, 15)) {
    ldout(s->cct, 15) << "CORSConfiguration";
    cors_config->to_xml(*_dout);
    *_dout << dendl;
  }

  cors_config->encode(cors_bl);

  free(data);
  return 0;
done_err:
  free(data);
  return r;
}

void RGWPutBucketCORS_ObjStore_GS::send_response()
{
  if (ret)
    set_req_state_err(s, ret);
  dump_errno(s);
  end_header(s, "application/xml");
  dump_start(s);
}

RGWOp *RGWHandler_ObjStore_Bucket_GS::op_get()
{
  //if (is_versioning_op())
  //  return new RGWGetVersioning_ObjStore_GS;
  //if (is_lifecycle_op())
  //  return new RGWGetLifecycle_ObjStore_GS;
  if (is_logging_op())
    return new RGWGetBucketLogging_ObjStore_GS;
  if (is_acl_op())
    return new RGWGetBucketACLs_ObjStore_GS;
  if (is_cors_op())
    return new RGWGetBucketCORS_ObjStore_GS;
  return new RGWListBucket_ObjStore_GS;
}

RGWOp *RGWHandler_ObjStore_Bucket_GS::op_put()
{
  //if (is_websiteconfig_op())
  //  return new RGWPutWebsiteConfig_ObjStore_GS;
  //if (is_versioning_op())
  //  return new RGWPutVersioning_ObjStore_GS;
  //if (is_lifecycle_op())
  //  return new RGWPutLifecycle_ObjStore_GS;
  //if (is_logging_op())
  //  return new RGWPutBucketLogging_ObjStore_GS;
  if (is_acl_op())
    return new RGWPutBucketACLs_ObjStore_GS;
  if (is_cors_op())
    return new RGWPutBucketCORS_ObjStore_GS;
  return new RGWCreateBucket_ObjStore_GS;
}

RGWOp *RGWHandler_ObjStore_Bucket_GS::op_delete()
{
  return new RGWDeleteBucket_ObjStore_GS;
}

}}}
