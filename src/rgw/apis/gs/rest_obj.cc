#include "common/ceph_json.h"
#include "rgw/rgw_client_io.h"

#include "rest_obj.h"

#define dout_subsys ceph_subsys_rgw
#undef dout_prefix
#define dout_prefix *_dout << "(rgw:api:gs) "

namespace rgw { namespace api { namespace gs {

extern int create_gs_policy(struct req_state *s, RGWRados *store, RGWAccessControlPolicy_GS& gspolicy);

struct response_attr_param {
  const char *param;
  const char *http_attr;
};

static struct response_attr_param resp_attr_params[] = {
  {"response-content-type", "Content-Type"},
  {"response-content-language", "Content-Language"},
//  {"response-expires", "Expires"},
  {"response-cache-control", "Cache-Control"},
  {"response-content-disposition", "Content-Disposition"},
  {"response-content-encoding", "Content-Encoding"},
  {NULL, NULL},
};

void RGWGetObjACLs_ObjStore_GS::send_response()
{
  if (ret)
    set_req_state_err(s, ret);
  dump_errno(s);
  end_header(s, "application/xml");
  dump_start(s);
  s->cio->write(acls.c_str(), acls.size());
}

int RGWPutObjACLs_ObjStore_GS::get_policy_from_state(RGWRados *store, struct req_state *s, stringstream& ss)
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

void RGWGetObjCORS_ObjStore_GS::send_response()
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

int RGWPutObjCORS_ObjStore_GS::get_params()
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

void RGWPutObjCORS_ObjStore_GS::send_response()
{
  if (ret)
    set_req_state_err(s, ret);
  dump_errno(s);
  end_header(s, "application/xml");
  dump_start(s);
}

void RGWPutObjACLs_ObjStore_GS::send_response()
{
  if (ret)
    set_req_state_err(s, ret);
  dump_errno(s);
  end_header(s, "application/xml");
  dump_start(s);
}



int RGWPutObj_ObjStore_GS::get_params()
{
  RGWAccessControlPolicy_GS gspolicy(s->cct);
  if (!s->length)
    return -ERR_LENGTH_REQUIRED;

  int r = create_gs_policy(s, store, gspolicy);
  if (r < 0)
    return r;

  policy = gspolicy;

  return RGWPutObj_ObjStore::get_params();
}

void RGWPutObj_ObjStore_GS::send_response()
{
  if (ret) {
    set_req_state_err(s, ret);
  } else {
    ret = 0;
    if (s->cct->_conf->rgw_gs_success_create_obj_status == 201)
      ret = STATUS_CREATED;
    if (s->cct->_conf->rgw_gs_success_create_obj_status == 204)
      ret = STATUS_NO_CONTENT;
    set_req_state_err(s, ret);
    dump_etag(s, etag.c_str());
    dump_content_length(s, 0);
  }
  if (s->system_request && mtime) {
    dump_epoch_header(s, "Rgwx-Mtime", mtime);
  }
  dump_errno(s);
  end_header(s);
}

int RGWGetObj_ObjStore_GS::send_response_data(bufferlist& bl, off_t bl_ofs, off_t bl_len)
{
  const char *content_type = NULL;
  string content_type_str;
  map<string, string> response_attrs;
  map<string, string>::iterator riter;
  bufferlist metadata_bl;

  if (ret)
    goto done;

  if (sent_header)
    goto send_data;

  if (range_str)
    dump_range(s, start, end, s->obj_size);

  if (s->system_request &&
      s->info.args.exists(RGW_SYS_PARAM_PREFIX "prepend-metadata")) {

    /* JSON encode object metadata */
    JSONFormatter jf;
    jf.open_object_section("obj_metadata");
    encode_json("attrs", attrs, &jf);
    encode_json("mtime", lastmod, &jf);
    jf.close_section();
    stringstream ss;
    jf.flush(ss);
    metadata_bl.append(ss.str());
    s->cio->print("Rgwx-Embedded-Metadata-Len: %lld\r\n", (long long)metadata_bl.length());
    total_len += metadata_bl.length();
  }

  if (s->system_request && lastmod) {
    /* we end up dumping mtime in two different methods, a bit redundant */
    dump_epoch_header(s, "Rgwx-Mtime", lastmod);
  }

  dump_content_length(s, total_len);
  dump_last_modified(s, lastmod);

  if (!ret) {
    map<string, bufferlist>::iterator iter = attrs.find(RGW_ATTR_ETAG);
    if (iter != attrs.end()) {
      bufferlist& bl = iter->second;
      if (bl.length()) {
        char *etag = bl.c_str();
        dump_etag(s, etag);
      }
    }

    for (struct response_attr_param *p = resp_attr_params; p->param; p++) {
      bool exists;
      string val = s->info.args.get(p->param, &exists);
      if (exists) {
        if (strcmp(p->param, "response-content-type") != 0) {
          response_attrs[p->http_attr] = val;
        } else {
          content_type_str = val;
          content_type = content_type_str.c_str();
        }
      }
    }

    for (iter = attrs.begin(); iter != attrs.end(); ++iter) {
      const char *name = iter->first.c_str();
      map<string, string>::iterator aiter = rgw_to_http_attrs.find(name);
      if (aiter != rgw_to_http_attrs.end()) {
        if (response_attrs.count(aiter->second) > 0) // was already overridden by a response param
          continue;

        if (aiter->first.compare(RGW_ATTR_CONTENT_TYPE) == 0) { // special handling for content_type
          if (!content_type)
            content_type = iter->second.c_str();
          continue;
              }
        response_attrs[aiter->second] = iter->second.c_str();
      } else {
        if (strncmp(name, RGW_ATTR_META_PREFIX, sizeof(RGW_ATTR_META_PREFIX)-1) == 0) {
          name += sizeof(RGW_ATTR_PREFIX) - 1;
          s->cio->print("%s: %s\r\n", name, iter->second.c_str());
        }
      }
    }
  }

done:
  set_req_state_err(s, (partial_content && !ret) ? STATUS_PARTIAL_CONTENT : ret);

  dump_errno(s);

  for (riter = response_attrs.begin(); riter != response_attrs.end(); ++riter) {
    s->cio->print("%s: %s\n", riter->first.c_str(), riter->second.c_str());
  }

  if (!content_type)
    content_type = "binary/octet-stream";
  end_header(s, content_type);

  if (metadata_bl.length()) {
    s->cio->write(metadata_bl.c_str(), metadata_bl.length());
  }
  sent_header = true;

send_data:
  if (get_data && !ret) {
    int r = s->cio->write(bl.c_str() + bl_ofs, bl_len);
    if (r < 0)
      return r;
  }

  return 0;
}

int RGWStatObj_ObjStore_GS::send_response_data(bufferlist& bl, off_t bl_ofs, off_t bl_len)
{
  const char *content_type = NULL;
  string content_type_str;
  map<string, string> response_attrs;
  map<string, string>::iterator riter;
  bufferlist metadata_bl;

  if (range_str)
    dump_range(s, start, end, s->obj_size);

  dump_content_length(s, total_len);
  dump_last_modified(s, lastmod);

  /* Etag */
  map<string, bufferlist>::iterator iter = attrs.find(RGW_ATTR_ETAG);
  if (iter != attrs.end()) {
    bufferlist& bl = iter->second;
    if (bl.length()) {
      char *etag = bl.c_str();
      dump_etag(s, etag);
    }
  }

  /* Content type */
  for (struct response_attr_param *p = resp_attr_params; p->param; p++) {
    bool exists;
    string val = s->info.args.get(p->param, &exists);
    if (exists) {
      if (strcmp(p->param, "response-content-type") != 0) {
        response_attrs[p->http_attr] = val;
      } else {
        content_type_str = val;
        content_type = content_type_str.c_str();
      }
    }
  }

  /* attrs (may override content-type) */
  for (iter = attrs.begin(); iter != attrs.end(); ++iter) {
    const char *name = iter->first.c_str();
    map<string, string>::iterator aiter = rgw_to_http_attrs.find(name);
    if (aiter != rgw_to_http_attrs.end()) {
      if (response_attrs.count(aiter->second) > 0) // was already overridden by a response param
        continue;

      if (aiter->first.compare(RGW_ATTR_CONTENT_TYPE) == 0) { // special handling for content_type
        if (!content_type)
          content_type = iter->second.c_str();
        continue;
      }
      response_attrs[aiter->second] = iter->second.c_str();
    } else {
      if (strncmp(name, RGW_ATTR_META_PREFIX, sizeof(RGW_ATTR_META_PREFIX)-1) == 0) {
        name += sizeof(RGW_ATTR_PREFIX) - 1;
        s->cio->print("%s: %s\r\n", name, iter->second.c_str());
      }
    }
  }

  set_req_state_err(s, ret);
  dump_errno(s);

  for (riter = response_attrs.begin(); riter != response_attrs.end(); ++riter) {
    s->cio->print("%s: %s\n", riter->first.c_str(), riter->second.c_str());
  }

  if (!content_type)
    content_type = "binary/octet-stream";
  end_header(s, content_type);

  if (metadata_bl.length()) {
    s->cio->write(metadata_bl.c_str(), metadata_bl.length());
  }

  return 0;
}

void RGWDeleteObj_ObjStore_GS::send_response()
{
  int r = ret;
  if (r == -ENOENT)
    r = 0;
  if (!r)
    r = STATUS_NO_CONTENT;

  set_req_state_err(s, r);
  dump_errno(s);
  end_header(s);
}

int RGWCopyObj_ObjStore_GS::init_dest_policy()
{
  RGWAccessControlPolicy_GS gspolicy(s->cct);

  /* build a policy for the target object */
  int r = create_gs_policy(s, store, gspolicy);
  if (r < 0)
    return r;

  dest_policy = gspolicy;

  return 0;
}

int RGWCopyObj_ObjStore_GS::get_params()
{
  if_mod = s->info.env->get("HTTP_X_GOOG_COPY_SOURCE_IF_MODIFIED_SINCE");
  if_unmod = s->info.env->get("HTTP_X_GOOG_COPY_SOURCE_IF_UNMODIFIED_SINCE");
  if_match = s->info.env->get("HTTP_X_GOOG_COPY_SOURCE_IF_MATCH");
  if_nomatch = s->info.env->get("HTTP_X_GOOG_COPY_SOURCE_IF_NONE_MATCH");

  const char *req_src = s->copy_source;
  if (!req_src) {
    ldout(s->cct, 0) << "copy source is NULL" << dendl;
    return -EINVAL;
  }

  ret = parse_copy_location(req_src, src_bucket_name, src_object);
  if (!ret) {
    ldout(s->cct, 0) << "failed to parse copy location" << dendl;
    return -EINVAL;
  }

  dest_bucket_name = s->bucket.name;
  dest_object = s->object_str;

  if (s->system_request) {
    source_zone = s->info.args.get(RGW_SYS_PARAM_PREFIX "source-zone");
    if (!source_zone.empty()) {
      client_id = s->info.args.get(RGW_SYS_PARAM_PREFIX "client-id");
      op_id = s->info.args.get(RGW_SYS_PARAM_PREFIX "op-id");

      if (client_id.empty() || op_id.empty()) {
        ldout(s->cct, 0) << RGW_SYS_PARAM_PREFIX "client-id or " RGW_SYS_PARAM_PREFIX "op-id were not provided, required for intra-region copy" << dendl;
        return -EINVAL;
      }
    }
  }

  const char *md_directive = s->info.env->get("HTTP_X_GOOG_METADATA_DIRECTIVE");
  if (md_directive) {
    if (strcasecmp(md_directive, "COPY") == 0) {
      replace_attrs = false;
    } else if (strcasecmp(md_directive, "REPLACE") == 0) {
      replace_attrs = true;
    } else if (!source_zone.empty()) {
      replace_attrs = false; // default for intra-region copy
    } else {
      ldout(s->cct, 0) << "invalid metadata directive" << dendl;
      return -EINVAL;
    }
  }

  if (source_zone.empty() &&
      (dest_bucket_name.compare(src_bucket_name) == 0) &&
      (dest_object.compare(src_object) == 0) &&
      !replace_attrs) {
    /* can only copy object into itself if replacing attrs */
    ldout(s->cct, 0) << "can't copy object into itself if not replacing attrs" << dendl;
    return -ERR_INVALID_REQUEST;
  }
  return 0;
}

void RGWCopyObj_ObjStore_GS::send_partial_response(off_t ofs)
{
  if (!sent_header) {
    if (ret)
    set_req_state_err(s, ret);
    dump_errno(s);

    end_header(s, "binary/octet-stream");
    if (ret == 0) {
      s->formatter->open_object_section("CopyObjectResult");
    }
    sent_header = true;
  } else {
    /* Send progress field. Note that this diverge from the original S3
     * spec. We do this in order to keep connection alive.
     */
    s->formatter->dump_int("Progress", (uint64_t)ofs);
  }
  rgw_flush_formatter(s, s->formatter);
}

void RGWCopyObj_ObjStore_GS::send_response()
{
  if (!sent_header)
    send_partial_response(0);

  if (ret == 0) {
    dump_time(s, "LastModified", &mtime);
    map<string, bufferlist>::iterator iter = attrs.find(RGW_ATTR_ETAG);
    if (iter != attrs.end()) {
      bufferlist& bl = iter->second;
      if (bl.length()) {
        char *etag = bl.c_str();
        s->formatter->dump_string("ETag", etag);
      }
    }
    s->formatter->close_section();
    rgw_flush_formatter_and_reset(s, s->formatter);
  }
}

RGWOp *RGWHandler_ObjStore_Obj_GS::op_get()
{
  if (is_acl_op())
    return new RGWGetObjACLs_ObjStore_GS;

  RGWGetObj_ObjStore_GS *get_obj_op = new RGWGetObj_ObjStore_GS;
  get_obj_op->set_get_data(true);
  //if (s->info.args.exists("generation"))
  //  get_obj_op->set_request_version(s->info.args.get("generation"))
  return get_obj_op;
}

RGWOp *RGWHandler_ObjStore_Obj_GS::op_put()
{
  //if (s->info.args.exists("generation"))
  //  set effective version id

  if (is_acl_op())
    return new RGWPutObjACLs_ObjStore_GS;
  if (!s->copy_source)
    return new RGWPutObj_ObjStore_GS;
  else
    return new RGWCopyObj_ObjStore_GS;
}

RGWOp *RGWHandler_ObjStore_Obj_GS::op_delete()
{
  //if (s->info.args.exists("generation"))
  //  set effective version id

  return new RGWDeleteObj_ObjStore_GS;
}


RGWOp *RGWHandler_ObjStore_Obj_GS::op_head()
{
  //if (s->info.args.exists("generation"))
  //  set effective version id

  return new RGWStatObj_ObjStore_GS;
}

RGWOp *RGWHandler_ObjStore_Obj_GS::op_post()
{
  // TODO: allow form posts
  // https://developers.google.com/storage/docs/reference-methods#postobject

  return NULL;
}

}}}
