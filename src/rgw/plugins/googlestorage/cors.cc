#include <string.h>
#include <limits.h>
#include <iostream>
#include <map>

#include "include/types.h"
#include "rgw/rgw_user.h"

#include "cors.h"

#define dout_subsys ceph_subsys_rgw
#undef dout_prefix
#define dout_prefix *_dout << "(rgw:api:gs) "

namespace rgw { namespace api { namespace gs {

void CORSRule::to_xml(XMLFormatter& f) {

  f.open_object_section("CORSRule");
  /*ID if present*/
  if (id.length() > 0) {
    f.dump_string("ID", id);;
  }
  /*AllowedMethods*/
  if (allowed_methods & RGW_CORS_GET)
    f.dump_string("AllowedMethod", "GET");
  if (allowed_methods & RGW_CORS_PUT)
    f.dump_string("AllowedMethod", "PUT");
  if (allowed_methods & RGW_CORS_DELETE)
    f.dump_string("AllowedMethod", "DELETE");
  if (allowed_methods & RGW_CORS_HEAD)
    f.dump_string("AllowedMethod", "HEAD");
  if (allowed_methods & RGW_CORS_POST)
    f.dump_string("AllowedMethod", "POST");
  /*AllowedOrigins*/
  for(set<string>::iterator it = allowed_origins.begin(); 
      it != allowed_origins.end(); 
      ++it) {
    string host = *it;
    f.dump_string("AllowedOrigin", host);
  }
  /*AllowedHeader*/
  for(set<string>::iterator it = allowed_hdrs.begin(); 
      it != allowed_hdrs.end(); ++it) {
    f.dump_string("AllowedHeader", *it);
  }
  /*MaxAgeSeconds*/
  if (max_age != CORS_MAX_AGE_INVALID) {
    f.dump_unsigned("MaxAgeSeconds", max_age);
  }
  /*ExposeHeader*/
  for(list<string>::iterator it = exposable_hdrs.begin(); 
      it != exposable_hdrs.end(); ++it) {
    f.dump_string("ExposeHeader", *it);
  }
  f.close_section();
}

bool CORSRule::xml_end(const char *el) {
  XMLObjIter iter = find("AllowedMethod");
  XMLObj *obj;
  /*Check all the allowedmethods*/
  obj = iter.get_next();
  if (obj) {
    for( ; obj; obj = iter.get_next()) {
      const char *s = obj->get_data().c_str();
      dout(10) << "RGWCORSRule::xml_end, el : " << el << ", data : " << s << dendl;
      if (strcasecmp(s, "GET") == 0) {
        allowed_methods |= RGW_CORS_GET;
      } else if (strcasecmp(s, "POST") == 0) {
        allowed_methods |= RGW_CORS_POST;
      } else if (strcasecmp(s, "DELETE") == 0) {
        allowed_methods |= RGW_CORS_DELETE;
      } else if (strcasecmp(s, "HEAD") == 0) {
        allowed_methods |= RGW_CORS_HEAD;
      } else if (strcasecmp(s, "PUT") == 0) {
        allowed_methods |= RGW_CORS_PUT;
      } else {
        return false;
      }
    }
  } 
  /*Check the id's len, it should be less than 255*/
  XMLObj *xml_id = find_first("ID");
  if (xml_id != NULL) {
    string data = xml_id->get_data();
    if (data.length() > 255) {
      dout(0) << "RGWCORSRule has id of length greater than 255" << dendl;
      return false;
    }
    dout(10) << "RGWCORRule id : " << data << dendl;  
    id = data;
  }
  /*Check if there is atleast one AllowedOrigin*/
  iter = find("AllowedOrigin");
  if (!(obj = iter.get_next())) {
    dout(0) << "RGWCORSRule does not have even one AllowedOrigin" << dendl;
    return false;
  }
  for( ; obj; obj = iter.get_next()) {
    dout(10) << "RGWCORSRule - origin : " << obj->get_data() << dendl;
    /*Just take the hostname*/
    string host = obj->get_data();
    if (validate_name_string(host) != 0)
      return false;
    allowed_origins.insert(allowed_origins.end(), host);
  }
  /*Check of max_age*/
  iter = find("MaxAgeSeconds");
  if ((obj = iter.get_next())) {
    char *end = NULL;

    unsigned long long ull = strtoull(obj->get_data().c_str(), &end, 10);
    if (ull >= 0x100000000ull) {
      max_age = CORS_MAX_AGE_INVALID;
    } else  {
      max_age = (uint32_t)ull;
    }
    dout(10) << "RGWCORSRule : max_age : " << max_age << dendl;
  }
  /*Check and update ExposeHeader*/
  iter = find("ExposeHeader");
  if ((obj = iter.get_next())) {
    for(; obj; obj = iter.get_next()) {
      dout(10) << "RGWCORSRule - exp_hdr : " << obj->get_data() << dendl;
      exposable_hdrs.push_back(obj->get_data());
    }
  }
  /*Check and update AllowedHeader*/
  iter = find("AllowedHeader");
  if ((obj = iter.get_next())) {
    for(; obj; obj = iter.get_next()) {
      dout(10) << "RGWCORSRule - allowed_hdr : " << obj->get_data() << dendl;
      string s = obj->get_data();
      if (validate_name_string(s) != 0)
         return false;
      allowed_hdrs.insert(allowed_hdrs.end(), s);
    }
  }
  return true;
}

void CORSConfiguration::to_xml(ostream& out) {
  XMLFormatter f;
  f.open_object_section("CORSConfiguration");
  for(list<RGWCORSRule>::iterator it = rules.begin();
      it != rules.end(); ++it) {
    (static_cast<CORSRule &>(*it)).to_xml(f);
  }
  f.close_section();
  f.flush(out);
}

bool CORSConfiguration::xml_end(const char *el) {
  XMLObjIter iter = find("CORSRule");
  CORSRule *obj;
  if (!(obj = static_cast<CORSRule *>(iter.get_next()))) {
    dout(0) << "CORSConfiguration should have atleast one CORSRule" << dendl;
    return false;
  }
  for(; obj; obj = static_cast<CORSRule *>(iter.get_next())) {
    rules.push_back(*obj);
  }
  return true;
}

XMLObj *CORSXMLParser::alloc_obj(const char *el) {
  if (strcmp(el, "CORSConfiguration") == 0) {
    return new CORSConfiguration;
  } else if (strcmp(el, "CORSRule") == 0) {
    return new CORSRule;
  } else if (strcmp(el, "ID") == 0) {
    return new CORSRuleID;
  } else if (strcmp(el, "AllowedOrigin") == 0) {
    return new CORSRuleAllowedOrigin;
  } else if (strcmp(el, "AllowedMethod") == 0) {
    return new CORSRuleAllowedMethod;
  } else if (strcmp(el, "AllowedHeader") == 0) {
    return new CORSRuleAllowedHeader;
  } else if (strcmp(el, "MaxAgeSeconds") == 0) {
    return new CORSRuleMaxAgeSeconds;
  } else if (strcmp(el, "ExposeHeader")  == 0) {
    return new CORSRuleExposeHeader;
  }
  return NULL;
}

}}}
