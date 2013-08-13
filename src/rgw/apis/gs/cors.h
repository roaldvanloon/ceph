#ifndef CEPH_RGW_APIS_GS_CORS_H
#define CEPH_RGW_APIS_GS_CORS_H

#include <map>
#include <string>
#include <iostream>
#include <expat.h>
#include <include/types.h>

#include "common/Formatter.h"
#include "rgw/rgw_xml.h"
#include "rgw/rgw_cors.h"

#define dout_subsys ceph_subsys_rgw

namespace rgw { namespace api { namespace gs {

class RGWCORSRule_GS : public RGWCORSRule, public XMLObj
{
  public:
    RGWCORSRule_GS() {}
    ~RGWCORSRule_GS() {}
    
    bool xml_end(const char *el);
    void to_xml(XMLFormatter& f);
};

class RGWCORSConfiguration_GS : public RGWCORSConfiguration, public XMLObj
{
  public:
    RGWCORSConfiguration_GS() {}
    ~RGWCORSConfiguration_GS() {}

    bool xml_end(const char *el);
    void to_xml(ostream& out);
};

class RGWCORSXMLParser_GS : public RGWXMLParser
{
  CephContext *cct;

  XMLObj *alloc_obj(const char *el);
public:
  RGWCORSXMLParser_GS(CephContext *_cct) : cct(_cct) {}
};

}}}

#endif /* CEPH_RGW_APIS_GS_CORS_H */
