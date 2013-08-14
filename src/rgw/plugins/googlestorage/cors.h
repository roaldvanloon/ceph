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

class CORSRule : public RGWCORSRule, public XMLObj
{
  public:
    CORSRule() {}
    ~CORSRule() {}
    
    bool xml_end(const char *el);
    void to_xml(XMLFormatter& f);
};

class CORSConfiguration : public RGWCORSConfiguration, public XMLObj
{
  public:
    CORSConfiguration() {}
    ~CORSConfiguration() {}

    bool xml_end(const char *el);
    void to_xml(ostream& out);
};

class CORSXMLParser : public RGWXMLParser
{
  CephContext *cct;

  XMLObj *alloc_obj(const char *el);
public:
  CORSXMLParser(CephContext *_cct) : cct(_cct) {}
};

class CORSRuleID : public XMLObj {
  public:
    CORSRuleID() {}
    ~CORSRuleID() {}
};

class CORSRuleAllowedOrigin : public XMLObj {
  public:
    CORSRuleAllowedOrigin() {}
    ~CORSRuleAllowedOrigin() {}
};

class CORSRuleAllowedMethod : public XMLObj {
  public:
    CORSRuleAllowedMethod() {}
    ~CORSRuleAllowedMethod() {}
};

class CORSRuleAllowedHeader : public XMLObj {
  public:
    CORSRuleAllowedHeader() {}
    ~CORSRuleAllowedHeader() {}
};

class CORSRuleMaxAgeSeconds : public XMLObj {
  public:
    CORSRuleMaxAgeSeconds() {}
    ~CORSRuleMaxAgeSeconds() {}
};

class CORSRuleExposeHeader : public XMLObj {
  public:
    CORSRuleExposeHeader() {}
    ~CORSRuleExposeHeader() {}
};

}}}

#endif /* CEPH_RGW_APIS_GS_CORS_H */
