#ifndef CEPH_RGW_PLUGIN_KEYSTONE_TOKEN_H
#define CEPH_RGW_PLUGIN_KEYSTONE_TOKEN_H

#include "include/types.h"
#include "include/str_list.h"
#include "common/ceph_json.h"
#include "common/Formatter.h"
#include "common/Clock.h"

#define BEGIN_CMS "-----BEGIN CMS-----"
#define END_CMS "-----END CMS-----"

namespace rgw { namespace plugins { namespace keystone {

class KeystoneToken {
public:
  class Metadata {
  public:
    bool is_admin;
    void decode_json(JSONObj *obj);
  };

  class Service {
  public:
    class Endpoint {
    public:
      string id;
      string admin_url;
      string public_url;
      string internal_url;
      string region;
      void decode_json(JSONObj *obj);
    };
    string type;
    string name;
    list<Endpoint> endpoints;
    void decode_json(JSONObj *obj);
  };

  class Token {
  public:
    class Tenant {
    public:
      string id;
      string name;
      string description;
      bool enabled;
      void decode_json(JSONObj *obj);
    };
    string id;
    time_t expires;
    Tenant tenant;
    void decode_json(JSONObj *obj);
  };

  class User {
  public:
    class Role {
    public:
      string id;
      string name;
      void decode_json(JSONObj *obj);
    };
    string id;
    string name;
    string user_name;
    list<Role> roles;
    void decode_json(JSONObj *obj);
    bool has_role(const string& r);
  };

  Metadata metadata;
  list<Service> service_catalog;
  Token token;
  User user;

public:
  KeystoneToken() { token.expires = 0; }
  int parse(CephContext *cct, bufferlist& bl);
  void decode_json(JSONObj *access_obj);

  bool expired() {
    uint64_t now = ceph_clock_now(NULL).sec();
    return (now < (uint64_t)token.expires);
  }
};

class KeystoneSignedEnveloppe {
public:
  string signed_certificate;
  string base64encoded;
  list<string> revoked_tokens;

public:
  KeystoneSignedEnveloppe() { };
  int parse(CephContext *cct, bufferlist& bl);
  void decode_json(JSONObj *o);
};

class KeystoneEC2Credentials {
public:
  class EC2Credential {
  public:
    string tenant;
    string access;
    string secret;
    void decode_json(JSONObj *obj);
  };

  string user_id;
  list<EC2Credential> ec2credentials;

public:
  KeystoneEC2Credentials() { };
  int parse(CephContext *cct, bufferlist& bl);
  void decode_json(JSONObj *o);
};

}}}

#endif /* CEPH_RGW_PLUGIN_KEYSTONE_TOKEN_H */
