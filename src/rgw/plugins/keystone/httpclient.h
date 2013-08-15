#ifndef CEPH_RGW_PLUGIN_KEYSTONE_HTTPCLIENT_H
#define CEPH_RGW_PLUGIN_KEYSTONE_HTTPCLIENT_H

#include "include/types.h"
#include "include/str_list.h"
#include "rgw/rgw_http_client.h"

#include "token.h"

namespace rgw { namespace plugins { namespace keystone {

class KeystoneClient : public RGWHTTPClient {
protected:
  string dispatch_url;
  bufferlist rx_buffer;
  bufferlist tx_buffer;
  list<string> roles_list;

public:
  KeystoneClient(CephContext *_cct, string request_uri)
      : RGWHTTPClient(_cct) {
    get_str_list(cct->_conf->rgw_keystone_accepted_roles, roles_list);

    dispatch_url = cct->_conf->rgw_keystone_url;
    if (dispatch_url[dispatch_url.size() - 1] != '/')
      dispatch_url.append("/");
    dispatch_url.append(request_uri);

    append_header("X-Auth-Token", cct->_conf->rgw_keystone_admin_token);
  }
  virtual ~KeystoneClient() { };

  int receive_header(void*, size_t) { return 0; };

  int receive_data(void *ptr, size_t len) {
    rx_buffer.append((char *)ptr, len);
    return 0;
  }

  int send_data(void *ptr, size_t len) {
    if (tx_buffer.length() == 0)
      return 0;

    if (tx_buffer.length() <= len) {
      memcpy(ptr, tx_buffer.c_str(), tx_buffer.length());
      return tx_buffer.length();
    }

    memcpy(ptr, tx_buffer.c_str(), len);
    bufferlist new_tx_buffer;
    tx_buffer.copy(len, tx_buffer.length()-len, new_tx_buffer);
    tx_buffer = new_tx_buffer;
    return len;
  }

  void set_json_body(JSONFormatter *f);
  virtual int dispatch() = 0;

};

class KeystoneAuthClient : public KeystoneClient {
public:
  KeystoneToken response;
public:
  KeystoneAuthClient(CephContext *_cct, string request_uri)
      : KeystoneClient(_cct, request_uri) { };
  virtual int dispatch();
};

class KeystoneRevokedTokensClient : public KeystoneClient {
public:
  KeystoneSignedEnveloppe response;
public:
  KeystoneRevokedTokensClient(CephContext *_cct, string request_uri)
      : KeystoneClient(_cct, request_uri) { };
  virtual int dispatch();
};

}}}

#endif /* CEPH_RGW_PLUGIN_KEYSTONE_HTTPCLIENT_H */
