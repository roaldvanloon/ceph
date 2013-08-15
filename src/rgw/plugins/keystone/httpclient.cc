#include "httpclient.h"

#define dout_subsys ceph_subsys_rgw
#undef dout_prefix
#define dout_prefix *_dout << "(rgw:plugin:keystone) "

namespace rgw { namespace plugins { namespace keystone {

void KeystoneClient::set_json_body(JSONFormatter *f) {
  append_header("Content-Type", "application/json");
  std::stringstream os;
  f->flush(os);
  tx_buffer.append(os.str());
  set_send_length(tx_buffer.length());
}

int KeystoneAuthClient::dispatch() {
  /* send http request */
  int ret = process("POST", dispatch_url.c_str());
  if (ret < 0) {
    return -EPERM;
  }

  /* parse response */
  if (response.parse(cct, rx_buffer) < 0) {
    return -EPERM;
  }

  /* check if we have a valid role */
  bool found = false;
  list<string>::iterator iter;
  for (iter = roles_list.begin(); iter != roles_list.end(); ++iter) {
    if ((found=response.user.has_role(*iter))==true)
      break;
  }

  if (!found) {
    return -EPERM;
  }

  /* everything seems fine, continue with this user */
  return 0;
}

int KeystoneRevokedTokensClient::dispatch() {
  /* send http request */
  int ret = process("GET", dispatch_url.c_str());
  if (ret < 0) {
    return -EPERM;
  }

  /* parse response */
  if (response.parse(cct, rx_buffer) < 0) {
    return -EPERM;
  }

  /* continue */
  return 0;
}

}}}
