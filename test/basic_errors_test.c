#include <ts.h>
#include "tinyunit.h"

TEST_IMPL(invalid_local_host) {
  ts_t* server = ts_server__create();
  ts_server__set_listener_count(server, 1);
  ts_server__set_listener_host_port(server, 0, "333.0.0.0", 1234);
  
  int r = ts_server__start(server);
  ASSERT_EQ(r, -4071);
  ASSERT_STR_EQ(ts_server__get_error_msg(server), "invalid host");
  r = ts_server__stop(server);
  ASSERT_EQ(r, 0);
  return 0;
}

TEST_IMPL(invalid_local_host_2) {
  ts_t* server = ts_server__create();
  ts_server__set_listener_count(server, 1);
  ts_server__set_listener_host_port(server, 0, "192.168.22.22", 1234);
  
  int r = ts_server__start(server);
  ASSERT_EQ(r, -4090);
  ASSERT_STR_EQ(ts_server__get_error_msg(server), "address not available");
  r = ts_server__stop(server);
  ASSERT_EQ(r, 0);
  return 0;
}

TEST_IMPL(invalid_ssl_cert) {
  ts_t* server = ts_server__create();
  ts_server__set_listener_count(server, 1);
  ts_server__set_listener_protocol(server, 0, TS_PROTO_TLS);
  ts_server__set_listener_certs(server, 0, "fakepath.crt", "fakekey.pem");
  
  int r = ts_server__start(server);
  ASSERT_EQ(r, 33558530);
  r = ts_server__stop(server);
  ASSERT_EQ(r, 0);
  return 0;
}
