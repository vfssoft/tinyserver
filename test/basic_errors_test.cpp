#include <gtest/gtest.h>
#include <ts_tcp.h>

TEST(TCPServer, InvalidLocalHostTest) {
  ts_server_t server;
  ts_server__init(&server);
  ts_server__set_listener_count(&server, 1);
  ts_server__set_listener_host_port(&server, 0, "333.0.0.0", 1234);
  
  int r = ts_server__start(&server);
  ASSERT_TRUE(r == -4071);
  ASSERT_STREQ(server.err->msg, "invalid host");
}

TEST(TCPServer, InvalidLocalHost2Test) {
  ts_server_t server;
  ts_server__init(&server);
  ts_server__set_listener_count(&server, 1);
  ts_server__set_listener_host_port(&server, 0, "192.168.22.22", 1234);
  
  int r = ts_server__start(&server);
  ASSERT_TRUE(r == -4090);
  ASSERT_STREQ(server.err->msg, "address not available");
}