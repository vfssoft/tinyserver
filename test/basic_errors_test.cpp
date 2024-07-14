#include <gtest/gtest.h>
#include <ts_tcp.h>

TEST(TCPServer, InvalidLocalHostTest) {
  ts_server_config_t cfg;
  
  cfg.listeners = (ts_server_listener_config_t*) malloc(sizeof(ts_server_listener_config_t));
  cfg.listeners_count = 1;
  ts_server_listener_config__init(&cfg.listeners[0]);
  cfg.listeners[0].host = "333.0.0.0";
  cfg.listeners[0].port = 1234;
  
  ts_server_t server;
  ts_server__init(&server);
  ts_server__set_config(&server, &cfg);
  
  int r = ts_server__start(&server);
  ASSERT_TRUE(r == -4071);
  ASSERT_STREQ(server.err_msg, "invalid host");
}

TEST(TCPServer, InvalidLocalHost2Test) {
  ts_server_config_t cfg;
  
  cfg.listeners = (ts_server_listener_config_t*) malloc(sizeof(ts_server_listener_config_t));
  cfg.listeners_count = 1;
  ts_server_listener_config__init(&cfg.listeners[0]);
  cfg.listeners[0].host = "192.168.22.22";
  cfg.listeners[0].port = 1234;
  
  ts_server_t server;
  ts_server__init(&server);
  ts_server__set_config(&server, &cfg);
  
  int r = ts_server__start(&server);
  ASSERT_TRUE(r == -4090);
  ASSERT_STREQ(server.err_msg, "address not available");
}