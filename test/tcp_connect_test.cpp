#include <gtest/gtest.h>
#include <ts_tcp.h>
#include "mytcp.h"

static void start_server(ts_server_t* server) {
  ts_server_config_t cfg;
  
  cfg.listeners = (ts_server_listener_config_t*) malloc(sizeof(ts_server_listener_config_t));
  cfg.listeners_count = 1;
  ts_server_listener_config__init(&cfg.listeners[0]);
  cfg.listeners[0].port = 12345;
  
  ts_server__init(server);
  ts_server__set_config(server, &cfg);
}

static void client_connect_cb(void *arg) {
  int err;
  mytcp_t client;
  err = mytcp__connect(&client, "127.0.0.1", 12345);
  ASSERT_EQ(err, 0);
  
  uv_sleep(100);
  
  err = mytcp__disconnect(&client);
  ASSERT_EQ(err, 0);
}

typedef struct test_connected_info_s {
  int fired;
  ts_server_t* server;
  ts_conn_t* conn;
  int status;
} test_connected_info_t;

static int connected_cb(void* ctx, ts_server_t* server, ts_conn_t* conn, int status) {
  test_connected_info_t* info = (test_connected_info_t*)ctx;
  info->fired++;
  info->server = server;
  info->conn = conn;
  info->status = status;
  return 0;
}

TEST(TCPServer, ConnectTest) {
  test_connected_info_t connected_info;
  memset(&connected_info, 0, sizeof(connected_info));
  
  ts_server_t server;
  start_server(&server);
  ts_server__set_cb_ctx(&server, &connected_info);
  ts_server__set_connected_cb(&server, connected_cb);
  
  uv_thread_t client_thread;
  uv_thread_create(&client_thread, client_connect_cb, NULL);
  
  int r = ts_server__start(&server);
  ASSERT_EQ(r, 0);
  while (true) {
    ts_server__run(&server);
    
    if (connected_info.fired > 0) {
      break;
    }
  }
  ASSERT_EQ(connected_info.fired, 1);
  ASSERT_EQ(connected_info.server, &server);
  ASSERT_TRUE(connected_info.conn != NULL);
  ASSERT_EQ(connected_info.status, 0);
  
  
}