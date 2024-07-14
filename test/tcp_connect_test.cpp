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

typedef struct test_conn_info_s {
  int fired;
  ts_server_t* server;
  ts_conn_t* conn;
} test_conn_info_t;

static int connected_cb(void* ctx, ts_server_t* server, ts_conn_t* conn, int status) {
  test_conn_info_t* info = (test_conn_info_t*)ctx;
  info->fired++;
  info->server = server;
  info->conn = conn;
  return 0;
}
static int disconnected_cb(void* ctx, ts_server_t* server, ts_conn_t* conn, int status) {
  test_conn_info_t* info = (test_conn_info_t*)ctx;
  info->fired--;
  info->server = server;
  info->conn = conn;
  return 0;
}

TEST(TCPServer, ConnectTest) {
  test_conn_info_t conn_info;
  memset(&conn_info, 0, sizeof(conn_info));
  
  ts_server_t server;
  start_server(&server);
  ts_server__set_cb_ctx(&server, &conn_info);
  ts_server__set_connected_cb(&server, connected_cb);
  ts_server__set_disconnected_cb(&server, disconnected_cb);
  
  uv_thread_t client_thread;
  uv_thread_create(&client_thread, client_connect_cb, NULL);
  
  int r = ts_server__start(&server);
  ASSERT_EQ(r, 0);
  while (conn_info.fired == 0) {
    ts_server__run(&server);
  }
  ASSERT_EQ(conn_info.fired, 1);
  ASSERT_EQ(conn_info.server, &server);
  ASSERT_TRUE(conn_info.conn != NULL);
  
  while (conn_info.fired > 0) {
    ts_server__run(&server);
  }
  
  ASSERT_EQ(conn_info.fired, 0);
  ASSERT_EQ(conn_info.server, &server);
  ASSERT_TRUE(conn_info.conn != NULL);
  
  ts_server__stop(&server);
}