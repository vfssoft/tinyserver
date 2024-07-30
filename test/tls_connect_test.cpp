#include <gtest/gtest.h>
#include <ts_tcp.h>
#include "mytcp.h"

static const char* cur_dir() {
  char* file = strdup(__FILE__);
  int idx = strlen(file) - 1;
  while (file[idx] != '\\') idx--;
  file[idx] = 0;
  return file;
}

static void start_server(ts_server_t* server) {
  ts_server__init(server);
  ts_server__set_listener_count(server, 1);
  ts_server__set_listener_host_port(server, 0, "127.0.0.1", 12345);
  ts_server__set_listener_protocol(server, 0, TS_PROTO_TLS);
  
  const char* dir_path = cur_dir();
  char crtpath[1024];
  char keypath[1024];

  sprintf(crtpath, "%s/certs/rsa_tinyserver.crt", dir_path);
  sprintf(keypath, "%s/certs/rsa_tinyserver.key", dir_path);
  
  ts_server__set_listener_certs(server, 0, crtpath, keypath);
}

static void ssl_client_connect_cb(void *arg) {
  int err;
  mytcp_t client;
  mytcp__init(&client);
  client.use_ssl = 1;

  err = mytcp__connect(&client, "127.0.0.1", 12345);
  ASSERT_EQ(err, 0);

  uv_sleep(500);

  err = mytcp__disconnect(&client);
  ASSERT_EQ(err, 0);
}

typedef struct test_conn_info_s {
    int connected_fired;
    int disconnected_fired;
    ts_server_t* server;
    ts_conn_t* conn;
} test_conn_info_t;

static int ssl_connected_cb(void* ctx, ts_server_t* server, ts_conn_t* conn, int status) {
  test_conn_info_t* info = (test_conn_info_t*)ctx;
  info->connected_fired++;
  info->server = server;
  info->conn = conn;
  return 0;
}
static int ssl_disconnected_cb(void* ctx, ts_server_t* server, ts_conn_t* conn, int status) {
  test_conn_info_t* info = (test_conn_info_t*)ctx;
  info->disconnected_fired++;
  info->server = server;
  info->conn = conn;
  return 0;
}

TEST(TCPServer, SSLConnectTest) {
  test_conn_info_t conn_info;
  memset(&conn_info, 0, sizeof(conn_info));

  ts_server_t server;
  start_server(&server);
  ts_server__set_cb_ctx(&server, &conn_info);
  ts_server__set_connected_cb(&server, ssl_connected_cb);
  ts_server__set_disconnected_cb(&server, ssl_disconnected_cb);

  uv_thread_t client_thread;
  uv_thread_create(&client_thread, ssl_client_connect_cb, NULL);

  int r = ts_server__start(&server);
  ASSERT_EQ(r, 0);
  while (conn_info.connected_fired == 0) {
    ts_server__run(&server);
  }
  ASSERT_EQ(conn_info.connected_fired, 1);
  ASSERT_EQ(conn_info.server, &server);
  ASSERT_TRUE(conn_info.conn != NULL);

  while (conn_info.disconnected_fired == 0) {
    ts_server__run(&server);
  }

  ASSERT_TRUE(conn_info.disconnected_fired == 1);
  ASSERT_TRUE(conn_info.server == &server);
  ASSERT_TRUE(conn_info.conn != NULL);

  ts_server__stop(&server);
}

static void ssl_client_connect_wait_disconnect_cb(void *arg) {
  int err;
  mytcp_t client;
  mytcp__init(&client);
  client.use_ssl = 1;
  err = mytcp__connect(&client, "127.0.0.1", 12345);
  ASSERT_EQ(err, 0);

  char readbuf[1];
  mytcp__read(&client, readbuf, 1);
}
static int ssl_connected_reject_cb(void* ctx, ts_server_t* server, ts_conn_t* conn, int status) {
  test_conn_info_t* info = (test_conn_info_t*)ctx;
  info->connected_fired++;

  ts_server__disconnect(server, conn);
  return 0;
}

TEST(TCPServer, SSLServerDisconnectTest) {
  test_conn_info_t conn_info;
  memset(&conn_info, 0, sizeof(conn_info));

  ts_server_t server;
  start_server(&server);
  ts_server__set_cb_ctx(&server, &conn_info);
  ts_server__set_connected_cb(&server, ssl_connected_reject_cb);
  ts_server__set_disconnected_cb(&server, ssl_disconnected_cb);

  uv_thread_t client_thread;
  uv_thread_create(&client_thread, ssl_client_connect_wait_disconnect_cb, NULL);

  int r = ts_server__start(&server);
  ASSERT_EQ(r, 0);
  while (conn_info.connected_fired == 0) {
    ts_server__run(&server);
  }
  ASSERT_EQ(conn_info.connected_fired, 1);

  while (conn_info.disconnected_fired == 0) {
    ts_server__run(&server);
  }

  ASSERT_TRUE(conn_info.disconnected_fired == 1);

  ts_server__stop(&server);
}

static void ssl_client_connect_disconnect_quick_cb(void *arg) {
  
  int err;
  mytcp_t client;
  mytcp__init(&client);
  client.use_ssl = 1;
  
  err = mytcp__connect(&client, "127.0.0.1", 12345);
  ASSERT_EQ(err, 0);
  
  if (arg) {
    int* afterSec = (int*)arg;
    uv_sleep(afterSec[0]);
  }
  
  err = mytcp__disconnect(&client);
  ASSERT_EQ(err, 0);

}

static void tcp_server__ssl_connect_disconnect_impl(int afterSec) {
  test_conn_info_t conn_info;
  memset(&conn_info, 0, sizeof(conn_info));
  
  ts_server_t server;
  start_server(&server);
  ts_server__set_cb_ctx(&server, &conn_info);
  ts_server__set_connected_cb(&server, ssl_connected_cb);
  ts_server__set_disconnected_cb(&server, ssl_disconnected_cb);
  
  uv_thread_t client_thread;
  uv_thread_create(&client_thread, ssl_client_connect_disconnect_quick_cb, NULL);
  
  int r = ts_server__start(&server);
  ASSERT_EQ(r, 0);
  while (conn_info.connected_fired == 0) {
    ts_server__run(&server);
  }
  ASSERT_EQ(conn_info.connected_fired, 1);
  ASSERT_EQ(conn_info.server, &server);
  ASSERT_TRUE(conn_info.conn != NULL);
  
  while (conn_info.disconnected_fired == 0) {
    ts_server__run(&server);
  }
  
  ASSERT_EQ(conn_info.disconnected_fired, 1);
  ASSERT_EQ(conn_info.server, &server);
  ASSERT_TRUE(conn_info.conn != NULL);
  
  ts_server__stop(&server);
}

TEST(TCPServer, SSLConnectDisconnectQuickTest) {
  tcp_server__ssl_connect_disconnect_impl(0);
}
TEST(TCPServer, SSLConnectDisconnect1sTest) {
  tcp_server__ssl_connect_disconnect_impl(1000);
}
