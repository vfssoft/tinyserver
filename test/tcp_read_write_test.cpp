#include <gtest/gtest.h>
#include <ts_tcp.h>
#include "mytcp.h"

static void start_server(ts_server_t* server) {
  ts_server__init(server);
  ts_server__set_listener_count(server, 1);
  ts_server__set_listener_host_port(server, 0, "127.0.0.1", 12345);
}

static void client_cb(void *arg) {
  int err;
  mytcp_t client;
  mytcp__init(&client);
  err = mytcp__connect(&client, "127.0.0.1", 12345);
  ASSERT_EQ(err, 0);
  
  char* data = (char*) arg;
  err = mytcp__write(&client, data, strlen(data));
  ASSERT_EQ(err, strlen(data));
  
  char recvbuf[100];
  err = mytcp__read(&client, recvbuf, 100);
  ASSERT_EQ(err, strlen(data));
  
  err = mytcp__disconnect(&client);
  ASSERT_EQ(err, 0);
}

typedef struct test_conn_info_s {
    int read_fired;
    char databuf[10];
    
    int write_fired;
} test_conn_info_t;

static int read_cb(void* ctx, ts_server_t* server, ts_conn_t* conn, const char* data, int len) {
  test_conn_info_t* info = (test_conn_info_t*)ctx;
  info->read_fired++;
  memcpy(info->databuf, data, len);
  
  ts_server__write(server, conn, data, len);
  return 0;
}
static int write_cb(void* ctx, ts_server_t* server, ts_conn_t* conn, int status, int write_more) {
  test_conn_info_t* info = (test_conn_info_t*)ctx;
  info->write_fired++;
  return 0;
}

TEST(TCPServer, EchoTest) {
  test_conn_info_t conn_info;
  memset(&conn_info, 0, sizeof(conn_info));
  
  ts_server_t server;
  start_server(&server);
  ts_server__set_cb_ctx(&server, &conn_info);
  ts_server__set_read_cb(&server, read_cb);
  ts_server__set_write_cb(&server, write_cb);
  
  char* str = "hello world";
  uv_thread_t client_thread;
  uv_thread_create(&client_thread, client_cb, str);
  
  int r = ts_server__start(&server);
  ASSERT_EQ(r, 0);
  while (conn_info.read_fired == 0) {
    ts_server__run(&server);
  }
  ASSERT_TRUE(conn_info.read_fired == 1);
  ASSERT_STREQ(conn_info.databuf, str);
  
  while (conn_info.write_fired == 0) {
    ts_server__run(&server);
  }
  
  ts_server__stop(&server);
  
}

static void client_cb2(void *arg) {
  int err;
  mytcp_t client;
  mytcp__init(&client);
  err = mytcp__connect(&client, "127.0.0.1", 12345);
  ASSERT_EQ(err, 0);
  
  char* data = (char*) arg;
  char recvbuf[100];
  
  for (int i = 0; i < 3; i++) {
    err = mytcp__write(&client, data, strlen(data));
    ASSERT_EQ(err, strlen(data));
  
    err = mytcp__read(&client, recvbuf, 100);
    ASSERT_EQ(err, strlen(data));
  }
  
  err = mytcp__disconnect(&client);
  ASSERT_EQ(err, 0);
}

TEST(TCPServer, Echo2Test) {
  test_conn_info_t conn_info;
  memset(&conn_info, 0, sizeof(conn_info));
  
  ts_server_t server;
  start_server(&server);
  ts_server__set_cb_ctx(&server, &conn_info);
  ts_server__set_read_cb(&server, read_cb);
  ts_server__set_write_cb(&server, write_cb);
  
  char* str = "hello world";
  uv_thread_t client_thread;
  uv_thread_create(&client_thread, client_cb2, str);
  
  int r = ts_server__start(&server);
  ASSERT_EQ(r, 0);
  while (conn_info.read_fired < 3) {
    ts_server__run(&server);
  }
  ASSERT_EQ(conn_info.read_fired, 3);
  
  while (conn_info.write_fired < 3) {
    ts_server__run(&server);
  }
  
  ts_server__stop(&server);
  
}