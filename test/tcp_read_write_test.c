
#include <ts.h>
#include "mytcp.h"
#include "testutil.h"
#include "tinyunit.h"

typedef struct test_conn_info_s {
    int read_fired;
    char databuf[65536];

    int write_fired;
} test_conn_info_t;

typedef struct test_echo_client_arg_s {
    int proto;
    const char* data;
    int data_len;
} test_echo_client_arg_t;

static void client_cb(void *arg) {
  int err;
  test_echo_client_arg_t* client_args = (test_echo_client_arg_t*) arg;
  mytcp_t client;
  mytcp__init_mutex();
  mytcp__init(&client);
  client.use_ssl = ts_use_ssl(client_args->proto);
  client.use_ws = ts_use_websocket(client_args->proto);

  err = mytcp__connect(&client, "127.0.0.1", 12345);
  ASSERT_EQ(err, 0);

  err = mytcp__write(&client, client_args->data, client_args->data_len);
  ASSERT_EQ(err, client_args->data_len);

  char* recvbuf = (char*) malloc(client_args->data_len);
  err = mytcp__read(&client, recvbuf, client_args->data_len);
  ASSERT_EQ(err, client_args->data_len);

  err = mytcp__disconnect(&client);
  ASSERT_EQ(err, 0);
}

static void read_cb(void* ctx, ts_server_t* server, ts_conn_t* conn, const char* data, int len) {
  test_conn_info_t* info = (test_conn_info_t*)ctx;
  info->read_fired++;
  memcpy(info->databuf, data, len);

  ts_server__write(server, conn, data, len, NULL);
}
static void write_cb(void* ctx, ts_server_t* server, ts_conn_t* conn, int status, int write_more, void* write_ctx) {
  test_conn_info_t* info = (test_conn_info_t*)ctx;
  info->write_fired++;
}

static int server_echo_impl(int proto, const char* data, int data_len) {
  test_conn_info_t conn_info;
  memset(&conn_info, 0, sizeof(conn_info));

  ts_t* server = start_server(proto);
  ts_callbacks_t cbs;
  RESET_STRUCT(cbs);
  cbs.ctx = &conn_info;
  cbs.read_cb = read_cb;
  cbs.write_cb = write_cb;
  ts_server__set_callbacks(server, &cbs);

  test_echo_client_arg_t client_args;
  client_args.proto = proto;
  client_args.data = data;
  client_args.data_len = data_len;

  uv_thread_t client_thread;
  uv_thread_create(&client_thread, client_cb, &client_args);

  int r = ts_server__start(server);
  ASSERT_EQ(r, 0);
  while (conn_info.read_fired == 0) {
    ts_server__run(server);
  }
  ASSERT_EQ(conn_info.read_fired, 1);

  while (conn_info.write_fired == 0) {
    ts_server__run(server);
  }

  ts_server__stop(server);
  uv_thread_join(&client_thread);
  
  return 0;
}

TEST_IMPL(tcp_echo) {
  const char* data = "hello world";
  return server_echo_impl(TS_PROTO_TCP, data, strlen(data));
}
TEST_IMPL(tls_echo) {
  const char* data = "hello world";
  return server_echo_impl(TS_PROTO_TLS, data, strlen(data));
}
TEST_IMPL(ws_echo) {
  const char* data = "hello world";
  return server_echo_impl(TS_PROTO_WS, data, strlen(data));
}
TEST_IMPL(wss_echo) {
  const char* data = "hello world";
  return server_echo_impl(TS_PROTO_WSS, data, strlen(data));
}
TEST_IMPL(tcp_echo_1k) {
  char* data = (char*) malloc(1024);
  memset(data, 'x', 1024);
  return server_echo_impl(TS_PROTO_TCP, data, 1024);
}
TEST_IMPL(tls_echo_1k) {
  char* data = (char*) malloc(1024);
  memset(data, 'x', 1024);
  return server_echo_impl(TS_PROTO_TLS, data, 1024);
}
TEST_IMPL(ws_echo_1k) {
  char* data = (char*) malloc(1024);
  memset(data, 'x', 1024);
  return server_echo_impl(TS_PROTO_WS, data, 1024);
}
TEST_IMPL(wss_echo_1k) {
  char* data = (char*) malloc(1024);
  memset(data, 'x', 1024);
  return server_echo_impl(TS_PROTO_WSS, data, 1024);
}

static void client_cb2(void *arg) {
  int err;
  test_echo_client_arg_t* client_args = (test_echo_client_arg_t*) arg;
  mytcp_t client;
  mytcp__init_mutex();
  mytcp__init(&client);
  client.use_ssl = ts_use_ssl(client_args->proto);
  client.use_ws = ts_use_websocket(client_args->proto);

  err = mytcp__connect(&client, "127.0.0.1", 12345);
  ASSERT_EQ(err, 0);

  const char* data = client_args->data;
  int data_len = client_args->data_len;
  char* recvbuf = (char*)malloc(data_len);

  for (int i = 0; i < 3; i++) {
    err = mytcp__write(&client, data, data_len);
    ASSERT_EQ(err, strlen(data));

    err = mytcp__read(&client, recvbuf, data_len);
    ASSERT_EQ(err, data_len);
  }

  err = mytcp__disconnect(&client);
  ASSERT_EQ(err, 0);
}

static int server_echo2_impl(int proto, const char* data, int data_len) {
  test_conn_info_t conn_info;
  memset(&conn_info, 0, sizeof(conn_info));
  
  ts_t* server = start_server(proto);
  ts_callbacks_t cbs;
  RESET_STRUCT(cbs);
  cbs.ctx = &conn_info;
  cbs.read_cb = read_cb;
  cbs.write_cb = write_cb;
  ts_server__set_callbacks(server, &cbs);

  test_echo_client_arg_t client_args;
  client_args.proto = proto;
  client_args.data = data;
  client_args.data_len = data_len;

  uv_thread_t client_thread;
  uv_thread_create(&client_thread, client_cb2, &client_args);

  int r = ts_server__start(server);
  ASSERT_EQ(r, 0);
  while (conn_info.read_fired < 3) {
    ts_server__run(server);
  }
  ASSERT_EQ(conn_info.read_fired, 3);

  while (conn_info.write_fired < 3) {
    ts_server__run(server);
  }

  ts_server__stop(server);
  uv_thread_join(&client_thread);
  
  return 0;
}

TEST_IMPL(tcp_echo2) {
  const char* data = "hello world!!!";
  return server_echo2_impl(TS_PROTO_TCP, data, strlen(data));
}
TEST_IMPL(tls_echo2) {
  const char* data = "hello world!!!";
  return server_echo2_impl(TS_PROTO_TLS, data, strlen(data));
}
TEST_IMPL(ws_echo2) {
  const char* data = "hello world!!!";
  return server_echo2_impl(TS_PROTO_WS, data, strlen(data));
}
TEST_IMPL(wss_echo2) {
  const char* data = "hello world!!!";
  return server_echo2_impl(TS_PROTO_WSS, data, strlen(data));
}

typedef struct test_echo_data_s {
    int proto;
    
    char* recv_buf;
    int   recv_buf_off;
    int   to_recv;

    int   client_done;
} test_echo_data_t;

static int echo_read_cb(void* ctx, ts_server_t* server, ts_conn_t* conn, const char* data, int len) {
  test_echo_data_t* info = (test_echo_data_t*)ctx;

  memcpy(info->recv_buf + info->recv_buf_off, data, len);
  info->recv_buf_off += len;

  if (info->recv_buf_off >= info->to_recv) {
    ts_server__write(server, conn, info->recv_buf, info->recv_buf_off, NULL);
  }

  return 0;
}

static void client_large_data_cb(void *arg) {
  int err;
  test_echo_data_t* info = (test_echo_data_t*)arg;
  mytcp_t client;
  mytcp__init_mutex();
  mytcp__init(&client);
  client.use_ssl = ts_use_ssl(info->proto);
  client.use_ws = ts_use_websocket(info->proto);
  err = mytcp__connect(&client, "127.0.0.1", 12345);
  ASSERT_EQ(err, 0);

  int data_len = info->to_recv;

  err = mytcp__write(&client, info->recv_buf, data_len);
  ASSERT_EQ(err, data_len);

  char* recvbuf = (char*) malloc(data_len);
  err = mytcp__read(&client, recvbuf, data_len);
  ASSERT_EQ(err,data_len);

  err = mytcp__disconnect(&client);
  ASSERT_EQ(err, 0);

  info->client_done = 1;
}

static int tcp_server__echo_large_data_impl(int proto, int data_size) {
  test_echo_data_t info;
  memset(&info, 0, sizeof(info));
  info.proto = proto;
  info.to_recv = data_size;
  info.recv_buf = (char*) malloc(data_size);
  memset(info.recv_buf, 'x', data_size);
  
  ts_t* server = start_server(proto);
  ts_callbacks_t cbs;
  RESET_STRUCT(cbs);
  cbs.read_cb = echo_read_cb;
  cbs.ctx = &info;
  ts_server__set_callbacks(server, &cbs);

  uv_thread_t client_thread;
  uv_thread_create(&client_thread, client_large_data_cb, &info);

  int r = ts_server__start(server);
  ASSERT_EQ(r, 0);

  while (info.client_done == 0) {
    ts_server__run(server);
  }

  ts_server__stop(server);
  return 0;
}

TEST_IMPL(tcp_echo_1k_data) {
  return tcp_server__echo_large_data_impl(TS_PROTO_TCP, 1024);
}
TEST_IMPL(tls_echo_1k_data) {
  return tcp_server__echo_large_data_impl(TS_PROTO_TLS, 1024);
}
TEST_IMPL(ws_echo_1k_data) {
  return tcp_server__echo_large_data_impl(TS_PROTO_WS, 1024);
}
TEST_IMPL(wss_echo_1k_data) {
  return tcp_server__echo_large_data_impl(TS_PROTO_WSS, 1024);
}
TEST_IMPL(tcp_echo_10m_data) {
  return tcp_server__echo_large_data_impl(TS_PROTO_TCP, 10 * 1024 * 1024);
}
TEST_IMPL(tls_echo_10m_data) {
  return tcp_server__echo_large_data_impl(TS_PROTO_TLS, 10 * 1024 * 1024);
}
TEST_IMPL(ws_echo_10m_data) {
  return tcp_server__echo_large_data_impl(TS_PROTO_WS, 10 * 1024 * 1024);
}
TEST_IMPL(wss_echo_10m_data) {
  return tcp_server__echo_large_data_impl(TS_PROTO_WSS, 10 * 1024 * 1024);
}
