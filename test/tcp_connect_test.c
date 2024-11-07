
#include <ts.h>
#include "mytcp.h"
#include "testutil.h"
#include "tinyunit.h"

static void client_connect_cb(void *arg) {
  int err;
  int proto = *(int*)arg;
  mytcp_t client;
  mytcp__init_mutex();
  mytcp__init(&client);
  client.use_ssl = ts_use_ssl(proto);
  client.use_ws = ts_use_websocket(proto);

  err = mytcp__connect(&client, "127.0.0.1", 12345);
  ASSERT_EQ(err, 0);

  uv_sleep(500);

  err = mytcp__disconnect(&client);
  ASSERT_EQ(err, 0);
}
typedef struct test_conn_info_s {
  int connected_fired;
  int disconnected_fired;
  ts_t* server;
  ts_conn_t* conn;
} test_conn_info_t;

static void connected_cb(void* ctx, ts_t* server, ts_conn_t* conn, int status) {
  test_conn_info_t* info = (test_conn_info_t*)ctx;
  info->connected_fired++;
  info->server = server;
  info->conn = conn;
}
static void disconnected_cb(void* ctx, ts_t* server, ts_conn_t* conn, int status) {
  test_conn_info_t* info = (test_conn_info_t*)ctx;
  info->disconnected_fired++;
  info->server = server;
  info->conn = conn;
}

static int server_connect_impl(int proto) {
  test_conn_info_t conn_info;
  memset(&conn_info, 0, sizeof(conn_info));

  ts_t* server = start_server(proto);
  ts_callbacks_t cbs;
  RESET_STRUCT(cbs);
  cbs.ctx = &conn_info;
  cbs.connected_cb = connected_cb;
  cbs.disconnected_cb = disconnected_cb;
  ts_server__set_callbacks(server, &cbs);

  uv_thread_t client_thread;
  uv_thread_create(&client_thread, client_connect_cb, (void*)&proto);

  int r = ts_server__start(server);
  ASSERT_EQ(r, 0);
  while (conn_info.connected_fired == 0) {
    ts_server__run(server);
  }
  ASSERT_EQ(conn_info.connected_fired, 1);
  ASSERT_EQ(conn_info.server, server);
  ASSERT_PTR_NE(conn_info.conn, NULL);

  while (conn_info.disconnected_fired == 0) {
    ts_server__run(server);
  }

  ASSERT_EQ(conn_info.disconnected_fired, 1);
  ASSERT_PTR_EQ(conn_info.server, server);
  ASSERT_PTR_NE(conn_info.conn, NULL);

  ts_server__stop(server);
  uv_thread_join(&client_thread);
  
  return 0;
}

TEST_IMPL(tcp_connect) {
  return server_connect_impl(TS_PROTO_TCP);
}
TEST_IMPL(tls_connect) {
  return server_connect_impl(TS_PROTO_TLS);
}
TEST_IMPL(ws_connect) {
  return server_connect_impl(TS_PROTO_WS);
}
TEST_IMPL(wss_connect) {
  return server_connect_impl(TS_PROTO_WSS);
}

static void client_connect_wait_disconnect_cb(void *arg) {
  int err;
  int proto = *(int*)arg;
  mytcp_t client;
  mytcp__init_mutex();
  mytcp__init(&client);
  client.use_ssl = ts_use_ssl(proto);
  client.use_ws = ts_use_websocket(proto);

  err = mytcp__connect(&client, "127.0.0.1", 12345);
  ASSERT_EQ(err, 0);

  char readbuf[1];
  mytcp__read(&client, readbuf, 1);
}
static void connected_reject_cb(void* ctx, ts_t* server, ts_conn_t* conn, int status) {
  test_conn_info_t* info = (test_conn_info_t*)ctx;
  info->connected_fired++;

  ts_server__disconnect(server, conn);
}

static int server_disconnect_impl(int proto) {
  test_conn_info_t conn_info;
  memset(&conn_info, 0, sizeof(conn_info));

  ts_t* server = start_server(proto);
  ts_callbacks_t cbs;
  RESET_STRUCT(cbs);
  cbs.ctx = &conn_info;
  cbs.connected_cb = connected_reject_cb;
  cbs.disconnected_cb = disconnected_cb;
  ts_server__set_callbacks(server, &cbs);

  uv_thread_t client_thread;
  uv_thread_create(&client_thread, client_connect_wait_disconnect_cb, &proto);

  int r = ts_server__start(server);
  ASSERT_EQ(r, 0);
  while (conn_info.connected_fired == 0) {
    ts_server__run(server);
  }
  ASSERT_EQ(conn_info.connected_fired, 1);

  while (conn_info.disconnected_fired == 0) {
    ts_server__run(server);
  }

  ASSERT_EQ(conn_info.disconnected_fired, 1);

  ts_server__stop(server);
  uv_thread_join(&client_thread);
  return 0;
}

TEST_IMPL(tcp_server_disconnect) {
  return server_disconnect_impl(TS_PROTO_TCP);
}
TEST_IMPL(tls_server_disconnect) {
  return server_disconnect_impl(TS_PROTO_TLS);
}
TEST_IMPL(ws_server_disconnect) {
  return server_disconnect_impl(TS_PROTO_WS);
}
TEST_IMPL(wss_server_disconnect) {
  return server_disconnect_impl(TS_PROTO_WSS);
}


typedef struct test_proto_aftersec_s {
    int proto;
    int after_sec;
} test_proto_aftersec_t;

static void client_connect_disconnect_quick_cb(void *arg) {
  int err;
  test_proto_aftersec_t* client_args = (test_proto_aftersec_t*) arg;
  mytcp_t client;
  mytcp__init_mutex();
  mytcp__init(&client);
  client.use_ssl = ts_use_ssl(client_args->proto);
  client.use_ws = ts_use_websocket(client_args->proto);

  err = mytcp__connect(&client, "127.0.0.1", 12345);
  ASSERT_EQ(err, 0);

  if (client_args->after_sec) {
    uv_sleep(client_args->after_sec);
  }

  err = mytcp__disconnect(&client);
  ASSERT_EQ(err, 0);
}

static int tcp_server__connect_disconnect_impl(int proto, int afterSec) {
  test_conn_info_t conn_info;
  memset(&conn_info, 0, sizeof(conn_info));

  ts_t* server = start_server(proto);
  ts_callbacks_t cbs;
  RESET_STRUCT(cbs);
  cbs.ctx = &conn_info;
  cbs.connected_cb = connected_cb;
  cbs.disconnected_cb = disconnected_cb;
  ts_server__set_callbacks(server, &cbs);

  test_proto_aftersec_t client_args;
  client_args.proto = proto;
  client_args.after_sec = afterSec;

  uv_thread_t client_thread;
  uv_thread_create(&client_thread, client_connect_disconnect_quick_cb, &client_args);

  int r = ts_server__start(server);
  ASSERT_EQ(r, 0);
  while (conn_info.connected_fired == 0) {
    ts_server__run(server);
  }
  ASSERT_EQ(conn_info.connected_fired, 1);
  ASSERT_EQ(conn_info.server, server);
  ASSERT_PTR_NE(conn_info.conn, NULL);

  while (conn_info.disconnected_fired == 0) {
    ts_server__run(server);
  }

  ASSERT_EQ(conn_info.disconnected_fired, 1);
  ASSERT_PTR_EQ(conn_info.server, server);
  ASSERT_PTR_NE(conn_info.conn, NULL);

  ts_server__stop(server);
  uv_thread_join(&client_thread);
  return 0;
}

TEST_IMPL(tcp_connect_disconnect_quick) {
  return tcp_server__connect_disconnect_impl(TS_PROTO_TCP, 0);
}
TEST_IMPL(tls_connect_disconnect_quick) {
  return tcp_server__connect_disconnect_impl(TS_PROTO_TLS, 0);
}
TEST_IMPL(ws_connect_disconnect_quick) {
  return tcp_server__connect_disconnect_impl(TS_PROTO_WS, 0);
}
TEST_IMPL(wss_connect_disconnect_quick) {
  return tcp_server__connect_disconnect_impl(TS_PROTO_WSS, 0);
}
TEST_IMPL(tcp_connect_disconnect_1s) {
  return tcp_server__connect_disconnect_impl(TS_PROTO_TCP, 1000);
}
TEST_IMPL(tls_connect_disconnect_1s) {
  return tcp_server__connect_disconnect_impl(TS_PROTO_TLS, 1000);
}
TEST_IMPL(ws_connect_disconnect_1s) {
  return tcp_server__connect_disconnect_impl(TS_PROTO_WS, 1000);
}
TEST_IMPL(wss_connect_disconnect_1s) {
  return tcp_server__connect_disconnect_impl(TS_PROTO_WSS, 1000);
}

static int tcp_server_clients_impl(int proto, int client_cnt) {
  test_conn_info_t conn_info;
  memset(&conn_info, 0, sizeof(conn_info));

  ts_t* server = start_server(proto);
  ts_callbacks_t cbs;
  RESET_STRUCT(cbs);
  cbs.ctx = &conn_info;
  cbs.connected_cb = connected_cb;
  cbs.disconnected_cb = disconnected_cb;
  ts_server__set_callbacks(server, &cbs);


  uv_thread_t* client_threads = (uv_thread_t*) malloc(sizeof(uv_thread_t) * client_cnt);
  for (int i = 0; i < client_cnt; i++) {
    uv_thread_create(&client_threads[i], client_connect_cb, &proto);
  }

  int r = ts_server__start(server);
  ASSERT_EQ(r, 0);
  while (conn_info.connected_fired < client_cnt) {
    ts_server__run(server);
  }
  ASSERT_EQ(conn_info.connected_fired, client_cnt);

  while (conn_info.disconnected_fired < client_cnt) {
    ts_server__run(server);
  }

  ASSERT_EQ(conn_info.disconnected_fired, client_cnt);

  ts_server__stop(server);
  for (int i = 0; i < client_cnt; i++) {
    uv_thread_join(&client_threads[i]);
  }
  return 0;
}

TEST_IMPL(tcp_10clients_connect) {
  return tcp_server_clients_impl(TS_PROTO_TCP, 10);
}
TEST_IMPL(tls_10clients_connect) {
  return tcp_server_clients_impl(TS_PROTO_TLS, 10);
}
TEST_IMPL(ws_10clients_connect) {
  return tcp_server_clients_impl(TS_PROTO_WS, 10);
}
TEST_IMPL(wss_10clients_connect) {
  return tcp_server_clients_impl(TS_PROTO_WSS, 10);
}
TEST_IMPL(tcp_100clients_connect) {
  return tcp_server_clients_impl(TS_PROTO_TCP, 100);
}
TEST_IMPL(tls_100clients_connect) {
  return tcp_server_clients_impl(TS_PROTO_TLS, 100);
}
TEST_IMPL(ws_100clients_connect) {
  return tcp_server_clients_impl(TS_PROTO_WS, 100);
}
TEST_IMPL(wss_100clients_connect) {
  return tcp_server_clients_impl(TS_PROTO_WSS, 100);
}
