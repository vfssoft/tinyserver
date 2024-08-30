#include <tm.h>
#include "tinyunit.h"
#include "testutil.h"
#include "mymqtt.h"

typedef struct test_conn_info_s {
    int connected_fired;
    int disconnected_fired;
    tm_t* server;
    ts_conn_t* conn;
    
    char user[32];
    char password[32];
} test_conn_info_t;

static void mqtt_auth_user_cb(void* ctx, tm_t* mq, const char* username, const char* password, int* ret_auth_ok) {
  test_conn_info_t* info = (test_conn_info_t*)ctx;
  if (username == NULL && password == NULL && strlen(info->user) == 0) {
    *ret_auth_ok = 1;
  }
}

static void mqtt_connected_cb(void* ctx, tm_t* mq, ts_conn_t* conn) {
  test_conn_info_t* info = (test_conn_info_t*)ctx;
  info->connected_fired++;
  info->server = mq;
  info->conn = conn;
}
static void mqtt_disconnected_cb(void* ctx, tm_t* mq, ts_conn_t* conn) {
  test_conn_info_t* info = (test_conn_info_t*)ctx;
  info->disconnected_fired++;
  info->server = mq;
  info->conn = conn;
}

static void mqtt_client_connect_cb(void *arg) {
  int err;
  int proto = *(int*)arg;
  mymqtt_t client;
  mymqtt__init(&client, proto, "test_client_id");
  
  err = mymqtt__connect(&client);
  ASSERT_EQ(err, 0);
  
  uv_sleep(500);
  
  err = mymqtt__disconnect(&client);
  ASSERT_EQ(err, 0);
}

static int mqtt_connect_imp(int proto) {
  test_conn_info_t conn_info;
  memset(&conn_info, 0, sizeof(conn_info));
  
  tm_t* server;
  tm_callbacks_t cbs;
  memset(&cbs, 0, sizeof(tm_callbacks_t));
  cbs.cb_ctx = &conn_info;
  cbs.auth_cb = mqtt_auth_user_cb;
  cbs.connected_cb = mqtt_connected_cb;
  cbs.disconnected_cb = mqtt_disconnected_cb;
  
  server = start_mqtt_server(proto, &cbs);
  int r = tm__start(server);
  ASSERT_EQ(r, 0);
  
  uv_thread_t client_thread;
  uv_thread_create(&client_thread, mqtt_client_connect_cb, (void*)&proto);
  
  while (conn_info.connected_fired == 0) {
    tm__run(server);
  }
  ASSERT_EQ(conn_info.connected_fired, 1);
  ASSERT_EQ(conn_info.server, server);
  ASSERT_PTR_NE(conn_info.conn, NULL);
  
  while (conn_info.disconnected_fired == 0) {
    tm__run(server);
  }
  
  ASSERT_EQ(conn_info.disconnected_fired, 1);
  ASSERT_PTR_EQ(conn_info.server, server);
  ASSERT_PTR_NE(conn_info.conn, NULL);
  
  tm__stop(server);
  uv_thread_join(&client_thread);
  
  return 0;
}

TEST_IMPL(mqtt_connect_tcp) {
  return mqtt_connect_imp(TS_PROTO_TCP);
}
TEST_IMPL(mqtt_connect_tls) {
  return mqtt_connect_imp(TS_PROTO_TLS);
}
TEST_IMPL(mqtt_connect_ws) {
  return mqtt_connect_imp(TS_PROTO_WS);
}
TEST_IMPL(mqtt_connect_wss) {
  return mqtt_connect_imp(TS_PROTO_WSS);
}