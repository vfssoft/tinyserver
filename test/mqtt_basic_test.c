#include <tm.h>
#include "tinyunit.h"
#include "testutil.h"
#include "mymqtt.h"

typedef struct test_conn_info_s {
    int connected_fired;
    int disconnected_fired;
    int auth_fired;
    tm_t* server;
    ts_conn_t* conn;
    
    char user[32];
    char password[32];
    int auth_fail;
    
    int proto;
    
    int client_err;
} test_conn_info_t;

static void mqtt_auth_user_cb(void* ctx, tm_t* mq, const char* username, const char* password, int* ret_auth_ok) {
  test_conn_info_t* info = (test_conn_info_t*)ctx;
  info->auth_fired = 1;
  if (info->auth_fail) {
    return;
  }
  if (username == NULL && password == NULL && strlen(info->user) == 0) {
    *ret_auth_ok = 1;
  } else if (strcmp(username, info->user) == 0 && strcmp(password, info->password) == 0) {
    *ret_auth_ok = 1;
  }
}
static void mqtt_auth_user_anonymous_cb(void* ctx, tm_t* mq, const char* username, const char* password, int* ret_auth_ok) {
  *ret_auth_ok = 1;
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

static void init_callbacks(tm_callbacks_t* cbs, void* cb_ctx) {
  memset(cbs, 0, sizeof(tm_callbacks_t));
  cbs->cb_ctx = cb_ctx;
  cbs->auth_cb = mqtt_auth_user_cb;
  cbs->connected_cb = mqtt_connected_cb;
  cbs->disconnected_cb = mqtt_disconnected_cb;
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
  init_callbacks(&cbs, &conn_info);
  
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

static void mqtt_client_connect_with_user_password_cb(void *arg) {
  int err;
  test_conn_info_t* info = (test_conn_info_t*)arg;
  mymqtt_t client;
  mymqtt__init(&client, info->proto, "test_client_id");
  
  mymqtt__set_user(&client, info->user);
  mymqtt__set_password(&client, info->password);
  
  err = mymqtt__connect(&client);
  if (info->auth_fail) {
    ASSERT_NE(err, 0);
  } else {
    ASSERT_EQ(err, 0);
  }
  
  err = mymqtt__disconnect(&client);
  ASSERT_EQ(err, 0);
}
static int mqtt_auth_user_impl(int auth_fail) {
  test_conn_info_t conn_info;
  memset(&conn_info, 0, sizeof(conn_info));
  conn_info.proto = TS_PROTO_TCP;
  strcpy(conn_info.user, "test");
  strcpy(conn_info.password, "test");
  conn_info.auth_fail = auth_fail;
  
  tm_t* server;
  tm_callbacks_t cbs;
  init_callbacks(&cbs, &conn_info);
  
  server = start_mqtt_server(conn_info.proto, &cbs);
  int r = tm__start(server);
  ASSERT_EQ(r, 0);
  
  uv_thread_t client_thread;
  uv_thread_create(&client_thread, mqtt_client_connect_with_user_password_cb, (void*)&conn_info);
  
  if (conn_info.auth_fail) {
    while (conn_info.auth_fired == 0) tm__run(server);
  } else {
    while (conn_info.connected_fired == 0) tm__run(server);
    ASSERT_EQ(conn_info.connected_fired, 1);
  
    while (conn_info.disconnected_fired == 0) {tm__run(server);}
  }
  
  
  tm__stop(server);
  uv_thread_join(&client_thread);
  
  return 0;
}
TEST_IMPL(mqtt_auth_user) {
  return mqtt_auth_user_impl(0);
}
TEST_IMPL(mqtt_auth_user_fail) {
  return mqtt_auth_user_impl(1);
}

typedef struct {
    int proto;
    int done;
} test_two_client_same_clientid_info_t;

static void mqtt_two_client_with_same_clientid_cb(void *arg) {
  int err;
  test_two_client_same_clientid_info_t* info = (test_two_client_same_clientid_info_t*) arg;
  mymqtt_t client1;
  mymqtt_t client2;
  mymqtt__init(&client1, info->proto, "test_client_id");
  mymqtt__init(&client2, info->proto, "test_client_id");

  err = mymqtt__connect(&client1);
  ASSERT_EQ(err, 0);

  err = mymqtt__connect(&client2);
  ASSERT_EQ(err, 0);


  long long endtime = get_current_time_millis() + 1000;
  while (get_current_time_millis() < endtime) {
    if (mymqtt__is_conn_lost(&client1)) {
      break;
    }

    wait(100);
  }
  ASSERT_EQ(mymqtt__is_conn_lost(&client1), 1);
  ASSERT_EQ(mymqtt__is_conn_lost(&client2), 0);

  err = mymqtt__disconnect(&client2);
  ASSERT_EQ(err, 0);

  info->done = 1;
}
static int mqtt_two_clients_with_same_clientid_impl(int proto) {
  test_conn_info_t conn_info;
  memset(&conn_info, 0, sizeof(conn_info));

  test_two_client_same_clientid_info_t info;
  RESET_STRUCT(info);
  info.proto = proto;

  tm_t* server;
  tm_callbacks_t cbs;
  init_callbacks(&cbs, &conn_info);

  server = start_mqtt_server(proto, &cbs);
  int r = tm__start(server);
  ASSERT_EQ(r, 0);

  uv_thread_t client_thread;
  uv_thread_create(&client_thread, mqtt_two_client_with_same_clientid_cb, (void*)&info);

  while (info.done == 0) { tm__run(server); }

  tm__stop(server);
  uv_thread_join(&client_thread);

  return 0;
}
TEST_IMPL(mqtt_two_clients_with_same_clientid_tcp) {
  return mqtt_two_clients_with_same_clientid_impl(TS_PROTO_TCP);
}
TEST_IMPL(mqtt_two_clients_with_same_clientid_tls) {
  return mqtt_two_clients_with_same_clientid_impl(TS_PROTO_TLS);
}
TEST_IMPL(mqtt_two_clients_with_same_clientid_ws) {
  return mqtt_two_clients_with_same_clientid_impl(TS_PROTO_WS);
}
TEST_IMPL(mqtt_two_clients_with_same_clientid_wss) {
  return mqtt_two_clients_with_same_clientid_impl(TS_PROTO_WSS);
}

static void mqtt_client_connect_with_invalid_protocol_cb(void *arg) {
  test_conn_info_t* info = (test_conn_info_t*)arg;
  mymqtt_t client;
  mymqtt__init(&client, info->proto, "test_client_id");
  
  info->client_err = mymqtt__connect(&client);
  ASSERT_NE(info->client_err, 0);
}
static int mqtt_invalid_transport_protocol_impl(int server_proto, int server_port, int client_proto) {
  test_conn_info_t conn_info;
  memset(&conn_info, 0, sizeof(conn_info));
  conn_info.proto = client_proto;
  
  tm_t* server;
  tm_callbacks_t cbs;
  init_callbacks(&cbs, &conn_info);
  
  server = start_mqtt_server_custom_port(server_proto, server_port, &cbs);
  int r = tm__start(server);
  ASSERT_EQ(r, 0);
  
  uv_thread_t client_thread;
  uv_thread_create(&client_thread, mqtt_client_connect_with_invalid_protocol_cb, (void*)&conn_info);
  
  while (conn_info.client_err == 0) tm__run(server);
  ASSERT_NE(conn_info.client_err, 0);

  tm__stop(server);
  uv_thread_join(&client_thread);
  return 0;
}

TEST_IMPL(mqtt_invalid_protocol_tcp_tls_test) {
  return mqtt_invalid_transport_protocol_impl(TS_PROTO_TCP, MQTT_TLS_PORT, TS_PROTO_TLS);
}
TEST_IMPL(mqtt_invalid_protocol_tcp_ws_test) {
  return mqtt_invalid_transport_protocol_impl(TS_PROTO_TCP, MQTT_WS_PORT, TS_PROTO_WS);
}
TEST_IMPL(mqtt_invalid_protocol_tcp_wss_test) {
  return mqtt_invalid_transport_protocol_impl(TS_PROTO_TCP, MQTT_WSS_PORT, TS_PROTO_WSS);
}
TEST_IMPL(mqtt_invalid_protocol_tls_tcp_test) {
  return mqtt_invalid_transport_protocol_impl(TS_PROTO_TLS, MQTT_PLAIN_PORT, TS_PROTO_TCP);
}
TEST_IMPL(mqtt_invalid_protocol_tls_ws_test) {
  return mqtt_invalid_transport_protocol_impl(TS_PROTO_TLS, MQTT_WS_PORT, TS_PROTO_WS);
}
TEST_IMPL(mqtt_invalid_protocol_tls_wss_test) {
  return mqtt_invalid_transport_protocol_impl(TS_PROTO_TLS, MQTT_WSS_PORT, TS_PROTO_WSS);
}
TEST_IMPL(mqtt_invalid_protocol_ws_tcp_test) {
  return mqtt_invalid_transport_protocol_impl(TS_PROTO_WS, MQTT_PLAIN_PORT, TS_PROTO_TCP);
}
TEST_IMPL(mqtt_invalid_protocol_ws_tls_test) {
  return mqtt_invalid_transport_protocol_impl(TS_PROTO_WS, MQTT_TLS_PORT, TS_PROTO_TLS);
}
TEST_IMPL(mqtt_invalid_protocol_ws_wss_test) {
  return mqtt_invalid_transport_protocol_impl(TS_PROTO_WS, MQTT_WSS_PORT, TS_PROTO_WSS);
}
TEST_IMPL(mqtt_invalid_protocol_wss_tcp_test) {
  return mqtt_invalid_transport_protocol_impl(TS_PROTO_WSS, MQTT_PLAIN_PORT, TS_PROTO_TCP);
}
TEST_IMPL(mqtt_invalid_protocol_wss_tls_test) {
  return mqtt_invalid_transport_protocol_impl(TS_PROTO_WSS, MQTT_TLS_PORT, TS_PROTO_TLS);
}
TEST_IMPL(mqtt_invalid_protocol_wss_ws_test) {
  return mqtt_invalid_transport_protocol_impl(TS_PROTO_WSS, MQTT_WS_PORT, TS_PROTO_WS);
}

typedef struct {
    int clean_session;
    int sp;
    int done;
} conn_ack_sp_info_t;

static void mqtt_client_conn_ack_sp_cb(void *arg) {
  int err;
  conn_ack_sp_info_t* info = (conn_ack_sp_info_t*)arg;
  mymqtt_t client;
  mymqtt__init(&client, TS_PROTO_TCP, "test_client_id");
  client.options.cleansession = info->clean_session;
  
  err = mymqtt__connect(&client);
  ASSERT_EQ(err, 0);
  ASSERT_EQ(mymqtt__sp(&client), 0);
  
  err = mymqtt__disconnect(&client);
  ASSERT_EQ(err, 0);
  
  err = mymqtt__connect(&client);
  ASSERT_EQ(err, 0);
  ASSERT_EQ(mymqtt__sp(&client), !info->clean_session);
  
  err = mymqtt__disconnect(&client);
  ASSERT_EQ(err, 0);
  
  info->done = 1;
}
static int mqtt_conn_ack_sp_impl(int clean_session) {
  conn_ack_sp_info_t info;
  RESET_STRUCT(info);
  info.clean_session = clean_session;
  
  tm_t* server;
  tm_callbacks_t cbs;
  RESET_STRUCT(cbs);
  cbs.auth_cb = mqtt_auth_user_anonymous_cb;
  
  server = start_mqtt_server(TS_PROTO_TCP, &cbs);
  int r = tm__start(server);
  ASSERT_EQ(r, 0);
  
  uv_thread_t client_thread;
  uv_thread_create(&client_thread, mqtt_client_conn_ack_sp_cb, (void*)&info);
  
  while (info.done == 0) tm__run(server);
  
  tm__stop(server);
  uv_thread_join(&client_thread);
  return 0;
}

TEST_IMPL(mqtt_conn_ack_sp_false_test) {
  return mqtt_conn_ack_sp_impl(0);
}
TEST_IMPL(mqtt_conn_ack_sp_true_test) {
  return mqtt_conn_ack_sp_impl(1);
}

typedef struct {
    char* client_id;
    int done;
} different_client_id_info_t;
static void mqtt_client_different_length_client_id_cb(void* arg) {
  int err;
  different_client_id_info_t* info = (different_client_id_info_t*)arg;
  mymqtt_t client;
  mymqtt__init(&client, TS_PROTO_TCP, info->client_id);
  err = mymqtt__connect(&client);
  if (strlen(info->client_id) > 512) {
    ASSERT_EQ(err, 2); // identifier rejected
  } else {
    ASSERT_EQ(err, 0);
  }
  
  err = mymqtt__disconnect(&client);
  ASSERT_EQ(err, 0);
  info->done = 1;
}
static int mqtt_different_length_client_id_impl(const char* client_id) {
  different_client_id_info_t info;
  RESET_STRUCT(info);
  info.client_id = strdup(client_id);
  
  tm_t* server;
  tm_callbacks_t cbs;
  RESET_STRUCT(cbs);
  cbs.auth_cb = mqtt_auth_user_anonymous_cb;
  
  server = start_mqtt_server(TS_PROTO_TCP, &cbs);
  int r = tm__start(server);
  ASSERT_EQ(r, 0);
  
  uv_thread_t client_thread;
  uv_thread_create(&client_thread, mqtt_client_different_length_client_id_cb, (void*)&info);
  
  while (info.done == 0) tm__run(server);
  
  tm__stop(server);
  uv_thread_join(&client_thread);
  return 0;
}
TEST_IMPL(mqtt_zero_length_client_id_test) {
  return mqtt_different_length_client_id_impl("");
}
TEST_IMPL(mqtt_normal_client_id_test) {
  return mqtt_different_length_client_id_impl("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");
}
TEST_IMPL(mqtt_512_length_client_id_test) {
  // KNOWN BUG
  return 0;
  char buf[512];
  memset(buf, 'x', 511);
  buf[511] = 0;
  return mqtt_different_length_client_id_impl(buf);
}
TEST_IMPL(mqtt_too_long_client_id_test) {
  char buf[1025];
  memset(buf, 'x', 1024);
  buf[1024] = 0;
  return mqtt_different_length_client_id_impl(buf);
}

typedef struct {
    int keep_alive;
    int done;
} client_ping_info_t;

static void mqtt_client_ping_client_cb(void* arg) {
  int err;
  client_ping_info_t* info = (client_ping_info_t*) arg;
  mymqtt_t client;
  mymqtt__init(&client, TS_PROTO_TCP, "client");
  mymqtt__set_keep_alive(&client, info->keep_alive);
  err = mymqtt__connect(&client);
  ASSERT_EQ(err, 0);
  
  unsigned long long end_time_marker = get_current_time_millis() + (info->keep_alive * 1.5 + 1) * 1000;
  while (end_time_marker > get_current_time_millis()) Sleep(1000);
  
  err = mymqtt__disconnect(&client);
  ASSERT_EQ(err, 0);
  info->done = 1;
}
static int mqtt_ping_impl(int keep_alive) {
  client_ping_info_t info;
  RESET_STRUCT(info);
  info.keep_alive = keep_alive;
  
  tm_t* server;
  tm_callbacks_t cbs;
  RESET_STRUCT(cbs);
  cbs.auth_cb = mqtt_auth_user_anonymous_cb;
  
  server = start_mqtt_server(TS_PROTO_TCP, &cbs);
  int r = tm__start(server);
  ASSERT_EQ(r, 0);
  
  uv_thread_t client_thread;
  uv_thread_create(&client_thread, mqtt_client_ping_client_cb, (void*)&info);
  
  while (info.done == 0) tm__run(server);
  
  tm__stop(server);
  uv_thread_join(&client_thread);
  return 0;
}

TEST_IMPL(mqtt_keep_alive_test) {
  return mqtt_ping_impl(3);
}
TEST_IMPL(mqtt_keep_alive_zero_test) {
  return mqtt_ping_impl(0);
}
