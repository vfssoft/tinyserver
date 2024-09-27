#include <tm.h>
#include "tinyunit.h"
#include "testutil.h"
#include "mymqtt.h"
#include "mytcp.h"

typedef struct {
    char pkt_buf[1024];
    int pkt_buf_len;
    
    int recv_done;
    char recv_buf[1024];
    int recv_buf_len;
} test_invalid_first_pkt_info_t;

void mqtt_server_auth_cb(void* ctx, tm_t* mq, const char* username, const char* password, int* ret_auth_ok) {
  *ret_auth_ok = 1;
}

static void mqtt_client_send_invalid_pkt_cb(void *arg) {
  int err;
  test_invalid_first_pkt_info_t* info = (test_invalid_first_pkt_info_t*)arg;
  mytcp_t client;
  mytcp__init_mutex();
  mytcp__init(&client);
  
  err = mytcp__connect(&client, "127.0.0.1", MQTT_PLAIN_PORT);
  ASSERT_EQ(err, 0);
  
  err = mytcp__write(&client, info->pkt_buf, info->pkt_buf_len);
  ASSERT_EQ(err, info->pkt_buf_len);
  
  err = mytcp__read(&client, info->recv_buf, 1024);
  info->recv_buf_len = err;
  
  err = mytcp__disconnect(&client);
  ASSERT_EQ(err, 0);
  
  info->recv_done = 1;
}
static int mqtt_invalid_first_packet_imp(const char* pkt, int len) {
  test_invalid_first_pkt_info_t info;
  memset(&info, 0, sizeof(info));
  memcpy(info.pkt_buf, pkt, len);
  info.pkt_buf_len = len;
  
  tm_t* server;
  tm_callbacks_t cbs;
  memset(&cbs, 0, sizeof(tm_callbacks_t));
  cbs.auth_cb = mqtt_server_auth_cb;

  server = start_mqtt_server(TS_PROTO_TCP, &cbs);
  int r = tm__start(server);
  ASSERT_EQ(r, 0);
  
  uv_thread_t client_thread;
  uv_thread_create(&client_thread, mqtt_client_send_invalid_pkt_cb, (void*)&info);
  
  while (info.recv_done == 0) {
    tm__run(server);
  }
  ASSERT_EQ(info.recv_buf_len, 0);
  
  tm__stop(server);
  uv_thread_join(&client_thread);
  
  return 0;
}

// [MQTT-2.2.2-1], [MQTT-2.2.2-2]
TEST_IMPL(mqtt_connect_invalid_reserved_flag_test) {
  const char* hex = "111a00044d5154540402000a000e746573745f636c69656e745f6964";
  int len = strlen(hex) / 2;
  char buf[63];
  decode_hex(hex, buf);
  return mqtt_invalid_first_packet_imp(buf, len);
}
// [MQTT-3.1.0-1]
TEST_IMPL(mqtt_invalid_first_pkt_test) {
  char buf[2] = { 0xe0, 0x00 }; // disconnect req
  return mqtt_invalid_first_packet_imp(buf, 2);
}
// [MQTT-3.1.2-1]
TEST_IMPL(mqtt_invalid_protocol_name_test) {
  const char* hex = "101a000"
                    "45d515454" // invalid protocol name
                    "0402000a000e746573745f636c69656e745f6964";
  int len = strlen(hex) / 2;
  char buf[63];
  decode_hex(hex, buf);
  return mqtt_invalid_first_packet_imp(buf, len);
}

TEST_IMPL(mqtt_invalid_will_flag_test) {
  // will flag is set, but no will
  const char* hex = "100c00044d5154540422000a0000";
  int len = strlen(hex) / 2;
  char buf[63];
  decode_hex(hex, buf);
  
  return mqtt_invalid_first_packet_imp(buf, len);
}
TEST_IMPL(mqtt_invalid_will_qos_test) {
  // will flag is not set, but will qos is not zero
  const char* hex = "100c00044d5154540412000a0000";
  int len = strlen(hex) / 2;
  char buf[63];
  decode_hex(hex, buf);
  
  return mqtt_invalid_first_packet_imp(buf, len);
}
TEST_IMPL(mqtt_invalid_user_name_flag_test) {
  // username flag is set, not no username
  const char* hex = "100c00044d5154540482000a0000";
  int len = strlen(hex) / 2;
  char buf[63];
  decode_hex(hex, buf);
  
  return mqtt_invalid_first_packet_imp(buf, len);
}
TEST_IMPL(mqtt_invalid_user_password_flag_test) {
  // username & password flags are set, not no username & password
  // TODO: it reaches a internal implementation bug, but it passes now. May be fix it later.
  const char* hex = "100c00044d51545404c2000a0000";
  int len = strlen(hex) / 2;
  char buf[63];
  decode_hex(hex, buf);
  
  return mqtt_invalid_first_packet_imp(buf, len);
}

static void mqtt_client_two_connects_cb(void *arg) {
  int err;
  test_invalid_first_pkt_info_t* info = (test_invalid_first_pkt_info_t*)arg;
  mytcp_t client;
  mytcp__init_mutex();
  mytcp__init(&client);
  
  err = mytcp__connect(&client, "127.0.0.1", MQTT_PLAIN_PORT);
  ASSERT_EQ(err, 0);
  
  err = mytcp__write(&client, info->pkt_buf, info->pkt_buf_len);
  ASSERT_EQ(err, info->pkt_buf_len);
  
  err = mytcp__read(&client, info->recv_buf, 1024);
  info->recv_buf_len = err;
  
  char tmpbuf[1];
  err = mytcp__read(&client, tmpbuf, 1);
  ASSERT_EQ(err, 0);
  
  err = mytcp__disconnect(&client);
  ASSERT_EQ(err, 0);
  
  info->recv_done = 1;
}
static int mqtt_two_connects_imp(const char* pkt, int len) {
  test_invalid_first_pkt_info_t info;
  memset(&info, 0, sizeof(info));
  memcpy(info.pkt_buf, pkt, len);
  info.pkt_buf_len = len;
  
  tm_t* server;
  tm_callbacks_t cbs;
  memset(&cbs, 0, sizeof(tm_callbacks_t));
  cbs.auth_cb = mqtt_server_auth_cb;
  
  server = start_mqtt_server(TS_PROTO_TCP, &cbs);
  int r = tm__start(server);
  ASSERT_EQ(r, 0);
  
  uv_thread_t client_thread;
  uv_thread_create(&client_thread, mqtt_client_two_connects_cb, (void*)&info);
  
  while (info.recv_done == 0) {
    tm__run(server);
  }
  ASSERT_EQ(info.recv_buf_len, 4);
  ASSERT_EQ(info.recv_buf[0], 0x20);
  ASSERT_EQ(info.recv_buf[1], 0x02);
  ASSERT_EQ(info.recv_buf[2], 0x00);
  ASSERT_EQ(info.recv_buf[3], 0x00);
  
  tm__stop(server);
  uv_thread_join(&client_thread);
  
  return 0;
}
// [MQTT-3.1.0-2]
TEST_IMPL(mqtt_two_connect_pkts) {
  const char* hex = "101a00044d5154540402000a000e746573745f636c69656e745f6964"
                    "101a00044d5154540402000a000e746573745f636c69656e745f6964";
  int len = strlen(hex) / 2;
  char buf[63];
  decode_hex(hex, buf);
  return mqtt_two_connects_imp(buf, len);
}

typedef struct {
    char pkt_buf[1024];
    int pkt_buf_len;
    
    int recv_done;
    char recv_buf[1024];
    int recv_buf_len;
} invalid_connect_connack_info_t;
static void mqtt_client_invalid_connect_connack_cb(void *arg) {
  int err;
  invalid_connect_connack_info_t* info = (invalid_connect_connack_info_t*)arg;
  mytcp_t client;
  mytcp__init_mutex();
  mytcp__init(&client);
  
  err = mytcp__connect(&client, "127.0.0.1", MQTT_PLAIN_PORT);
  ASSERT_EQ(err, 0);
  
  err = mytcp__write(&client, info->pkt_buf, info->pkt_buf_len);
  ASSERT_EQ(err, info->pkt_buf_len);
  
  err = mytcp__read(&client, info->recv_buf, 1024);
  info->recv_buf_len = err;
  
  char tmpbuf[1];
  err = mytcp__read(&client, tmpbuf, 1);
  ASSERT_EQ(err, 0);
  
  err = mytcp__disconnect(&client);
  ASSERT_EQ(err, 0);
  
  info->recv_done = 1;
}
static int mqtt_valid_connect_connack_imp(invalid_connect_connack_info_t* info) {
  tm_t* server;
  tm_callbacks_t cbs;
  memset(&cbs, 0, sizeof(tm_callbacks_t));
  cbs.auth_cb = mqtt_server_auth_cb;
  
  server = start_mqtt_server(TS_PROTO_TCP, &cbs);
  int r = tm__start(server);
  ASSERT_EQ(r, 0);
  
  uv_thread_t client_thread;
  uv_thread_create(&client_thread, mqtt_client_invalid_connect_connack_cb, (void*)info);
  
  while (info->recv_done == 0) {
    tm__run(server);
  }
  
  tm__stop(server);
  uv_thread_join(&client_thread);
  
  return 0;
}

// [MQTT-3.1.2-2]
TEST_IMPL(mqtt_valid_protocol_level_test) {
  const char* hex = "101a00044d515454"
                    "01" // invalid protocol level
                    "02000a000e746573745f636c69656e745f6964";
  int len = strlen(hex) / 2;
  char buf[63];
  decode_hex(hex, buf);
  
  invalid_connect_connack_info_t info;
  RESET_STRUCT(info);
  memcpy(info.pkt_buf, buf, len);
  info.pkt_buf_len = len;
  
  mqtt_valid_connect_connack_imp(&info);
  
  ASSERT_EQ(info.recv_buf_len, 4);
  ASSERT_EQ(info.recv_buf[0], 0x20);
  ASSERT_EQ(info.recv_buf[1], 0x02);
  ASSERT_EQ(info.recv_buf[2], 0x00);
  ASSERT_EQ(info.recv_buf[3], 0x01);
  return 0;
  
}

// [MQTT-3.1.3-8]
TEST_IMPL(mqtt_zero_clientid_but_not_clean_session_test) {
  const char* hex = "100c00044d5154540400000a0000";
  int len = strlen(hex) / 2;
  char buf[63];
  decode_hex(hex, buf);
  
  invalid_connect_connack_info_t info;
  RESET_STRUCT(info);
  memcpy(info.pkt_buf, buf, len);
  info.pkt_buf_len = len;
  
  mqtt_valid_connect_connack_imp(&info);
  
  ASSERT_EQ(info.recv_buf_len, 4);
  ASSERT_EQ(info.recv_buf[0], 0x20);
  ASSERT_EQ(info.recv_buf[1], 0x02);
  ASSERT_EQ(info.recv_buf[2], 0x00);
  ASSERT_EQ(info.recv_buf[3], 0x02);
  return 0;
}

typedef struct {
  int done;
} client_timed_out_info_t;
static void mqtt_client_timed_out_cb(void *arg) {
  int err;
  client_timed_out_info_t* info = (client_timed_out_info_t*)arg;
  mytcp_t client;
  mytcp__init_mutex();
  mytcp__init(&client);
  
  err = mytcp__connect(&client, "127.0.0.1", MQTT_PLAIN_PORT);
  ASSERT_EQ(err, 0);
  
  const char* hex = "101a00044d51545404020001000e746573745f636c69656e745f6964"; // keep_alive: 1s
  int len = strlen(hex) / 2;
  char buf[63];
  decode_hex(hex, buf);
  
  err = mytcp__write(&client, buf, len);
  ASSERT_EQ(err, len);
  
  err = mytcp__read(&client, buf, 4);
  ASSERT_EQ(err, 4);
  ASSERT_EQ(buf[3], 0x00); // acked
  
  wait(2500);
  
  char tmpbuf[1];
  err = mytcp__read(&client, tmpbuf, 1);
  ASSERT_EQ(err, 0);
  
  err = mytcp__disconnect(&client);
  ASSERT_EQ(err, 0);
  
  info->done = 1;
}
static int mqtt_keep_alive_timed_out_imp() {
  client_timed_out_info_t info;
  RESET_STRUCT(info);
  
  tm_t* server;
  tm_callbacks_t cbs;
  memset(&cbs, 0, sizeof(tm_callbacks_t));
  cbs.auth_cb = mqtt_server_auth_cb;
  
  server = start_mqtt_server(TS_PROTO_TCP, &cbs);
  int r = tm__start(server);
  ASSERT_EQ(r, 0);
  
  uv_thread_t client_thread;
  uv_thread_create(&client_thread, mqtt_client_timed_out_cb, (void*)&info);
  
  while (info.done == 0) {
    tm__run(server);
  }
  
  tm__stop(server);
  uv_thread_join(&client_thread);
  
  return 0;
}
TEST_IMPL(mqtt_keep_alive_timed_out_test) {
  return mqtt_keep_alive_timed_out_imp();
}


static void mqtt_client_on_pkt_after_connected_cb(void *arg) {
  int err;
  int* done = (int*)arg;
  mytcp_t client;
  mytcp__init_mutex();
  mytcp__init(&client);
  
  err = mytcp__connect(&client, "127.0.0.1", MQTT_PLAIN_PORT);
  ASSERT_EQ(err, 0);
  
  char tmpbuf[1];
  err = mytcp__read(&client, tmpbuf, 1);
  ASSERT_EQ(err, 0);
  
  err = mytcp__disconnect(&client);
  ASSERT_EQ(err, 0);
  
  *done = 1;
}
static int mqtt_no_pkt_after_connected_imp() {
  int done = 0;
  
  tm_t* server;
  tm_callbacks_t cbs;
  memset(&cbs, 0, sizeof(tm_callbacks_t));
  cbs.auth_cb = mqtt_server_auth_cb;
  
  server = start_mqtt_server(TS_PROTO_TCP, &cbs);
  int r = tm__start(server);
  ASSERT_EQ(r, 0);
  
  uv_thread_t client_thread;
  uv_thread_create(&client_thread, mqtt_client_on_pkt_after_connected_cb, (void*)&done);
  
  while (done == 0) {
    tm__run(server);
  }
  
  tm__stop(server);
  uv_thread_join(&client_thread);
  
  return 0;
}
TEST_IMPL(mqtt_no_pkt_after_connected_test) {
  return mqtt_no_pkt_after_connected_imp();
}


typedef struct {
    char connect_pkt[128];
    int connect_pkt_len;
    char second_pkt[128];
    int second_pkt_len;
    
    int done;
} test_invalid_second_pkt_info_t;

static void mqtt_client_send_invalid_second_pkt_cb(void *arg) {
  int err;
  test_invalid_second_pkt_info_t* info = (test_invalid_second_pkt_info_t*)arg;
  mytcp_t client;
  char recv_buf[128];
  mytcp__init_mutex();
  mytcp__init(&client);
  
  err = mytcp__connect(&client, "127.0.0.1", MQTT_PLAIN_PORT);
  ASSERT_EQ(err, 0);
  
  err = mytcp__write(&client, info->connect_pkt, info->connect_pkt_len);
  ASSERT_EQ(err, info->connect_pkt_len);
  
  err = mytcp__read(&client, recv_buf, 128);
  ASSERT_EQ(err, 4);
  
  err = mytcp__write(&client, info->second_pkt, info->second_pkt_len);
  ASSERT_EQ(err, info->second_pkt_len);
  
  err = mytcp__read(&client, recv_buf, 128);
  ASSERT_EQ(err, 0);
  
  info->done = 1;
}
static int mqtt_invalid_second_packet_imp(const char* pkt, int len) {
  test_invalid_second_pkt_info_t info;
  memset(&info, 0, sizeof(info));
  
  const char* connect_pkt_hex = "102400044d5154540402000a0018746573745f7075626c69736865725f636c69656e745f6964";
  decode_hex(connect_pkt_hex, (unsigned char*)info.connect_pkt);
  info.connect_pkt_len = strlen(connect_pkt_hex) / 2;
  
  memcpy(info.second_pkt, pkt, len);
  info.second_pkt_len = len;
  
  tm_t* server;
  tm_callbacks_t cbs;
  memset(&cbs, 0, sizeof(tm_callbacks_t));
  cbs.auth_cb = mqtt_server_auth_cb;
  
  server = start_mqtt_server(TS_PROTO_TCP, &cbs);
  int r = tm__start(server);
  ASSERT_EQ(r, 0);
  
  uv_thread_t client_thread;
  uv_thread_create(&client_thread, mqtt_client_send_invalid_second_pkt_cb, (void*)&info);
  
  while (info.done == 0) {
    tm__run(server);
  }
  
  tm__stop(server);
  uv_thread_join(&client_thread);
  
  return 0;
}

TEST_IMPL(mqtt_empty_subscribe) {
  char sub[] = { 0x82, 0x02, 0x00, 0x01 };
  return mqtt_invalid_second_packet_imp(sub, 4);
}
TEST_IMPL(mqtt_subscribe_invalid_reserved) {
  char sub[] = { 0x80, 0x02, 0x00, 0x01 };
  return mqtt_invalid_second_packet_imp(sub, 4);
}
TEST_IMPL(mqtt_subscribe_invalid_qos) {
  const char* hex = "820c00010007746f7069635f3111";
  unsigned char sub[32];
  decode_hex(hex, sub);
  return mqtt_invalid_second_packet_imp(sub, strlen(hex)/2);
}
TEST_IMPL(mqtt_subscribe_invalid_topic) {
  const char* hex = "820c00010007746f7069635f0001"; // ends with 0 is invalid
  unsigned char sub[32];
  decode_hex(hex, sub);
  return mqtt_invalid_second_packet_imp(sub, strlen(hex)/2);
}

TEST_IMPL(mqtt_empty_unsubscribe) {
  char unsub[] = { 0xA2, 0x02, 0x00, 0x02 };
  return mqtt_invalid_second_packet_imp(unsub, 4);
}
TEST_IMPL(mqtt_unsubscribe_invalid_reserved) {
  char unsub[] = { 0xA0, 0x02, 0x00, 0x02 };
  return mqtt_invalid_second_packet_imp(unsub, 4);
}
TEST_IMPL(mqtt_unsubscribe_invalid_topic) {
  const char* hex = "a20b00020007746f7069635f00"; // ends with 0 is invalid
  unsigned char unsub[32];
  decode_hex(hex, unsub);
  return mqtt_invalid_second_packet_imp(unsub, strlen(hex)/2);
}

TEST_IMPL(mqtt_unsubscribe_zero_pkt_id) {
  const char* hex = "a20b00000007746f7069635f20";
  unsigned char unsub[32];
  decode_hex(hex, unsub);
  return mqtt_invalid_second_packet_imp(unsub, strlen(hex)/2);
}

