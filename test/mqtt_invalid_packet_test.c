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

static int mqtt_valid_protocol_level_imp(const char* pkt, int len) {
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
  ASSERT_EQ(info.recv_buf[3], 0x01); // unacceptable protocol level
  
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
  return mqtt_valid_protocol_level_imp(buf, len);
}