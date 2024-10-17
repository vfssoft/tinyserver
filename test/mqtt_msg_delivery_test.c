#include <tm.h>
#include "tinyunit.h"
#include "testutil.h"
#include "mymqtt.h"
#include "mytcp.h"

static void mqtt_auth_user_anonymous_cb(void* ctx, tm_t* mq, const char* username, const char* password, int* ret_auth_ok) {
  *ret_auth_ok = 1;
}
static void init_callbacks(tm_callbacks_t* cbs, void* cb_ctx) {
  memset(cbs, 0, sizeof(tm_callbacks_t));
  cbs->cb_ctx = cb_ctx;
  cbs->auth_cb = mqtt_auth_user_anonymous_cb;
}

typedef struct {
    int proto;
    char client_id[128];
    char topic[128];
    int qos;
    char* payload;
    int payload_len;
    int retain;
    int done;
} test_client_publisher_info_t;
static void mqtt_client_publisher_cb(void *arg) {
  int err;
  test_client_publisher_info_t* info = (test_client_publisher_info_t*) arg;
  mymqtt_t client;
  mymqtt__init(&client, info->proto, info->client_id);
  
  err = mymqtt__connect(&client);
  ASSERT_EQ(err, 0);
  
  err = mymqtt__publish(&client, info->topic, info->payload, info->payload_len, info->qos, info->retain);
  ASSERT_EQ(err, 0);
  
  err = mymqtt__disconnect(&client);
  ASSERT_EQ(err, 0);
  
  info->done = 1;
}
static int mqtt_publish_a_msg(tm_t* server, int proto, const char* topic, int qos, char* payload, int payload_len, BOOL retain) {
  test_client_publisher_info_t info;
  RESET_STRUCT(info);
  info.proto = proto;
  strcpy(info.client_id, "test_publisher_client_id");
  strcpy(info.topic, topic);
  info.qos = qos;
  info.payload_len = payload_len;
  info.payload = payload;
  info.retain = retain;
  
  uv_thread_t publisher_thread;
  uv_thread_create(&publisher_thread, mqtt_client_publisher_cb, (void*)&info);
  while (info.done == 0) { tm__run(server); }
  uv_thread_join(&publisher_thread);
  return 0;
}

typedef struct {
  int done;
} client_resend_publish_qos1_info_t;

static void client_resend_publish_qos1_cb(void *arg) {
  client_resend_publish_qos1_info_t* info = (client_resend_publish_qos1_info_t*) arg;
  
  char conn_bytes[1024];
  int conn_bytes_len = build_connect_pkt(conn_bytes, "subscriber", FALSE, NULL, NULL, NULL, 0, NULL, 0, FALSE, 30);
  
  char sub_bytes[128];
  int sub_bytes_len = build_subscribe_pkt(sub_bytes, 1, "test", 1);
  
  int err;
  mytcp_t client;
  char recv_buf[1024];
  mytcp__init_mutex();
  mytcp__init(&client);
  
  err = mytcp__connect(&client, "127.0.0.1", MQTT_PLAIN_PORT);
  ASSERT_EQ(err, 0);
  
  // connect
  err = mytcp__write(&client, conn_bytes, conn_bytes_len);
  ASSERT_EQ(err, conn_bytes_len);
  err = mytcp__read(&client, recv_buf, 1024);
  ASSERT_EQ(err, 4);
  
  // subscribe
  err = mytcp__write(&client, sub_bytes, sub_bytes_len);
  ASSERT_EQ(err, sub_bytes_len);
  err = mytcp__read(&client, recv_buf, 1024);
  ASSERT_EQ(err, 5);
  
  // wait message
  mytcp__read(&client, recv_buf, 1024);
  
  // disconnect without sending puback
  mytcp__disconnect(&client);
  
  // re-connect
  err = mytcp__connect(&client, "127.0.0.1", MQTT_PLAIN_PORT);
  ASSERT_EQ(err, 0);
  
  // connect
  err = mytcp__write(&client, conn_bytes, conn_bytes_len);
  ASSERT_EQ(err, conn_bytes_len);
  err = mytcp__read(&client, recv_buf, 1024);
  ASSERT_EQ(err, 4);
  
  // server should resend publish to us
  err = mytcp__read(&client, recv_buf, 128);
  ASSERT_EQ(err, 15);
  ASSERT_EQ(recv_buf[0], 0x3a); // DUP, QoS 1, Not retain
  ASSERT_EQ(recv_buf[8], 0x00);
  ASSERT_EQ(recv_buf[9], 0x01); // packet id

  info->done = 1;
}
TEST_IMPL(mqtt_msg_delivery_resend_puback) {
  client_resend_publish_qos1_info_t info;
  RESET_STRUCT(info);
  
  tm_t* server;
  tm_callbacks_t cbs;
  init_callbacks(&cbs, &info);
  
  server = start_mqtt_server(TS_PROTO_TCP, &cbs);
  int r = tm__start(server);
  ASSERT_EQ(r, 0);
  
  uv_thread_t client_thread;
  uv_thread_create(&client_thread, client_resend_publish_qos1_cb, (void*)&info);
  
  mqtt_publish_a_msg(server, TS_PROTO_TCP, "test", 1, "hello", 5, FALSE);
  
  while (info.done == 0) {
    tm__run(server);
  }
  
  tm__stop(server);
  uv_thread_join(&client_thread);
  
  return 0;
}