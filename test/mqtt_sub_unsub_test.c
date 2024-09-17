#include <tm.h>
#include "tinyunit.h"
#include "testutil.h"
#include "mymqtt.h"

static void mqtt_auth_user_anonymous_cb(void* ctx, tm_t* mq, const char* username, const char* password, int* ret_auth_ok) {
  *ret_auth_ok = 1;
}
static void init_callbacks(tm_callbacks_t* cbs, void* cb_ctx) {
  memset(cbs, 0, sizeof(tm_callbacks_t));
  cbs->cb_ctx = cb_ctx;
  cbs->auth_cb = mqtt_auth_user_anonymous_cb;
}

typedef struct {
  int done;
  char sub_topic[64];
  char unsub_topic[64];
  int qos;
  
  int sub_fired;
  int unsub_fired;
} test_sub_unsub_info_t;

static void mqtt_sub_unsub_subscribe_cb(void* ctx, tm_t* mqt, ts_conn_t* conn, const char* topic, int requested_qos, int* granted_qos) {
  test_sub_unsub_info_t* info = (test_sub_unsub_info_t*) ctx;
  info->sub_fired++;
}
static void mqtt_sub_unsub_unsubscribe_cb(void* ctx, tm_t* mqt, ts_conn_t* conn, const char* topic) {
  test_sub_unsub_info_t* info = (test_sub_unsub_info_t*) ctx;
  info->unsub_fired++;
}
static void mqtt_client_sub_unsub_cb(void *arg) {
  int err;
  test_sub_unsub_info_t* info = (test_sub_unsub_info_t*) arg;
  mymqtt_t client;
  mymqtt__init(&client, TS_PROTO_TCP, "test_client_id");
  
  err = mymqtt__connect(&client);
  ASSERT_EQ(err, 0);
  
  err = mymqtt__subscribe(&client, info->sub_topic, info->qos);
  ASSERT_EQ(err, 0);
  
  err = mymqtt__unsubscribe(&client, info->unsub_topic);
  ASSERT_EQ(err, 0);
  
  err = mymqtt__disconnect(&client);
  ASSERT_EQ(err, 0);
  
  info->done = 1;
}
static int mqtt_sub_unsub_impl(const char* topic, int qos) {
  test_sub_unsub_info_t info;
  RESET_STRUCT(info);
  strcpy(info.sub_topic, topic);
  strcpy(info.unsub_topic, topic);
  info.qos = qos;
  
  tm_t* server;
  tm_callbacks_t cbs;
  init_callbacks(&cbs, &info);
  cbs.subscriber_cb = mqtt_sub_unsub_subscribe_cb;
  cbs.unsubscribe_cb = mqtt_sub_unsub_unsubscribe_cb;
  
  server = start_mqtt_server(TS_PROTO_TCP, &cbs);
  int r = tm__start(server);
  ASSERT_EQ(r, 0);
  
  uv_thread_t client_thread;
  uv_thread_create(&client_thread, mqtt_client_sub_unsub_cb, (void*)&info);
  
  while (info.done == 0) {
    tm__run(server);
  }
  ASSERT_EQ(info.sub_fired, 1);
  ASSERT_EQ(info.unsub_fired, 1);
  
  tm__stop(server);
  uv_thread_join(&client_thread);
  
  return 0;
}

TEST_IMPL(mqtt_sub_unsub_qos_0_test) {
  return mqtt_sub_unsub_impl("topic_0", 0);
}
TEST_IMPL(mqtt_sub_unsub_qos_1_test) {
  return mqtt_sub_unsub_impl("topic_1", 1);
}
TEST_IMPL(mqtt_sub_unsub_qos_2_test) {
  return mqtt_sub_unsub_impl("topic_2", 2);
}

static int mqtt_unsub_non_exist_impl(const char* sub_topic,const char* unsub_topic, int qos) {
  test_sub_unsub_info_t info;
  RESET_STRUCT(info);
  strcpy(info.sub_topic, sub_topic);
  strcpy(info.unsub_topic, unsub_topic);
  info.qos = qos;
  
  tm_t* server;
  tm_callbacks_t cbs;
  init_callbacks(&cbs, &info);
  cbs.subscriber_cb = mqtt_sub_unsub_subscribe_cb;
  cbs.unsubscribe_cb = mqtt_sub_unsub_unsubscribe_cb;
  
  server = start_mqtt_server(TS_PROTO_TCP, &cbs);
  int r = tm__start(server);
  ASSERT_EQ(r, 0);
  
  uv_thread_t client_thread;
  uv_thread_create(&client_thread, mqtt_client_sub_unsub_cb, (void*)&info);
  
  while (info.done == 0) {
    tm__run(server);
  }
  ASSERT_EQ(info.sub_fired, 1);
  ASSERT_EQ(info.unsub_fired, 1);
  
  tm__stop(server);
  uv_thread_join(&client_thread);
  
  return 0;
}

TEST_IMPL(mqtt_unsub_non_exist_qos_0_test) {
  return mqtt_unsub_non_exist_impl("topic_0", "fake_topic", 0);
}
TEST_IMPL(mqtt_unsub_non_exist_qos_1_test) {
  return mqtt_unsub_non_exist_impl("topic_1", "fake_topic", 1);
}
TEST_IMPL(mqtt_unsub_non_exist_qos_2_test) {
  return mqtt_unsub_non_exist_impl("topic_2", "fake_topic", 2);
}
TEST_IMPL(mqtt_unsub_non_exist_test_2) {
  return mqtt_unsub_non_exist_impl("A/B/?", "A/B/C", 2);
}
TEST_IMPL(mqtt_unsub_non_exist_test_3) {
  return mqtt_unsub_non_exist_impl("A/B/#", "A/B/C", 2);
}