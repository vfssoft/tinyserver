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
  int proto;
  char client_id[128];
  char topic[128];
  int qos;
  int stop;
  int done;
} test_client_subscriber_info_t;

static void mqtt_client_subscriber_cb(void *arg) {
  int err;
  test_client_subscriber_info_t* info = (test_client_subscriber_info_t*) arg;
  mymqtt_t client;
  mymqtt__init(&client, info->proto, info->client_id);

  err = mymqtt__connect(&client);
  ASSERT_EQ(err, 0);

  err = mymqtt__subscribe(&client, info->topic, info->qos);
  ASSERT_EQ(err, 0);

  while (!info->stop) {
    Sleep(100);
  }

  err = mymqtt__unsubscribe(&client, info->topic);
  ASSERT_EQ(err, 0);

  err = mymqtt__disconnect(&client);
  ASSERT_EQ(err, 0);

  info->done = 1;
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

static int mqtt_basic_pub_impl(int proto, const char* topic, int qos, char* payload, int payload_len) {
  test_client_publisher_info_t info;
  RESET_STRUCT(info);
  info.proto = proto;
  strcpy(info.client_id, "test_publisher_client_id");
  strcpy(info.topic, topic);
  info.qos = qos;
  info.payload_len = payload_len;
  info.payload = payload;
  
  tm_t* server;
  tm_callbacks_t cbs;
  init_callbacks(&cbs, &info);
  
  server = start_mqtt_server(proto, &cbs);
  int r = tm__start(server);
  ASSERT_EQ(r, 0);
  
  uv_thread_t client_thread;
  uv_thread_create(&client_thread, mqtt_client_publisher_cb, (void*)&info);
  
  while (info.done == 0) {
    tm__run(server);
  }
  
  tm__stop(server);
  uv_thread_join(&client_thread);
  
  return 0;
}

TEST_IMPL(mqtt_basic_pub_qos0_test) {
  return mqtt_basic_pub_impl(TS_PROTO_TCP, "a", 0, "hello", 5);
}
TEST_IMPL(mqtt_basic_pub_qos1_test) {
  return mqtt_basic_pub_impl(TS_PROTO_TCP, "a", 1, "hello", 5);
}
TEST_IMPL(mqtt_basic_pub_qos2_test) {
  return mqtt_basic_pub_impl(TS_PROTO_TCP, "a", 2, "hello", 5);
}