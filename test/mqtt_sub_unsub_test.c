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

typedef struct {
    int done;
    const char** sub_topics;
    int sub_topics_count;
    const char** unsub_topics;
    int unsub_topics_count;
    
    int sub_fired;
    int unsub_fired;
} test_sub_unsub_many_info_t;

static void mqtt_sub_unsub_many_subscribe_cb(void* ctx, tm_t* mqt, ts_conn_t* conn, const char* topic, int requested_qos, int* granted_qos) {
  test_sub_unsub_many_info_t* info = (test_sub_unsub_many_info_t*) ctx;
  info->sub_fired++;
}
static void mqtt_sub_unsub_many_unsubscribe_cb(void* ctx, tm_t* mqt, ts_conn_t* conn, const char* topic) {
  test_sub_unsub_many_info_t* info = (test_sub_unsub_many_info_t*) ctx;
  info->unsub_fired++;
}
static void mqtt_client_sub_unsub_many_cb(void *arg) {
  int err;
  test_sub_unsub_many_info_t* info = (test_sub_unsub_many_info_t*) arg;
  mymqtt_t client;
  mymqtt__init(&client, TS_PROTO_TCP, "test_client_id");
  
  err = mymqtt__connect(&client);
  ASSERT_EQ(err, 0);
  
  int* qoss = malloc(sizeof(int) * info->sub_topics_count);
  for (int i = 0; i < info->sub_topics_count; i++) qoss[i] = 2;
  err = mymqtt__subscribe_many(&client, info->sub_topics, qoss, info->sub_topics_count);
  ASSERT_EQ(err, 0);
  
  err = mymqtt__unsubscribe_many(&client, info->unsub_topics, info->unsub_topics_count);
  ASSERT_EQ(err, 0);
  
  err = mymqtt__disconnect(&client);
  ASSERT_EQ(err, 0);
  
  free(qoss);
  info->done = 1;
}
static int mqtt_sub_unsub_many_impl(const char** sub_topics, int sub_topics_count, const char** unsub_topics, int unsub_topics_count) {
  test_sub_unsub_many_info_t info;
  RESET_STRUCT(info);
  info.sub_topics = sub_topics;
  info.sub_topics_count = sub_topics_count;
  info.unsub_topics = unsub_topics;
  info.unsub_topics_count = unsub_topics_count;
  
  tm_t* server;
  tm_callbacks_t cbs;
  init_callbacks(&cbs, &info);
  cbs.subscriber_cb = mqtt_sub_unsub_many_subscribe_cb;
  cbs.unsubscribe_cb = mqtt_sub_unsub_many_unsubscribe_cb;
  
  server = start_mqtt_server(TS_PROTO_TCP, &cbs);
  int r = tm__start(server);
  ASSERT_EQ(r, 0);
  
  uv_thread_t client_thread;
  uv_thread_create(&client_thread, mqtt_client_sub_unsub_many_cb, (void*)&info);
  
  while (info.done == 0) {
    tm__run(server);
  }
  ASSERT_EQ(info.sub_fired, sub_topics_count);
  ASSERT_EQ(info.unsub_fired, unsub_topics_count);
  
  tm__stop(server);
  uv_thread_join(&client_thread);
  
  return 0;
}
TEST_IMPL(mqtt_sub_unsub_many_test1) {
  const char* topics[] = {
    "/A/?",
    "Test/#",
    "A/B/C/D"
  };
  return mqtt_sub_unsub_many_impl(topics, ARRAYSIZE(topics), topics, ARRAYSIZE(topics));
}
TEST_IMPL(mqtt_sub_unsub_many_test2) {
  const char* sub_topics[] = {
      "/A/?",
      "Test/#",
      "A/B/C/D"
  };
  const char* unsub_topics[] = {
      "/A/?",
      "Test/#",
      //"A/B/C/D"
  };
  
  return mqtt_sub_unsub_many_impl(sub_topics, ARRAYSIZE(sub_topics), unsub_topics, ARRAYSIZE(unsub_topics));
}
TEST_IMPL(mqtt_sub_unsub_many_test3) {
  const char* sub_topics[] = {
      "/A/?",
      "Test/#",
      "A/B/C/D"
  };
  const char* unsub_topics[] = {
      "/A/?",
      "Test/#",
      "A/B/C/D"
      "HHH/hhh/test"
  };
  
  return mqtt_sub_unsub_many_impl(sub_topics, ARRAYSIZE(sub_topics), unsub_topics, ARRAYSIZE(unsub_topics));
}

typedef struct {
    int proto;
    char topic[64];
    int request_qos;
    int granted_qos;
    int done;
} test_grant_low_qos_info_t;

static void mqtt_grant_low_qos_subscribe_cb(void* ctx, tm_t* mqt, ts_conn_t* conn, const char* topic, int requested_qos, int* granted_qos) {
  //test_grant_low_qos_info_t* info = (test_grant_low_qos_info_t*) ctx;
  *granted_qos = 1;
}

static void mqtt_client_grant_low_qos_cb(void *arg) {
  int err;
  test_grant_low_qos_info_t* info = (test_grant_low_qos_info_t*) arg;
  mymqtt_t client;
  mymqtt__init(&client, info->proto, "test_client_id");
  
  err = mymqtt__connect(&client);
  ASSERT_EQ(err, 0);
  
  err = mymqtt__subscribe(&client, info->topic, info->request_qos);
  ASSERT_EQ(err, 0);
  
  // MQTTClient doesn't support query the granted qos, so we cannot verify it here.
  
  err = mymqtt__unsubscribe(&client, info->topic);
  ASSERT_EQ(err, 0);
  
  err = mymqtt__disconnect(&client);
  ASSERT_EQ(err, 0);
  
  info->done = 1;
}

TEST_IMPL(mqtt_grant_low_qos_value) {
  const char* topic = "test_topic";
  test_grant_low_qos_info_t info;
  RESET_STRUCT(info);
  info.proto = TS_PROTO_TCP;
  strcpy(info.topic, topic);
  info.request_qos = 2;
  
  tm_t* server;
  tm_callbacks_t cbs;
  init_callbacks(&cbs, &info);
  cbs.subscriber_cb = mqtt_grant_low_qos_subscribe_cb;
  
  server = start_mqtt_server(TS_PROTO_TCP, &cbs);
  int r = tm__start(server);
  ASSERT_EQ(r, 0);
  
  uv_thread_t client_thread;
  uv_thread_create(&client_thread, mqtt_client_grant_low_qos_cb, (void*)&info);
  
  while (info.done == 0) {
    tm__run(server);
  }
  
  tm__stop(server);
  uv_thread_join(&client_thread);
  
  return 0;
}