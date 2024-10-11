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
  int timeoutms;
  int exp_recv_count;
  int subscribed;
  int done;
    
  mymqtt_msg_t msgs[32]; // msg received
  int msgs_count;
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
  
  info->subscribed = 1;
  
  long long int start = get_current_time_millis();
  while (1) {
    Sleep(20);
    
    if (info->timeoutms > 0) {
      long long int current = get_current_time_millis();
      if (current - start >= info->timeoutms) {
        break;
      }
    }
    if (mymqtt__recv_msg_count(&client) >= info->exp_recv_count) {
      break;
    }
  }
  
  if (mymqtt__recv_msg_count(&client) >= 0) {
    info->msgs_count = mymqtt__recv_msgs(&client, info->msgs);
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
static test_client_subscriber_info_t* mqtt_subscriber_start(tm_t* server, uv_thread_t* thread, int proto, const char* topic, int qos, int timeoutms) {
  test_client_subscriber_info_t* info = (test_client_subscriber_info_t*) malloc(sizeof(test_client_subscriber_info_t));
  memset(info, 0, sizeof(test_client_subscriber_info_t));
  info->proto = proto;
  strcpy(info->client_id, "tet_subscriber_client_id");
  strcpy(info->topic, topic);
  info->qos = qos;
  info->timeoutms = timeoutms;
  info->exp_recv_count = 1;
  
  uv_thread_create(thread, mqtt_client_subscriber_cb, (void*)info);
  while (info->subscribed == 0) { tm__run(server); }
  return info;
}
static int mqtt_subscriber_stop(tm_t* server, uv_thread_t* thread,  test_client_subscriber_info_t* info) {
  while (info->done == 0) { tm__run(server); }
  uv_thread_join(thread);
  return 0;
}

static int mqtt_basic_pub_recv_impl(
    int proto,
    const char* pub_topic, int pub_qos, char* payload, int payload_len,
    const char* sub_topic, int sub_qos
) {
  test_client_subscriber_info_t* subscriber_info;
  uv_thread_t subscriber_thread;
  
  tm_t* server;
  tm_callbacks_t cbs;
  init_callbacks(&cbs, NULL);

  server = start_mqtt_server(proto, &cbs);
  int r = tm__start(server);
  ASSERT_EQ(r, 0);
  
  subscriber_info = mqtt_subscriber_start(server, &subscriber_thread, proto, sub_topic, sub_qos, 500);
  
  mqtt_publish_a_msg(server, proto, pub_topic, pub_qos, payload, payload_len, FALSE);
  
  mqtt_subscriber_stop(server, &subscriber_thread, subscriber_info);
  
  tm__stop(server);
  
  ASSERT_EQ(subscriber_info->msgs_count, 1);
  mymqtt_msg_t* msg = &(subscriber_info->msgs[0]);
  ASSERT_STR_EQ(msg->topic, sub_topic);
  ASSERT_EQ(msg->qos, (sub_qos > pub_qos ? pub_qos : sub_qos));
  ASSERT_EQ(msg->payload_len, payload_len);
  ASSERT_MEM_EQ(payload, (char*)msg->payload, payload_len);
  
  return 0;
}

TEST_IMPL(mqtt_basic_pub_recv_qos0_tcp) {
  return mqtt_basic_pub_recv_impl(
      TS_PROTO_TCP,
      "topic", 0, "ABC", 3,
      "topic", 0
  );
}
TEST_IMPL(mqtt_basic_pub_recv_qos1_tcp) {
  return mqtt_basic_pub_recv_impl(
      TS_PROTO_TCP,
      "topic", 1, "ABC", 3,
      "topic", 1
  );
}
TEST_IMPL(mqtt_basic_pub_recv_qos2_tcp) {
  return mqtt_basic_pub_recv_impl(
      TS_PROTO_TCP,
      "topic", 2, "ABC", 3,
      "topic", 2
  );
}

typedef struct {
    int proto;
    char client_id[128];
    char topic[128];
    int qos;
    char* payload;
    int payload_len;
    int retain;
    int disconnect_abnormal;
    int done;
} test_client_will_info_t;
static void mqtt_client_with_will_cb(void *arg) {
  int err;
  test_client_will_info_t* info = (test_client_will_info_t*) arg;
  mymqtt_t client;
  mymqtt__init(&client, info->proto, info->client_id);
  
  mymqtt__set_keep_alive(&client, 1);
  mymqtt__set_will(&client, info->topic, info->qos, info->payload, info->payload_len, info->retain);
  
  err = mymqtt__connect(&client);
  ASSERT_EQ(err, 0);
  
  if (info->disconnect_abnormal) {
    // invalid topic will cause the server disconnect us
    mymqtt__subscribe(&client, "###", 1);
  } else {
    err = mymqtt__disconnect(&client);
    ASSERT_EQ(err, 0);
  }
  
  info->done = 1;
}
static int mqtt_connect_with_will_msg(tm_t* server, int proto, const char* topic, int qos, char* payload, int payload_len, BOOL retain, int disconnect_abnormal) {
  test_client_will_info_t info;
  RESET_STRUCT(info);
  info.proto = proto;
  strcpy(info.client_id, "test_will_client_id");
  strcpy(info.topic, topic);
  info.qos = qos;
  info.payload_len = payload_len;
  info.payload = payload;
  info.retain = retain;
  info.disconnect_abnormal = disconnect_abnormal;
  
  uv_thread_t publisher_thread;
  uv_thread_create(&publisher_thread, mqtt_client_with_will_cb, (void*)&info);
  while (info.done == 0) { tm__run(server); }
  uv_thread_join(&publisher_thread);
  return 0;
}
static int mqtt_basic_will_msg_impl(int proto, int disconnect_abnormal, int retain) {
  test_client_subscriber_info_t* subscriber_info;
  uv_thread_t subscriber_thread;
  
  const char* will_topic = "will_topic";
  char* payload = "hello will";
  
  tm_t* server;
  tm_callbacks_t cbs;
  init_callbacks(&cbs, NULL);
  
  server = start_mqtt_server(proto, &cbs);
  int r = tm__start(server);
  ASSERT_EQ(r, 0);
  
  subscriber_info = mqtt_subscriber_start(server, &subscriber_thread, proto, will_topic, 1, 10000);
  
  mqtt_connect_with_will_msg(server, proto, will_topic, 1, payload, strlen(payload), retain, disconnect_abnormal);
  
  mqtt_subscriber_stop(server, &subscriber_thread, subscriber_info);
  
  tm__stop(server);
  
  if (disconnect_abnormal) {
    ASSERT_EQ(subscriber_info->msgs_count, 1);
    mymqtt_msg_t* msg = &(subscriber_info->msgs[0]);
    ASSERT_STR_EQ(msg->topic, will_topic);
    ASSERT_EQ(msg->qos, 1);
    ASSERT_MEM_EQ(payload, (char*)msg->payload, msg->payload_len);
    ASSERT_EQ(msg->retained, 0);
  } else {
    ASSERT_EQ(subscriber_info->msgs_count, 0);
  }
  
  return 0;
}
TEST_IMPL(mqtt_not_pub_will_if_client_disconnect_normally) {
  return mqtt_basic_will_msg_impl(TS_PROTO_TCP, 0, FALSE);
}
TEST_IMPL(mqtt_pub_will_if_client_disconnect_abnormally) {
  return mqtt_basic_will_msg_impl(TS_PROTO_TCP, 1, FALSE);
}
TEST_IMPL(mqtt_pub_will_if_client_disconnect_abnormally_retain) {
  return mqtt_basic_will_msg_impl(TS_PROTO_TCP, 1, TRUE);
}


TEST_IMPL(mqtt_retain_msg_current_subscription) {
  test_client_subscriber_info_t* subscriber_info;
  uv_thread_t subscriber_thread;
  
  int proto = TS_PROTO_TCP;
  const char* topic = "retain_topic";
  int qos = 1;
  char* payload = "hello retain message";
  
  tm_t* server;
  tm_callbacks_t cbs;
  init_callbacks(&cbs, NULL);
  
  server = start_mqtt_server(proto, &cbs);
  int r = tm__start(server);
  ASSERT_EQ(r, 0);
  
  subscriber_info = mqtt_subscriber_start(server, &subscriber_thread, proto, topic, qos, 500);
  
  mqtt_publish_a_msg(server, proto, topic, qos, payload, strlen(payload), TRUE);
  
  mqtt_subscriber_stop(server, &subscriber_thread, subscriber_info);
  
  tm__stop(server);
  
  ASSERT_EQ(subscriber_info->msgs_count, 1);
  mymqtt_msg_t* msg = &(subscriber_info->msgs[0]);
  ASSERT_STR_EQ(msg->topic, topic);
  ASSERT_EQ(msg->qos, qos);
  ASSERT_EQ(msg->payload_len, strlen(payload));
  ASSERT_MEM_EQ(payload, (char*)msg->payload, msg->payload_len);
  
  ASSERT_EQ(msg->retained, FALSE);
  
  return 0;
}

TEST_IMPL(mqtt_retain_msg_new_subscription) {
  test_client_subscriber_info_t* subscriber_info;
  uv_thread_t subscriber_thread;
  
  int proto = TS_PROTO_TCP;
  const char* topic = "retain_topic";
  int qos = 1;
  char* payload = "hello retain message";
  
  tm_t* server;
  tm_callbacks_t cbs;
  init_callbacks(&cbs, NULL);
  
  server = start_mqtt_server(proto, &cbs);
  int r = tm__start(server);
  ASSERT_EQ(r, 0);
  
  mqtt_publish_a_msg(server, proto, topic, qos, payload, strlen(payload), TRUE);
  
  subscriber_info = mqtt_subscriber_start(server, &subscriber_thread, proto, topic, qos, 500);
  
  mqtt_subscriber_stop(server, &subscriber_thread, subscriber_info);
  
  tm__stop(server);
  
  ASSERT_EQ(subscriber_info->msgs_count, 1);
  mymqtt_msg_t* msg = &(subscriber_info->msgs[0]);
  ASSERT_STR_EQ(msg->topic, topic);
  ASSERT_EQ(msg->qos, qos);
  ASSERT_EQ(msg->payload_len, strlen(payload));
  ASSERT_MEM_EQ(payload, (char*)msg->payload, msg->payload_len);
  
  ASSERT_EQ(msg->retained, TRUE);
  
  return 0;
}
TEST_IMPL(mqtt_retain_msg_zero_byte) {
  test_client_subscriber_info_t* subscriber_info;
  uv_thread_t subscriber_thread;
  
  int proto = TS_PROTO_TCP;
  const char* topic = "retain_message_zero_byte_payload";
  int qos = 1;
  char* payload = "";
  
  tm_t* server;
  tm_callbacks_t cbs;
  init_callbacks(&cbs, NULL);
  
  server = start_mqtt_server(proto, &cbs);
  int r = tm__start(server);
  ASSERT_EQ(r, 0);
  
  mqtt_publish_a_msg(server, proto, topic, qos, payload, strlen(payload), TRUE);
  
  subscriber_info = mqtt_subscriber_start(server, &subscriber_thread, proto, topic, qos, 1000);
  
  mqtt_subscriber_stop(server, &subscriber_thread, subscriber_info);
  
  tm__stop(server);
  
  ASSERT_EQ(subscriber_info->msgs_count, 0);
  
  return 0;
}
TEST_IMPL(mqtt_retain_msg_zero_byte_1) {
  test_client_subscriber_info_t* subscriber_info;
  uv_thread_t subscriber_thread;
  
  int proto = TS_PROTO_TCP;
  const char* topic = "retain_message_zero_byte_payload";
  int qos = 1;
  char* payload = "";
  
  tm_t* server;
  tm_callbacks_t cbs;
  init_callbacks(&cbs, NULL);
  
  server = start_mqtt_server(proto, &cbs);
  int r = tm__start(server);
  ASSERT_EQ(r, 0);
  
  subscriber_info = mqtt_subscriber_start(server, &subscriber_thread, proto, topic, qos, 500);
  
  mqtt_publish_a_msg(server, proto, topic, qos, payload, 0, TRUE);
  
  mqtt_subscriber_stop(server, &subscriber_thread, subscriber_info);
  
  tm__stop(server);
  
  ASSERT_EQ(subscriber_info->msgs_count, 1);
  mymqtt_msg_t* msg = &(subscriber_info->msgs[0]);
  ASSERT_STR_EQ(msg->topic, topic);
  ASSERT_EQ(msg->qos, qos);
  ASSERT_EQ(msg->payload_len, 0);
  ASSERT_EQ(msg->retained, FALSE);
  
  return 0;
}
TEST_IMPL(mqtt_retain_msg_zero_byte_2) {
  test_client_subscriber_info_t* subscriber_info;
  uv_thread_t subscriber_thread;
  
  int proto = TS_PROTO_TCP;
  const char* topic = "retain_message_zero_byte_payload";
  int qos = 1;
  
  tm_t* server;
  tm_callbacks_t cbs;
  init_callbacks(&cbs, NULL);
  
  server = start_mqtt_server(proto, &cbs);
  int r = tm__start(server);
  ASSERT_EQ(r, 0);
  
  mqtt_publish_a_msg(server, proto, topic, qos, "A", 1, TRUE); // create a retained message
  mqtt_publish_a_msg(server, proto, topic, qos, "", 0, TRUE); // remove the retained message
  
  subscriber_info = mqtt_subscriber_start(server, &subscriber_thread, proto, topic, qos, 1000);
  
  mqtt_subscriber_stop(server, &subscriber_thread, subscriber_info);
  
  tm__stop(server);
  
  ASSERT_EQ(subscriber_info->msgs_count, 0);
  
  return 0;
}
TEST_IMPL(mqtt_retain_msg_zero_byte_3) {
  test_client_subscriber_info_t* subscriber_info;
  uv_thread_t subscriber_thread;
  
  int proto = TS_PROTO_TCP;
  const char* topic = "retain_message_zero_byte_payload";
  int qos = 1;
  
  tm_t* server;
  tm_callbacks_t cbs;
  init_callbacks(&cbs, NULL);
  
  server = start_mqtt_server(proto, &cbs);
  int r = tm__start(server);
  ASSERT_EQ(r, 0);
  
  mqtt_publish_a_msg(server, proto, topic, qos, "A", 1, TRUE); // create a retained message
  mqtt_publish_a_msg(server, proto, topic, qos, "", 0, FALSE); // public a message with the same topic but not retained
  
  subscriber_info = mqtt_subscriber_start(server, &subscriber_thread, proto, topic, qos, 500);
  
  mqtt_subscriber_stop(server, &subscriber_thread, subscriber_info);
  
  tm__stop(server);
  
  ASSERT_EQ(subscriber_info->msgs_count, 1);
  mymqtt_msg_t* msg = &(subscriber_info->msgs[0]);
  ASSERT_STR_EQ(msg->topic, topic);
  ASSERT_EQ(msg->qos, qos);
  ASSERT_EQ(msg->payload_len, 1);
  ASSERT_EQ(msg->retained, TRUE);
  
  return 0;
}
TEST_IMPL(mqtt_retain_msg_update_exist) {
  test_client_subscriber_info_t* subscriber_info;
  uv_thread_t subscriber_thread;
  
  int proto = TS_PROTO_TCP;
  const char* topic = "retain_message_topic";
  int qos = 1;
  
  tm_t* server;
  tm_callbacks_t cbs;
  init_callbacks(&cbs, NULL);
  
  server = start_mqtt_server(proto, &cbs);
  int r = tm__start(server);
  ASSERT_EQ(r, 0);
  
  mqtt_publish_a_msg(server, proto, topic, qos, "A", 1, TRUE); // create a retained message
  mqtt_publish_a_msg(server, proto, topic, qos, "B", 1, TRUE); // update the retained message
  
  subscriber_info = mqtt_subscriber_start(server, &subscriber_thread, proto, topic, qos, 500);
  
  mqtt_subscriber_stop(server, &subscriber_thread, subscriber_info);
  
  tm__stop(server);
  
  ASSERT_EQ(subscriber_info->msgs_count, 1);
  mymqtt_msg_t* msg = &(subscriber_info->msgs[0]);
  ASSERT_STR_EQ(msg->topic, topic);
  ASSERT_EQ(msg->qos, qos);
  ASSERT_EQ(msg->payload_len, 1);
  ASSERT_MEM_EQ(msg->payload, "B", 1);
  ASSERT_EQ(msg->retained, TRUE);
  
  return 0;
}