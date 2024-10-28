#include <tm.h>
#include "tinyunit.h"
#include "testutil.h"
#include "mymqtt.h"

static void mqtt_auth_user_anonymous_cb(void* ctx, tm_t* mq, const char* username, const char* password, int* ret_auth_ok) {
  *ret_auth_ok = 1;
}

typedef struct {
    int proto;
    char client_id[128];
    int done;
    
    msgs_t* msgs;
    int intervalms;
} test_client_publisher_info_t;

static void mqtt_client_publisher_cb(void *arg) {
  int err;
  test_client_publisher_info_t* info = (test_client_publisher_info_t*) arg;
  mymqtt_t client;
  msg_t* msg;
  
  mymqtt__init(&client, info->proto, info->client_id);
  
  err = mymqtt__connect(&client);
  ASSERT_EQ(err, 0);
  
  for (int i = 0; i < msgs__count(info->msgs); i++) {
    msg = msgs__at(info->msgs, i);
    err = mymqtt__publish(
        &client,
        msg->topic,
        msg->payload,
        msg->payload_len,
        msg->qos,
        msg->retained
    );
    ASSERT_EQ(err, 0);
  
    mysleep(info->intervalms);
  }
  
  err = mymqtt__disconnect(&client);
  ASSERT_EQ(err, 0);
  
  info->done = 1;
}
static int mqtt_publish_msgs(tm_t* server, int proto, msgs_t* msgs, int pub_interval) {
  test_client_publisher_info_t info;
  RESET_STRUCT(info);
  info.proto = proto;
  strcpy(info.client_id, "test_publisher_client_id");
  info.msgs = msgs;
  info.intervalms = pub_interval;
  
  uv_thread_t publisher_thread;
  
  uv_thread_create(&publisher_thread, mqtt_client_publisher_cb, (void*)&info);
  while (info.done == 0) { tm__run(server); }
  uv_thread_join(&publisher_thread);
  return 0;
}

typedef struct {
    int proto;
    int clean_session;
    char client_id[128];
    char topic[128];
    int qos;
    int timeoutms;
    int exp_recv_count;
    int subscribed;
    int skip_sub;
    int done;
    
    msgs_t* msgs; // msg received
} test_client_subscriber_info_t;

static void mqtt_client_subscriber_cb(void *arg) {
  int err;
  test_client_subscriber_info_t* info = (test_client_subscriber_info_t*) arg;
  mymqtt_t client;
  mymqtt__init(&client, info->proto, info->client_id);
  
  client.options.cleansession = info->clean_session;
  
  err = mymqtt__connect(&client);
  ASSERT_EQ(err, 0);
  
  if (!info->skip_sub) {
    err = mymqtt__subscribe(&client, info->topic, info->qos);
    ASSERT_EQ(err, 0);
  }
  
  info->subscribed = 1;
  
  long long int start = get_current_time_millis();
  while (1) {
    mysleep(20);
    
    if (info->timeoutms > 0) {
      long long int current = get_current_time_millis();
      if (current - start >= info->timeoutms) {
        break;
      }
    }
    if (msgs__count(client.msgs) >= info->exp_recv_count) {
      break;
    }
  }
  
  if (msgs__count(client.msgs) > 0) {
    info->msgs = msgs__clone(client.msgs);
  }
  
  if (!info->skip_sub) {
    err = mymqtt__unsubscribe(&client, info->topic);
    ASSERT_EQ(err, 0);
  }
  
  err = mymqtt__disconnect(&client);
  ASSERT_EQ(err, 0);
  
  info->done = 1;
}
static test_client_subscriber_info_t* mqtt_subscriber_start_ex(tm_t* server, uv_thread_t* thread, int proto, const char* topic, int qos, int timeoutms, int exp_receive_count, const char* client_id, int clean_session, int skip_sub) {
  test_client_subscriber_info_t* info = (test_client_subscriber_info_t*) malloc(sizeof(test_client_subscriber_info_t));
  memset(info, 0, sizeof(test_client_subscriber_info_t));
  info->proto = proto;
  info->clean_session = clean_session;
  strcpy(info->client_id, client_id);
  strcpy(info->topic, topic);
  info->qos = qos;
  info->timeoutms = timeoutms;
  info->exp_recv_count = exp_receive_count;
  info->skip_sub = skip_sub;
  
  uv_thread_create(thread, mqtt_client_subscriber_cb, (void*)info);
  while (info->subscribed == 0) { tm__run(server); }
  return info;
}
static test_client_subscriber_info_t* mqtt_subscriber_start(tm_t* server, uv_thread_t* thread, int proto, const char* topic, int qos, int timeoutms, int exp_receive_count) {
  return mqtt_subscriber_start_ex(server, thread, proto, topic, qos, timeoutms, exp_receive_count, "tet_subscriber_client_id", 1, 0);
}
static int mqtt_subscriber_stop(tm_t* server, uv_thread_t* thread,  test_client_subscriber_info_t* info) {
  while (info->done == 0) { tm__run(server); }
  uv_thread_join(thread);
  return 0;
}


static int mqtt_singe_pub_single_single_sub_many_msgs_impl(int proto, int msg_count, int qos) {
  test_client_subscriber_info_t* subscriber_info;
  uv_thread_t subscriber_thread;
  msgs_t* msgs;
  
  tm_t* server;
  tm_callbacks_t cbs;
  memset(&cbs, 0, sizeof(tm_callbacks_t));
  cbs.auth_cb = mqtt_auth_user_anonymous_cb;
  
  server = start_mqtt_server(proto, &cbs);
  int r = tm__start(server);
  ASSERT_EQ(r, 0);
  
  subscriber_info = mqtt_subscriber_start(server, &subscriber_thread, proto, "#", 2, msg_count * 100, msg_count);
  
  msgs = msgs__create(msg_count);
  for (int i = 0; i < msg_count; i++) {
    msgs__add2(msgs, "/TEST", "A", 1, qos, 0, 0);
  }
  
  mqtt_publish_msgs(server, proto, msgs, 0);
  
  mqtt_subscriber_stop(server, &subscriber_thread, subscriber_info);
  
  tm__stop(server);
  msgs__destroy(msgs);
  
  ASSERT_EQ(msgs__count(subscriber_info->msgs), msg_count);
  
  return 0;
}

TEST_IMPL(mqtt_singe_pub_single_single_sub_1000_msgs_qos_0_tcp) {
  return mqtt_singe_pub_single_single_sub_many_msgs_impl(TS_PROTO_TCP, 1000, 0);
}
TEST_IMPL(mqtt_singe_pub_single_single_sub_1000_msgs_qos_0_tls) {
  return mqtt_singe_pub_single_single_sub_many_msgs_impl(TS_PROTO_TLS, 1000, 0);
}
TEST_IMPL(mqtt_singe_pub_single_single_sub_1000_msgs_qos_0_ws) {
  return mqtt_singe_pub_single_single_sub_many_msgs_impl(TS_PROTO_WS, 1000, 0);
}
TEST_IMPL(mqtt_singe_pub_single_single_sub_1000_msgs_qos_0_wss) {
  return mqtt_singe_pub_single_single_sub_many_msgs_impl(TS_PROTO_WSS, 1000, 0);
}


TEST_IMPL(mqtt_singe_pub_single_single_sub_1000_msgs_qos_1_tcp) {
  return mqtt_singe_pub_single_single_sub_many_msgs_impl(TS_PROTO_TCP, 1000, 1);
}
TEST_IMPL(mqtt_singe_pub_single_single_sub_1000_msgs_qos_1_tls) {
  return mqtt_singe_pub_single_single_sub_many_msgs_impl(TS_PROTO_TLS, 1000, 1);
}
TEST_IMPL(mqtt_singe_pub_single_single_sub_1000_msgs_qos_1_ws) {
  return mqtt_singe_pub_single_single_sub_many_msgs_impl(TS_PROTO_WS, 1000, 1);
}
TEST_IMPL(mqtt_singe_pub_single_single_sub_1000_msgs_qos_1_wss) {
  return mqtt_singe_pub_single_single_sub_many_msgs_impl(TS_PROTO_WSS, 1000, 1);
}

TEST_IMPL(mqtt_singe_pub_single_single_sub_1000_msgs_qos_2_tcp) {
  return mqtt_singe_pub_single_single_sub_many_msgs_impl(TS_PROTO_TCP, 1000, 2);
}
TEST_IMPL(mqtt_singe_pub_single_single_sub_1000_msgs_qos_2_tls) {
  return mqtt_singe_pub_single_single_sub_many_msgs_impl(TS_PROTO_TLS, 1000, 2);
}
TEST_IMPL(mqtt_singe_pub_single_single_sub_1000_msgs_qos_2_ws) {
  return mqtt_singe_pub_single_single_sub_many_msgs_impl(TS_PROTO_WS, 1000, 2);
}
TEST_IMPL(mqtt_singe_pub_single_single_sub_1000_msgs_qos_2_wss) {
  return mqtt_singe_pub_single_single_sub_many_msgs_impl(TS_PROTO_WSS, 1000, 2);
}

