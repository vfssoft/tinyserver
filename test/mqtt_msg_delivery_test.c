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
    
    mymqtt_msg_t msgs[32]; // msg received
    int msgs_count;
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
  
  if (!info->skip_sub) {
    err = mymqtt__unsubscribe(&client, info->topic);
    ASSERT_EQ(err, 0);
  }
  
  err = mymqtt__disconnect(&client);
  ASSERT_EQ(err, 0);
  
  info->done = 1;
}
static test_client_subscriber_info_t* mqtt_subscriber_start_ex(tm_t* server, uv_thread_t* thread, int proto, const char* topic, int qos, int timeoutms, const char* client_id, int clean_session, int skip_sub) {
  test_client_subscriber_info_t* info = (test_client_subscriber_info_t*) malloc(sizeof(test_client_subscriber_info_t));
  memset(info, 0, sizeof(test_client_subscriber_info_t));
  info->proto = proto;
  info->clean_session = clean_session;
  strcpy(info->client_id, client_id);
  strcpy(info->topic, topic);
  info->qos = qos;
  info->timeoutms = timeoutms;
  info->exp_recv_count = 1;
  info->skip_sub = skip_sub;
  
  uv_thread_create(thread, mqtt_client_subscriber_cb, (void*)info);
  while (info->subscribed == 0) { tm__run(server); }
  return info;
}
static test_client_subscriber_info_t* mqtt_subscriber_start(tm_t* server, uv_thread_t* thread, int proto, const char* topic, int qos, int timeoutms) {
  return mqtt_subscriber_start_ex(server, thread, proto, topic, qos, timeoutms, "tet_subscriber_client_id", TRUE, FALSE);
}
static int mqtt_subscriber_stop(tm_t* server, uv_thread_t* thread,  test_client_subscriber_info_t* info) {
  while (info->done == 0) { tm__run(server); }
  uv_thread_join(thread);
  return 0;
}


typedef struct {
  int done;
} client_resend_publish_qos1_info_t;

static void client_server_resend_publish_qos1_cb(void *arg) {
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
TEST_IMPL(mqtt_msg_delivery__server_resend_publish_qos1) {
  client_resend_publish_qos1_info_t info;
  RESET_STRUCT(info);
  
  tm_t* server;
  tm_callbacks_t cbs;
  init_callbacks(&cbs, &info);
  
  server = start_mqtt_server(TS_PROTO_TCP, &cbs);
  int r = tm__start(server);
  ASSERT_EQ(r, 0);
  
  uv_thread_t client_thread;
  uv_thread_create(&client_thread, client_server_resend_publish_qos1_cb, (void*)&info);
  
  mqtt_publish_a_msg(server, TS_PROTO_TCP, "test", 1, "hello", 5, FALSE);
  
  while (info.done == 0) {
    tm__run(server);
  }
  
  tm__stop(server);
  uv_thread_join(&client_thread);
  
  return 0;
}

static void client_client_resend_publish_qos1_cb(void *arg) {
  client_resend_publish_qos1_info_t* info = (client_resend_publish_qos1_info_t*) arg;
  
  char conn_bytes[1024];
  int conn_bytes_len = build_connect_pkt(conn_bytes, "publish", FALSE, NULL, NULL, NULL, 0, NULL, 0, FALSE, 30);
  
  char pub_bytes[128];
  int pub_bytes_len = build_publish_pkt(pub_bytes, "test", 1, 1, FALSE, FALSE, "hello", 5);
  
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
  
  // publish
  err = mytcp__write(&client, pub_bytes, pub_bytes_len);
  ASSERT_EQ(err, pub_bytes_len);
  
  // disconnect immediately
  mytcp__disconnect(&client);
  
  // re-connect
  err = mytcp__connect(&client, "127.0.0.1", MQTT_PLAIN_PORT);
  ASSERT_EQ(err, 0);
  
  // connect
  err = mytcp__write(&client, conn_bytes, conn_bytes_len);
  ASSERT_EQ(err, conn_bytes_len);
  err = mytcp__read(&client, recv_buf, 1024);
  ASSERT_EQ(err, 4);
  
  // resend publish
  pub_bytes_len = build_publish_pkt(pub_bytes, "test", 1, 1, TRUE, FALSE, "hello", 5);
  err = mytcp__write(&client, pub_bytes, pub_bytes_len);
  ASSERT_EQ(err, pub_bytes_len);
  
  err = mytcp__read(&client, recv_buf, 128);
  ASSERT_EQ(err, 4);
  
  info->done = 1;
}
static void mqtt_msg_delivery__client_resend_publish_qos1_msg_cb(void* ctx, tm_t* mqt, ts_conn_t* conn, tm_msg_t* msg, int old_state, int new_state) {
  if (new_state == 7 /*MSG_STATE_SEND_PUBACK*/) {
    Sleep(500);
  }
}
TEST_IMPL(mqtt_msg_delivery__client_resend_publish_qos1) {
  test_client_subscriber_info_t* subscriber_info;
  uv_thread_t subscriber_thread;
  
  client_resend_publish_qos1_info_t info;
  RESET_STRUCT(info);
  
  tm_t* server;
  tm_callbacks_t cbs;
  init_callbacks(&cbs, &info);
  cbs.msg_cb = mqtt_msg_delivery__client_resend_publish_qos1_msg_cb;
  
  server = start_mqtt_server(TS_PROTO_TCP, &cbs);
  int r = tm__start(server);
  ASSERT_EQ(r, 0);
  
  subscriber_info = mqtt_subscriber_start(server, &subscriber_thread, TS_PROTO_TCP, "test", 1, 2000);
  
  uv_thread_t client_thread;
  uv_thread_create(&client_thread, client_client_resend_publish_qos1_cb, (void*)&info);
  
  mqtt_subscriber_stop(server, &subscriber_thread, subscriber_info);
  tm__stop(server);
  
  ASSERT_EQ(subscriber_info->msgs_count, 1);
  mymqtt_msg_t* msg = &(subscriber_info->msgs[0]);
  ASSERT_STR_EQ(msg->topic, "test");
  ASSERT_EQ(msg->qos, 1);
  ASSERT_EQ(msg->payload_len, 5);
  ASSERT_MEM_EQ("hello", (char*)msg->payload, 5);
  
  return 0;
}

static void client_server_resend_publish_qos2_cb(void *arg) {
  client_resend_publish_qos1_info_t* info = (client_resend_publish_qos1_info_t*) arg;
  
  char conn_bytes[1024];
  int conn_bytes_len = build_connect_pkt(conn_bytes, "subscriber", FALSE, NULL, NULL, NULL, 0, NULL, 0, FALSE, 30);
  
  char sub_bytes[128];
  int sub_bytes_len = build_subscribe_pkt(sub_bytes, 1, "test", 2);
  
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
  
  // disconnect without sending pubrec
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
  ASSERT_EQ(recv_buf[0], 0x3c); // DUP, QoS 2, Not retain
  ASSERT_EQ(recv_buf[8], 0x00);
  ASSERT_EQ(recv_buf[9], 0x01); // packet id
  
  info->done = 1;
}
TEST_IMPL(mqtt_msg_delivery__server_resend_publish_qos2) {
  client_resend_publish_qos1_info_t info;
  RESET_STRUCT(info);
  
  tm_t* server;
  tm_callbacks_t cbs;
  init_callbacks(&cbs, &info);
  
  server = start_mqtt_server(TS_PROTO_TCP, &cbs);
  int r = tm__start(server);
  ASSERT_EQ(r, 0);
  
  uv_thread_t client_thread;
  uv_thread_create(&client_thread, client_server_resend_publish_qos2_cb, (void*)&info);
  
  mqtt_publish_a_msg(server, TS_PROTO_TCP, "test", 2, "hello", 5, FALSE);
  
  while (info.done == 0) {
    tm__run(server);
  }
  
  tm__stop(server);
  uv_thread_join(&client_thread);
  
  return 0;
}


static void client_server_resend_pubrel_cb(void *arg) {
  client_resend_publish_qos1_info_t* info = (client_resend_publish_qos1_info_t*) arg;
  
  char conn_bytes[1024];
  int conn_bytes_len = build_connect_pkt(conn_bytes, "subscriber", FALSE, NULL, NULL, NULL, 0, NULL, 0, FALSE, 30);
  
  char sub_bytes[128];
  int sub_bytes_len = build_subscribe_pkt(sub_bytes, 1, "test", 2);
  
  char pubrec_bytes[4] = { 0x50, 0x02, 0x00, 0x01 };
  
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
  
  // wait publish
  err = mytcp__read(&client, recv_buf, 1024);
  ASSERT_EQ(err, 15);
  ASSERT_EQ(recv_buf[0], 0x34); // DUP=0, QoS 2, Not retain
  ASSERT_EQ(recv_buf[8], 0x00);
  ASSERT_EQ(recv_buf[9], 0x01); // packet id
  
  err = mytcp__write(&client, pubrec_bytes, 4);
  ASSERT_EQ(err, 4);
  
  // wait pubrel
  err = mytcp__read(&client, recv_buf, 1024);
  ASSERT_EQ(err, 4);
  ASSERT_EQ(recv_buf[0], 0x62);
  
  // disconnect now
  mytcp__disconnect(&client);
  
  // re-connect
  err = mytcp__connect(&client, "127.0.0.1", MQTT_PLAIN_PORT);
  ASSERT_EQ(err, 0);
  
  // connect
  err = mytcp__write(&client, conn_bytes, conn_bytes_len);
  ASSERT_EQ(err, conn_bytes_len);
  err = mytcp__read(&client, recv_buf, 1024);
  ASSERT_EQ(err, 4);
  
  // server should resend pubrel to us
  err = mytcp__read(&client, recv_buf, 128);
  ASSERT_EQ(err, 4);
  ASSERT_EQ(recv_buf[0], 0x62);
  ASSERT_EQ(recv_buf[2], 0x00);
  ASSERT_EQ(recv_buf[3], 0x01); // packet id
  
  info->done = 1;
}
TEST_IMPL(mqtt_msg_delivery__server_resend_pubrel) {
  client_resend_publish_qos1_info_t info;
  RESET_STRUCT(info);
  
  tm_t* server;
  tm_callbacks_t cbs;
  init_callbacks(&cbs, &info);
  
  server = start_mqtt_server(TS_PROTO_TCP, &cbs);
  int r = tm__start(server);
  ASSERT_EQ(r, 0);
  
  uv_thread_t client_thread;
  uv_thread_create(&client_thread, client_server_resend_pubrel_cb, (void*)&info);
  
  mqtt_publish_a_msg(server, TS_PROTO_TCP, "test", 2, "hello", 5, FALSE);
  
  while (info.done == 0) {
    tm__run(server);
  }
  
  tm__stop(server);
  uv_thread_join(&client_thread);
  
  return 0;
}

static void client_client_resend_pubrel_cb(void *arg) {
  client_resend_publish_qos1_info_t* info = (client_resend_publish_qos1_info_t*) arg;
  
  char conn_bytes[1024];
  int conn_bytes_len = build_connect_pkt(conn_bytes, "publish", FALSE, NULL, NULL, NULL, 0, NULL, 0, FALSE, 30);
  
  char pub_bytes[128];
  int pub_bytes_len = build_publish_pkt(pub_bytes, "test", 1, 2, FALSE, FALSE, "hello", 5);
  
  char pubrel_bytes[] = { 0x62, 0x02, 0x00, 0x01 };
  
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
  
  // publish
  err = mytcp__write(&client, pub_bytes, pub_bytes_len);
  ASSERT_EQ(err, pub_bytes_len);
  
  // recv pubrec
  err = mytcp__read(&client, recv_buf, 1024);
  ASSERT_EQ(err, 4);
  
  // send pubrel
  //err = mytcp__write(&client, pubrel_bytes, 4);
  //ASSERT_EQ(err, 4);
  
  // disconnect immediately
  mytcp__disconnect(&client);
  
  // re-connect
  err = mytcp__connect(&client, "127.0.0.1", MQTT_PLAIN_PORT);
  ASSERT_EQ(err, 0);
  
  // connect
  err = mytcp__write(&client, conn_bytes, conn_bytes_len);
  ASSERT_EQ(err, conn_bytes_len);
  err = mytcp__read(&client, recv_buf, 1024);
  ASSERT_EQ(err, 4);
  
  // resend pubrel
  err = mytcp__write(&client, pubrel_bytes, 4);
  ASSERT_EQ(err, 4);
  err = mytcp__read(&client, recv_buf, 128);
  ASSERT_EQ(err, 4);
  
  info->done = 1;
}
static void mqtt_msg_delivery__client_resend_pubrel_msg_cb(void* ctx, tm_t* mqt, ts_conn_t* conn, tm_msg_t* msg, int old_state, int new_state) {
  if (new_state == 10 /*MSG_STATE_SEND_PUBCOMP*/) {
    Sleep(500);
  }
}
TEST_IMPL(mqtt_msg_delivery__client_resend_pubrel) {
  test_client_subscriber_info_t* subscriber_info;
  uv_thread_t subscriber_thread;
  
  client_resend_publish_qos1_info_t info;
  RESET_STRUCT(info);
  
  tm_t* server;
  tm_callbacks_t cbs;
  init_callbacks(&cbs, &info);
  cbs.msg_cb = mqtt_msg_delivery__client_resend_pubrel_msg_cb;
  
  server = start_mqtt_server(TS_PROTO_TCP, &cbs);
  int r = tm__start(server);
  ASSERT_EQ(r, 0);
  
  subscriber_info = mqtt_subscriber_start(server, &subscriber_thread, TS_PROTO_TCP, "test", 2, 2000);
  
  uv_thread_t client_thread;
  uv_thread_create(&client_thread, client_client_resend_pubrel_cb, (void*)&info);
  
  mqtt_subscriber_stop(server, &subscriber_thread, subscriber_info);
  tm__stop(server);
  
  ASSERT_EQ(subscriber_info->msgs_count, 1);
  mymqtt_msg_t* msg = &(subscriber_info->msgs[0]);
  ASSERT_STR_EQ(msg->topic, "test");
  ASSERT_EQ(msg->qos, 2);
  ASSERT_EQ(msg->payload_len, 5);
  ASSERT_MEM_EQ("hello", (char*)msg->payload, 5);
  
  return 0;
}
