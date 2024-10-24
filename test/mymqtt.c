#include "mymqtt.h"
#include "testutil.h"

#include <stdio.h>
#include <string.h>

void conn_lost_cb(void *context, char *cause)
{
  mymqtt_t* c = (mymqtt_t*)context;
  c->is_conn_lost = 1;
  c->conn_lost_reason = strdup(cause);
}

int msg_arrived_cb(void *context, char *topicName, int topicLen, MQTTClient_message *message) {
  mymqtt_t* c = (mymqtt_t*)context;
  mymqtt_msg_t* msg = (mymqtt_msg_t*) malloc(sizeof(mymqtt_msg_t));
  
  topicLen = strlen(topicName);
  msg->topic = (char*) malloc(topicLen + 1);
  strcpy(msg->topic, topicName);
  msg->topic[topicLen] = 0;
  
  msg->payload = (char*) malloc(message->payloadlen);
  memcpy(msg->payload, message->payload, message->payloadlen);
  msg->payload_len = message->payloadlen;
  
  msg->qos = message->qos;
  msg->dup = message->dup;
  msg->retained = message->retained;
  
  memcpy(&(c->msgs[c->msgs_count]), msg, sizeof(mymqtt_msg_t));
  c->msgs_count++;
  
  return 1;
}

void delivered_cb(void *context, MQTTClient_deliveryToken dt) {
  //printf("Message with token value %d delivery confirmed\n", dt);
  //deliveredtoken = dt;
}

int mymqtt__init(mymqtt_t* c, int proto, const char* client_id) {
  int err;
  const char* server;
  MQTTClient_connectOptions tcp_opts = MQTTClient_connectOptions_initializer;
  MQTTClient_SSLOptions ssl_opts = MQTTClient_SSLOptions_initializer;
  MQTTClient_connectOptions ws_opts = MQTTClient_connectOptions_initializer_ws;
  
  // TODO: add a unit tests for protocol fallback
  tcp_opts.MQTTVersion = MQTTVERSION_3_1_1;
  ws_opts.MQTTVersion = MQTTVERSION_3_1_1;
  
  ssl_opts.enableServerCertAuth = 0;
  
  switch (proto) {
    case TS_PROTO_TCP:
      server = "127.0.0.1:11883";
      memcpy(&(c->options), &tcp_opts, sizeof(MQTTClient_connectOptions));
      break;
      
    case TS_PROTO_TLS:
      server = "ssl://127.0.0.1:18883";
      memcpy(&(c->options), &tcp_opts, sizeof(MQTTClient_connectOptions));
      c->options.ssl = (MQTTClient_SSLOptions*) malloc(sizeof(MQTTClient_SSLOptions));
      memcpy(c->options.ssl, &ssl_opts, sizeof(MQTTClient_SSLOptions));
      break;
      
    case TS_PROTO_WS:
      server = "ws://127.0.0.1:18080";
      memcpy(&(c->options), &ws_opts, sizeof(MQTTClient_connectOptions));
      break;
      
    case TS_PROTO_WSS:
      server = "wss://127.0.0.1:18083";
      memcpy(&(c->options), &ws_opts, sizeof(MQTTClient_connectOptions));
      c->options.ssl = (MQTTClient_SSLOptions*) malloc(sizeof(MQTTClient_SSLOptions));
      memcpy(c->options.ssl, &ssl_opts, sizeof(MQTTClient_SSLOptions));
      break;
  }
  
  err = MQTTClient_create(
      &(c->client),
      server,
      client_id,
      strlen(client_id) == 0 ? MQTTCLIENT_PERSISTENCE_NONE : MQTTCLIENT_PERSISTENCE_DEFAULT,
      NULL
  );
  if (err != MQTTCLIENT_SUCCESS) {
    return err;
  }
  
  err = MQTTClient_setCallbacks(c->client, c, conn_lost_cb, msg_arrived_cb, delivered_cb);
  if (err != MQTTCLIENT_SUCCESS) {
    return err;
  }
  
  c->options.keepAliveInterval = 10;
  c->options.cleansession = 1;
  c->options.connectTimeout = 3;
  
  memset(c->msgs, 0, sizeof(mymqtt_msg_t) * 32);
  c->msgs_count = 0;

  c->is_conn_lost = 0;
  c->conn_lost_reason = NULL;
  
  return 0;
}
void mymqtt__destroy(mymqtt_t* c) {
  MQTTClient_destroy(&c->client);

  if (c->conn_lost_reason) {
    free(c->conn_lost_reason);
    c->conn_lost_reason = NULL;
  }
}

void mymqtt__set_user(mymqtt_t* c, const char* user) {
  c->options.username = strdup(user);
}
void mymqtt__set_password(mymqtt_t* c, const char* password) {
  c->options.password = strdup(password);
}
void mymqtt__set_keep_alive(mymqtt_t* c, int keep_alive) {
  c->options.keepAliveInterval = keep_alive;
}
void mymqtt__set_will(mymqtt_t* c, const char* topic, int qos, const char* payload, int payload_len, int retain) {
  MQTTClient_willOptions willOptions = MQTTClient_willOptions_initializer;
  willOptions.topicName = strdup(topic);
  willOptions.message = NULL;
  willOptions.qos = qos;
  willOptions.retained = retain;
  willOptions.payload.data = malloc(payload_len);
  memcpy(willOptions.payload.data, payload, payload_len);
  willOptions.payload.len = payload_len;
  
  c->options.will = malloc(sizeof(MQTTClient_willOptions));
  memcpy(c->options.will, &willOptions, sizeof(MQTTClient_willOptions));
}

int mymqtt__sp(mymqtt_t* c) {
  return c->options.returned.sessionPresent;
}
int mymqtt__recv_msg_count(mymqtt_t* c) {
  return c->msgs_count;
}
int mymqtt__recv_msgs(mymqtt_t* c, mymqtt_msg_t* msgs) {
  memcpy(msgs, c->msgs, sizeof(mymqtt_msg_t) * c->msgs_count);
  return c->msgs_count;
}
int mymqtt__is_conn_lost(mymqtt_t* c) {
  return c->is_conn_lost;
}

int mymqtt__connect(mymqtt_t* c) {
  int err;
  
  err = MQTTClient_connect(c->client, &(c->options));
  if (err != MQTTCLIENT_SUCCESS) {
    return err;
  }
  
  return 0;
}
int mymqtt__disconnect(mymqtt_t* c) {
  return MQTTClient_disconnect(c->client, 1000);
}

int mymqtt__subscribe(mymqtt_t* c, const char* topic, int qos) {
  int err;
  
  err = MQTTClient_subscribe(c->client, topic, qos);
  if (err != MQTTCLIENT_SUCCESS) {
    return err;
  }
  
  return 0;
}
int mymqtt__unsubscribe(mymqtt_t* c, const char* topic) {
  int err;
  
  err = MQTTClient_unsubscribe(c->client, topic);
  if (err != MQTTCLIENT_SUCCESS) {
    return err;
  }
  
  return 0;
}

int mymqtt__subscribe_many(mymqtt_t* c, const char** topics, int* qoss, int count) {
  int err;
  
  err = MQTTClient_subscribeMany(c->client, count, (char*const*)topics, qoss);
  if (err != MQTTCLIENT_SUCCESS) {
    return err;
  }
  
  return 0;
}
int mymqtt__unsubscribe_many(mymqtt_t* c, const char** topics, int count) {
  int err;
  
  err = MQTTClient_unsubscribeMany(c->client, count, (char*const*)topics);
  if (err != MQTTCLIENT_SUCCESS) {
    return err;
  }
  
  return 0;
}

int mymqtt__publish(mymqtt_t* c, const char* topic, const char* payload, int payload_len, int qos, int retained) {
  int err;
  MQTTClient_deliveryToken token;
  
  err = MQTTClient_publish(
      c->client,
      topic,
      payload_len,
      payload,
      qos,
      retained,
      &token
  );
  if (err != MQTTCLIENT_SUCCESS) {
    return err;
  }
  
  err = MQTTClient_waitForCompletion(c->client, token, 1000);
  if (err != MQTTCLIENT_SUCCESS) {
    return err;
  }
  
  return err;
}