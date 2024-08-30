#include "mymqtt.h"
#include "testutil.h"

#include <stdio.h>
#include <string.h>

void conn_lost_cb(void *context, char *cause)
{
  printf("\nConnection lost\n");
  if (cause)
    printf("     cause: %s\n", cause);
}

int msg_arrived_cb(void *context, char *topicName, int topicLen, MQTTClient_message *message) {
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
      MQTTCLIENT_PERSISTENCE_DEFAULT,
      NULL
  );
  if (err != MQTTCLIENT_SUCCESS) {
    return err;
  }
  
  err = MQTTClient_setCallbacks(c->client, NULL, conn_lost_cb, msg_arrived_cb, delivered_cb);
  if (err != MQTTCLIENT_SUCCESS) {
    return err;
  }
  
  c->options.keepAliveInterval = 10;
  c->options.cleansession = 1;
  
  return 0;
}
void mymqtt__destroy(mymqtt_t* c) {
  MQTTClient_destroy(c->client);
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