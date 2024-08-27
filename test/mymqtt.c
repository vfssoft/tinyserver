#include "mymqtt.h"

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

int mymqtt__init(mymqtt_t* c, const char* server, const char* client_id) {
  int err;
  MQTTClient_connectOptions default_opts = MQTTClient_connectOptions_initializer;
  
  err = MQTTClient_create(
      c->client,
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
  
  memcpy(&(c->options), &default_opts, sizeof(MQTTClient_connectOptions));
  c->options.keepAliveInterval = 10;
  c->options.cleansession = 1;
  
  return 0;
}
void mymqtt__destroy(mymqtt_t* c) {
  return MQTTClient_destroy(c->client);
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