
#ifndef TINYSERVER_MYMQTT_H
#define TINYSERVER_MYMQTT_H

#include <MQTTClient.h>
#include "test_mqtt_msgs.h"

typedef struct mymqtt_s mymqtt_t;

struct mymqtt_s {
  MQTTClient client;
  MQTTClient_connectOptions options;

  int  is_conn_lost;
  char* conn_lost_reason;
  
  msgs_t* msgs;
};

int mymqtt__init(mymqtt_t* c, int proto, const char* client_id);
void mymqtt__destroy(mymqtt_t* c);

void mymqtt__set_user(mymqtt_t* c, const char* user);
void mymqtt__set_password(mymqtt_t* c, const char* password);
void mymqtt__set_keep_alive(mymqtt_t* c, int keep_alive);
void mymqtt__set_will(mymqtt_t* c, const char* topic, int qos, const char* payload, int payload_len, int retain);

int mymqtt__sp(mymqtt_t* c);
int mymqtt__is_conn_lost(mymqtt_t* c);

int mymqtt__connect(mymqtt_t* c);
int mymqtt__disconnect(mymqtt_t* c);

int mymqtt__subscribe(mymqtt_t* c, const char* topic, int qos);
int mymqtt__unsubscribe(mymqtt_t* c, const char* topic);

int mymqtt__subscribe_many(mymqtt_t* c, const char** topics, int* qoss, int count);
int mymqtt__unsubscribe_many(mymqtt_t* c, const char** topics, int count);

int mymqtt__publish(mymqtt_t* c, const char* topic, const char* payload, int payload_len, int qos, int retained);


#endif //TINYSERVER_MYMQTT_H
