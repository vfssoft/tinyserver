
#ifndef TINYSERVER_MYMQTT_H
#define TINYSERVER_MYMQTT_H

#include <MQTTClient.h>

typedef struct mymqtt_s mymqtt_t;

struct mymqtt_s {
  MQTTClient client;
  MQTTClient_connectOptions options;
};

int mymqtt__init(mymqtt_t* c, int proto, const char* client_id);
void mymqtt__destroy(mymqtt_t* c);

void mymqtt__set_user(mymqtt_t* c, const char* user);
void mymqtt__set_password(mymqtt_t* c, const char* password);

int mymqtt__sp(mymqtt_t* c);

int mymqtt__connect(mymqtt_t* c);
int mymqtt__disconnect(mymqtt_t* c);

int mymqtt__subscribe(mymqtt_t* c, const char* topic, int qos);
int mymqtt__unsubscribe(mymqtt_t* c, const char* topic);

int mymqtt__publish(mymqtt_t* c, const char* topic, const char* payload, int payload_len, int qos, int retained);


#endif //TINYSERVER_MYMQTT_H
