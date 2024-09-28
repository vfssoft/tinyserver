
#ifndef TINYSERVER_MYMQTT_H
#define TINYSERVER_MYMQTT_H

#include <MQTTClient.h>

typedef struct mymqtt_msg_s mymqtt_msg_t;
typedef struct mymqtt_s mymqtt_t;

struct mymqtt_msg_s {
    char* topic;
    int payload_len;
    char* payload;
    int qos;
    int retained;
    int dup;
};

struct mymqtt_s {
  MQTTClient client;
  MQTTClient_connectOptions options;
  
  char* conn_lost_reason;
  mymqtt_msg_t msgs[32];
  int msgs_count;
};

int mymqtt__init(mymqtt_t* c, int proto, const char* client_id);
void mymqtt__destroy(mymqtt_t* c);

void mymqtt__set_user(mymqtt_t* c, const char* user);
void mymqtt__set_password(mymqtt_t* c, const char* password);
void mymqtt__set_keep_alive(mymqtt_t* c, int keep_alive);

int mymqtt__sp(mymqtt_t* c);
int mymqtt__recv_msg_count(mymqtt_t* c);
int mymqtt__recv_msgs(mymqtt_t* c, mymqtt_msg_t* msgs);

int mymqtt__connect(mymqtt_t* c);
int mymqtt__disconnect(mymqtt_t* c);

int mymqtt__subscribe(mymqtt_t* c, const char* topic, int qos);
int mymqtt__unsubscribe(mymqtt_t* c, const char* topic);

int mymqtt__subscribe_many(mymqtt_t* c, const char** topics, int* qoss, int count);
int mymqtt__unsubscribe_many(mymqtt_t* c, const char** topics, int count);

int mymqtt__publish(mymqtt_t* c, const char* topic, const char* payload, int payload_len, int qos, int retained);


#endif //TINYSERVER_MYMQTT_H
