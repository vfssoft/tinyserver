#ifndef TINYSERVER_MQTT_MESSAGE_H
#define TINYSERVER_MQTT_MESSAGE_H


#include <internal/ts_mutex.h>
#include <internal/ts_data_buf.h>
#include <internal/utlist.h>

#define MSG_STATE_INIT         0
// Outgoing
#define MSG_STATE_TO_PUBLISH   1
#define MSG_STATE_WAIT_PUBACK  2
#define MSG_STATE_WAIT_PUBREC  3
#define MSG_STATE_SEND_PUBREL  4
#define MSG_STATE_WAIT_PUBCOMP 5
// Incoming
#define MSG_STATE_RECEIVE_PUB  6
#define MSG_STATE_SEND_PUBACK  7
#define MSG_STATE_SEND_PUBREC  8
#define MSG_STATE_WAIT_PUBREL  9
#define MSG_STATE_SEND_PUBCOMP 10

#define MSG_STATE_DONE         11

typedef struct tm_mqtt_msg_core_s tm_mqtt_msg_core_t;
typedef struct tm_mqtt_msg_s tm_mqtt_msg_t;
typedef struct tm_msg_mgr_s tm_msg_mgr_t;


struct tm_mqtt_msg_core_s {
  ts_buf_t* topic;
  ts_buf_t* payload;
  int ref_count;

  tm_mqtt_msg_core_t* prev;
  tm_mqtt_msg_core_t* next;
};

struct tm_mqtt_msg_s {
  tm_mqtt_msg_core_t* msg_core;
  int flags; // DUP, QoS, RETAIN

  unsigned long long id;
  int state;
  int pkt_id;

  tm_mqtt_msg_t* prev;
  tm_mqtt_msg_t* next;
};

struct tm_msg_mgr_s {
    ts_mutex_t mu;
    tm_mqtt_msg_core_t* message_cores;
    tm_mqtt_msg_t* messages;
    unsigned long long next_msg_id;
};

int tm_mqtt_msg__retain(tm_mqtt_msg_t* msg);
void tm_mqtt_msg__set_retain(tm_mqtt_msg_t* msg, int retain);
int tm_mqtt_msg__qos(tm_mqtt_msg_t* msg);
void tm_mqtt_msg__set_qos(tm_mqtt_msg_t* msg, int qos);
int tm_mqtt_msg__dup(tm_mqtt_msg_t* msg);
void tm_mqtt_msg__set_dup(tm_mqtt_msg_t* msg, int dup);
const char* tm_mqtt_msg__topic(tm_mqtt_msg_t* msg);
int tm_mqtt_msg__payload_len(tm_mqtt_msg_t* msg);

unsigned long long tm_mqtt_msg__id(tm_mqtt_msg_t* msg);
int tm_mqtt_msg__get_state(tm_mqtt_msg_t* msg);
int tm_mqtt_msg__set_state(tm_mqtt_msg_t* msg, int state);
int tm_mqtt_msg__update_state(tm_mqtt_msg_t* msg);


tm_msg_mgr_t* tm_msg_mgr__create();
int tm_msg_mgr__destroy(tm_msg_mgr_t* mgr);
tm_mqtt_msg_t* tm_msg_mgr__add(tm_msg_mgr_t* mgr, const char* topic, const char* payload, int payload_len, int dup, int qos, int retain);
tm_mqtt_msg_t* tm_msg_mgr__dup(tm_msg_mgr_t* mgr, tm_mqtt_msg_t* src_msg, int dup, int qos, int retain);
int tm_msg_mgr__unuse(tm_msg_mgr_t* mgr, tm_mqtt_msg_t* msg);

#endif //TINYSERVER_MQTT_MESSAGE_H
