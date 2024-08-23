#ifndef TINYSERVER_MQTT_MESSAGE_H
#define TINYSERVER_MQTT_MESSAGE_H


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
#define MSG_STATE_SEND_PUBACK  6
#define MSG_STATE_SEND_PUBREC  7
#define MSG_STATE_WAIT_PUBREL  8
#define MSG_STATE_SEND_PUBCOMP 9

#define MSG_STATE_DONE         10


typedef struct tm_mqtt_msg_core_s tm_mqtt_msg_core_t;
typedef struct tm_mqtt_msg_s tm_mqtt_msg_t;


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

  int state;

  tm_mqtt_msg_t* prev;
  tm_mqtt_msg_t* next;
};

tm_mqtt_msg_core_t* tm_mqtt_msg_core__create(const char* topic, const char* payload, int payload_len);
int tm_mqtt_msg_core__destroy(tm_mqtt_msg_core_t* msg_core);

int tm_mqtt_msg_core__add_ref(tm_mqtt_msg_core_t* msg_core);
int tm_mqtt_msg_core__dec_ref(tm_mqtt_msg_core_t* msg_core);

int tm_mqtt_msg__get_state(tm_mqtt_msg_t* msg);
int tm_mqtt_msg__change_state(tm_mqtt_msg_t* msg, int new_state);

#endif //TINYSERVER_MQTT_MESSAGE_H
