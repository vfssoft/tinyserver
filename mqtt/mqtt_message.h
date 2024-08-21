#ifndef TINYSERVER_MQTT_MESSAGE_H
#define TINYSERVER_MQTT_MESSAGE_H


#include <internal/ts_data_buf.h>
#include <internal/utlist.h>

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

  tm_mqtt_msg_t* prev;
  tm_mqtt_msg_t* next;
};

tm_mqtt_msg_core_t* tm_mqtt_msg_core__create(const char* topic, const char* payload, int payload_len);
int tm_mqtt_msg_core__destroy(tm_mqtt_msg_core_t* msg_core);

int tm_mqtt_msg_core__add_ref(tm_mqtt_msg_core_t* msg_core);
int tm_mqtt_msg_core__dec_ref(tm_mqtt_msg_core_t* msg_core);

#endif //TINYSERVER_MQTT_MESSAGE_H
