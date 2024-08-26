#ifndef TINYSERVER_MQTT_SESSION_H
#define TINYSERVER_MQTT_SESSION_H

#include <internal/ts_error.h>
#include <internal/uthash.h>

#include "mqtt_message.h"

typedef struct tm_mqtt_session_s tm_mqtt_session_t;

struct tm_mqtt_session_s {
    int connected;
    char* client_id;
    int clean_session;

    // TODO: subscriptions
    tm_mqtt_msg_t* in_msgs;
    tm_mqtt_msg_t* out_msgs;
    
    ts_error_t err;
    
    UT_hash_handle hh; // make this struct hashable
};

tm_mqtt_session_t* tm_mqtt_session__create(const char* client_id);
int tm_mqtt_session__destroy(tm_mqtt_session_t* sess);

int tm_mqtt_session__add_in_msg(tm_mqtt_session_t* sess, tm_mqtt_msg_t* msg);
tm_mqtt_msg_t* tm_mqtt_session__find_in_msg(tm_mqtt_session_t* sess, int pkt_id);
int tm_mqtt_session__add_out_msg(tm_mqtt_session_t* sess, tm_mqtt_msg_t* msg);
tm_mqtt_msg_t* tm_mqtt_session__find_out_msg(tm_mqtt_session_t* sess, int pkt_id);

#endif //TINYSERVER_MQTT_SESSION_H
