#ifndef TINYSERVER_MQTT_SESSION_H
#define TINYSERVER_MQTT_SESSION_H

#include <internal/ts_mutex.h>
#include <internal/ts_error.h>
#include <internal/uthash.h>

#include "mqtt_message.h"

typedef struct tm_mqtt_session_s tm_mqtt_session_t;
typedef struct tm_session_mgr_s tm_session_mgr_t;

struct tm_mqtt_session_s {
    void* conn; // ts_conn_t;
    char* client_id;
    int clean_session;

    // TODO: subscriptions
    tm_mqtt_msg_t* in_msgs;
    tm_mqtt_msg_t* out_msgs;
    
    ts_error_t err;
    
    UT_hash_handle hh; // make this struct hashable
};

struct tm_session_mgr_s {
    ts_mutex_t mu;
    tm_mqtt_session_t* sessions;
};

tm_session_mgr_t* tm_session_mgr__create();
void tm_session_mgr__destroy(tm_session_mgr_t* mgr);
tm_mqtt_session_t* tm_session_mgr__find(tm_session_mgr_t* mgr, const char* client_id);
tm_mqtt_session_t* tm_session_mgr__add(tm_session_mgr_t* mgr, const char* client_id);
int tm_session_mgr__delete(tm_session_mgr_t* mgr, tm_mqtt_session_t* sess);

//tm_mqtt_session_t* tm_mqtt_session__create(const char* client_id);
//int tm_mqtt_session__destroy(tm_mqtt_session_t* sess);

void* tm_mqtt_session__conn(tm_mqtt_session_t* sess);
void tm_mqtt_session__attach(tm_mqtt_session_t* sess, void* conn);
void* tm_mqtt_session__detach(tm_mqtt_session_t* sess);

int tm_mqtt_session__add_in_msg(tm_mqtt_session_t* sess, tm_mqtt_msg_t* msg);
int tm_mqtt_session__remove_in_msg(tm_mqtt_session_t* sess, tm_mqtt_msg_t* msg);
tm_mqtt_msg_t* tm_mqtt_session__find_in_msg(tm_mqtt_session_t* sess, int pkt_id);
int tm_mqtt_session__add_out_msg(tm_mqtt_session_t* sess, tm_mqtt_msg_t* msg);
tm_mqtt_msg_t* tm_mqtt_session__find_out_msg(tm_mqtt_session_t* sess, int pkt_id);

#endif //TINYSERVER_MQTT_SESSION_H
