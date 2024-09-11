
#ifndef TINYSERVER_MQTT_H
#define TINYSERVER_MQTT_H

#include <ts.h>
#include <tm.h>
#include <internal/ts_error.h>
#include <internal/ts_mutex.h>

#include "mqtt_session.h"
#include "mqtt_message.h"
#include "mqtt_topics.h"

typedef struct tm_server_s tm_server_t;

struct tm_server_s {
    ts_t* server;
    tm_callbacks_t callbacks;
    ts_error_t err;

    ts_mutex_t sessions_mu;
    tm_mqtt_session_t* sessions;

    ts_mutex_t messages_mu;
    tm_mqtt_msg_core_t* message_cores;
    
    tm_topics_t* topics;
};

// internal callbacks
void tm__internal_log_cb(tm_server_t* mq, const char* msg);
void tm__internal_auth_user_cb(tm_server_t* mq, const char* username, const char* password, int* ret_auth_ok);
void tm__internal_connected_cb(tm_server_t* mq, ts_conn_t* conn);
void tm__internal_disconnected_cb(tm_server_t* mq, ts_conn_t* conn);
void tm__internal_subscribe_cb(tm_server_t* mqt, ts_conn_t* conn, const char* topic, int requested_qos, int* granted_qos);
void tm__internal_unsubscribe_cb(tm_server_t* mqt, ts_conn_t* conn, const char* topic);

// session methods
tm_mqtt_session_t* tm__find_session(tm_server_t* s, const char* client_id);
tm_mqtt_session_t* tm__create_session(tm_server_t* s, const char* client_id);
int tm__remove_session(tm_server_t* s, tm_mqtt_session_t* sess);

// messages
tm_mqtt_msg_t* tm__create_message(tm_server_t* s, const char* topic, const char* payload, int payload_len, int dup, int qos, int retain);
void tm__remove_message(tm_server_t* s, tm_mqtt_msg_t* msg);

// subscription
int tm__on_subscription(ts_t* server, ts_conn_t* c, const char* topic, int granted_qos);
int tm__on_unsubscription(ts_t* server, ts_conn_t* c, const char* topic);

#endif //TINYSERVER_MQTT_H
