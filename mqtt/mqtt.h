
#ifndef TINYSERVER_MQTT_H
#define TINYSERVER_MQTT_H

#include <ts.h>
#include <tm.h>
#include <internal/ts_error.h>
#include <internal/ts_mutex.h>

#include <string.h>

#include "mqtt_session.h"

typedef struct tm_server_s tm_server_t;

struct tm_server_s {
    ts_t* server;
    tm_callbacks_t callbacks;
    ts_error_t err;

    ts_mutex_t sessions_mu;
    tm_mqtt_session_t* sessions;
};

// session methods
tm_mqtt_session_t* tm__find_session(tm_server_t* s, const char* client_id);
tm_mqtt_session_t* tm__create_session(tm_server_t* s, const char* client_id);
int tm__remove_session(tm_server_t* s, tm_mqtt_session_t* sess);

#endif //TINYSERVER_MQTT_H
