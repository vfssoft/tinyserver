#ifndef TINYSERVER_MQTT_SESSION_H
#define TINYSERVER_MQTT_SESSION_H

#include <internal/ts_error.h>

typedef struct tm_mqtt_session_s tm_mqtt_session_t;

struct tm_mqtt_session_s {
    int connected;
    char* client_id;
    int clean_session;
    
    ts_error_t err;
};

tm_mqtt_session_t* tm_mqtt_session__create();
int tm_mqtt_session__destroy(tm_mqtt_session_t* sess);

#endif //TINYSERVER_MQTT_SESSION_H
