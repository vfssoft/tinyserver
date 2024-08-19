
#ifndef TINYSERVER_MQTT_H
#define TINYSERVER_MQTT_H

#include <ts.h>
#include <internal/ts_error.h>
#include <tm.h>

#include <string.h>

typedef struct tm_server_s tm_server_t;

struct tm_server_s {
    ts_t* server;
    tm_callbacks_t callbacks;
    ts_error_t err;
};

#endif //TINYSERVER_MQTT_H
