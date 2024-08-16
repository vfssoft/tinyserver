
#ifndef TINYSERVER_TS_MQTT_H
#define TINYSERVER_TS_MQTT_H

#include <ts.h>
#include <tm.h>

typedef struct tm_server_s tm_server_t;

struct tm_server_s {
    ts_t* server;
};

#endif //TINYSERVER_TS_MQTT_H
