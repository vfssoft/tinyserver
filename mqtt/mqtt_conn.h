
#ifndef TINYSERVER_MQTT_CONN_H
#define TINYSERVER_MQTT_CONN_H

typedef struct tm_mqtt_conn_s tm_mqtt_conn_t;

struct tm_mqtt_conn_s {

};

tm_mqtt_conn_t* tm_mqtt_conn__create();
int tm_mqtt_conn__destroy(tm_mqtt_conn_t* conn);

#endif //TINYSERVER_MQTT_CONN_H
