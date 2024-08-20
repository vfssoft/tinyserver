
#ifndef TINYSERVER_MQTT_CONN_H
#define TINYSERVER_MQTT_CONN_H

#include "mqtt.h"
#include "mqtt_packets.h"
#include "mqtt_message.h"
#include "mqtt_session.h"

#include <internal/ts_data_buf.h>

typedef struct tm_mqtt_conn_s tm_mqtt_conn_t;

struct tm_mqtt_conn_s {
  int keep_alive;
  
  tm_mqtt_msg_t* will;
  tm_mqtt_session_t* session;
    
  tm_server_t* server;
  
  ts_buf_t* in_buf;
  tm_packet_decoder_t decoder;
  ts_error_t err;
};

tm_mqtt_conn_t* tm_mqtt_conn__create(tm_server_t* s);
int tm_mqtt_conn__destroy(tm_mqtt_conn_t* conn);

int tm_mqtt_conn__data_in(tm_mqtt_conn_t* conn, const char* data, int len);

#endif //TINYSERVER_MQTT_CONN_H
