
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
  
  unsigned long long last_active_time;
  tm_mqtt_msg_t* will;
  tm_mqtt_session_t* session;
    
  tm_server_t* server;
  
  ts_buf_t* in_buf;
  tm_packet_decoder_t decoder;
};

tm_mqtt_conn_t* tm_mqtt_conn__create(tm_server_t* s);
int tm_mqtt_conn__destroy(tm_mqtt_conn_t* conn);

void tm_mqtt_conn__abort(ts_t* server, ts_conn_t* c);

int tm_mqtt_conn__data_in(ts_t* server, ts_conn_t* c, const char* data, int len);

int tm_mqtt_conn__process_connect(ts_t* server, ts_conn_t* c, const char* pkt_bytes, int pkt_bytes_len, int variable_header_off);
int tm_mqtt_conn__process_publish(ts_t* server, ts_conn_t* c, const char* pkt_bytes, int pkt_bytes_len, int variable_header_off);
int tm_mqtt_conn__process_subscribe(ts_t* server, ts_conn_t* c, const char* pkt_bytes, int pkt_bytes_len, int variable_header_off);
int tm_mqtt_conn__process_unsubscribe(ts_t* server, ts_conn_t* c, const char* pkt_bytes, int pkt_bytes_len, int variable_header_off);
int tm_mqtt_conn__process_pingreq(ts_t* server, ts_conn_t* c);
int tm_mqtt_conn__process_disconnect(ts_t* server, ts_conn_t* c);
int tm_mqtt_conn__process_tcp_disconnect(ts_t* server, ts_conn_t* c);

#endif //TINYSERVER_MQTT_CONN_H
