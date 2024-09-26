
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
  unsigned long long next_recv_time; // use 'next' on purpose, milliseconds
  
  unsigned long long last_active_time;
  tm_mqtt_msg_t* will;
  tm_mqtt_session_t* session;
    
  tm_server_t* server;
  
  ts_buf_t* in_buf;
  tm_packet_decoder_t decoder;
};

tm_mqtt_conn_t* tm_mqtt_conn__create(tm_server_t* s, ts_conn_t* conn);
int tm_mqtt_conn__destroy(ts_t* server, ts_conn_t* conn);

void tm_mqtt_conn__abort(ts_t* server, ts_conn_t* c);
int tm_mqtt_conn__send_packet(ts_t* server, ts_conn_t* c, const char* data, int len, int pkt_id, tm_mqtt_msg_t* msg);

void tm_mqtt_conn__data_in(ts_t* server, ts_conn_t* c, const char* data, int len);

int tm_mqtt_conn__process_connect(ts_t* server, ts_conn_t* c, const char* pkt_bytes, int pkt_bytes_len, int variable_header_off);
int tm_mqtt_conn__process_publish(ts_t* server, ts_conn_t* c, const char* pkt_bytes, int pkt_bytes_len, int variable_header_off);
int tm_mqtt_conn__process_puback(ts_t* server, ts_conn_t* c, const char* pkt_bytes, int pkt_bytes_len, int variable_header_off);
int tm_mqtt_conn__process_pubrec(ts_t* server, ts_conn_t* c, const char* pkt_bytes, int pkt_bytes_len, int variable_header_off);
int tm_mqtt_conn__process_pubrel(ts_t* server, ts_conn_t* c, const char* pkt_bytes, int pkt_bytes_len, int variable_header_off);
int tm_mqtt_conn__process_pubcomp(ts_t* server, ts_conn_t* c, const char* pkt_bytes, int pkt_bytes_len, int variable_header_off);
int tm_mqtt_conn__process_subscribe(ts_t* server, ts_conn_t* c, const char* pkt_bytes, int pkt_bytes_len, int variable_header_off);
int tm_mqtt_conn__process_unsubscribe(ts_t* server, ts_conn_t* c, const char* pkt_bytes, int pkt_bytes_len, int variable_header_off);
int tm_mqtt_conn__process_pingreq(ts_t* server, ts_conn_t* c);
int tm_mqtt_conn__process_disconnect(ts_t* server, ts_conn_t* c);
int tm_mqtt_conn__process_tcp_disconnect(ts_t* server, ts_conn_t* c);

void tm_mqtt_conn__write_cb(ts_t* server, ts_conn_t* c, int status, int can_write_more);

void tm_mqtt_conn__timer_cb(ts_t* server, ts_conn_t* c);

int tm_mqtt_conn__update_msg_state(ts_t* server, ts_conn_t* c, tm_mqtt_msg_t* msg);

#endif //TINYSERVER_MQTT_CONN_H
