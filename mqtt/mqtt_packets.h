
#ifndef TINYSERVER_MQTT_PACKETS_H
#define TINYSERVER_MQTT_PACKETS_H

#include "mqtt_conn.h"

#define PKT_TYPE_CONNECT     1
#define PKT_TYPE_CONNACK     2
#define PKT_TYPE_PUBLISH     3
#define PKT_TYPE_PUBACK      4
#define PKT_TYPE_PUBREC      5
#define PKT_TYPE_PUBREL      6
#define PKT_TYPE_PUBCOMP     7
#define PKT_TYPE_SUBSCRIBE   8
#define PKT_TYPE_SUBACK      9
#define PKT_TYPE_UNSUBSCRIBE 10
#define PKT_TYPE_UNSUBACK    11
#define PKT_TYPE_PINGREQ     12
#define PKT_TYPE_PINGRESP    13
#define PKT_TYPE_DISCONNECT  14

BOOL tm__parse_packet(
    tm_mqtt_conn_t* conn,
    const char* data,
    int data_len,
    int* pkt_bytes_cnt,
    unsigned int* remaining_length,
    ts_error_t* err
);


#endif //TINYSERVER_MQTT_PACKETS_H
