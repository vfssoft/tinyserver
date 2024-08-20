
#ifndef TINYSERVER_MQTT_PACKETS_H
#define TINYSERVER_MQTT_PACKETS_H

#include "mqtt_conn.h"

#include <internal/ts_miscellany.h>

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
    const char* data,
    int data_len,
    int* pkt_bytes_cnt,
    unsigned int* remaining_length,
    ts_error_t* err
);

typedef struct tm_packet_decoder_s tm_packet_decoder_t;

struct tm_packet_decoder_s {
    const char* buf;
    int len;

    int offset;
};

int tm_packet_decoder__set(tm_packet_decoder_t* decoder, const char* buf, int len);
int tm_packet_decoder__available(tm_packet_decoder_t* decoder);
const char* tm_packet_decoder__ptr(tm_packet_decoder_t* decoder);
int tm_packet_decoder__read_byte(tm_packet_decoder_t* decoder, int* ret);
int tm_packet_decoder__read_int16(tm_packet_decoder_t* decoder, int* ret);
int tm_packet_decoder__read_int16_string(tm_packet_decoder_t* decoder, int* retlen, const char** retstr);







#endif //TINYSERVER_MQTT_PACKETS_H
