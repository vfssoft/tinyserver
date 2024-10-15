#ifndef TINYSERVER_TESTUTIL_H
#define TINYSERVER_TESTUTIL_H

#include <ts.h>
#include <ts_internal.h>
#include <tm.h>

#define MQTT_PLAIN_PORT 11883
#define MQTT_TLS_PORT   18883
#define MQTT_WS_PORT    18080
#define MQTT_WSS_PORT   18083

#define RESET_STRUCT(s) memset(&s, 0, sizeof(s))

const char* cur_dir();

ts_t* start_server(int proto);

tm_t* start_mqtt_server(int proto, tm_callbacks_t* cbs);
tm_t* start_mqtt_server_custom_port(int proto, int listen_port, tm_callbacks_t* cbs);

void assert_bytes_equals(const char* d1, int d1len, const char* d2, int d2len);

void decode_hex(const char* hex, unsigned char* bytes);

long long get_current_time_millis();
long get_current_process_memory_usage();

void wait(int milliseconds);

int build_connect_pkt(
    char* buf,
    const char* client_id,
    int clean_session,
    const char* username, const char* password,
    const char* will_msg, int will_msg_len, const char* will_topic, int will_qos, int will_retain,
    int keep_alive
);

int build_subscribe_pkt(char* buf, int pkt_id, const char* topic, int qos);

#endif //TINYSERVER_TESTUTIL_H
