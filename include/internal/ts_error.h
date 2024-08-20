#ifndef TINYSERVER_TS_ERROR_H
#define TINYSERVER_TS_ERROR_H

#define TS_ERR_OUT_OF_MEMORY 0x80000001
#define TS_ERR_INVALID_WS_HEADERS 0x80000002
#define TS_ERR_INVALID_WS_FRAME 0x80000003
#define TS_ERR_WS_CLOSED 0x80000004
#define TS_ERR_NOT_FOUND 0x80000005
#define TS_ERR_INVALID_ARGUMENT 0x80000006
#define TS_ERR_INVALID_TOPIC 0x80000007
#define TS_ERR_MALFORMED_MQTT_PACKET 0x80000008
#define TS_ERR_PROTOCOL_ERROR 0x80000009
#define TS_ERR_INVALID_OPERATION 0x8000000A

typedef struct ts_error_s ts_error_t;

struct ts_error_s {
    int err;
    char* msg;
};

void ts_error__init(ts_error_t* errt);
void ts_error__reset(ts_error_t* errt);
void ts_error__set(ts_error_t* errt, int err);
void ts_error__set_msg(ts_error_t* errt, int err, const char* msg);
void ts_error__set_msgf(ts_error_t* errt, int err, const char* format, ...);
void ts_error__copy(ts_error_t* dst, ts_error_t* src);

#endif //TINYSERVER_TS_ERROR_H
