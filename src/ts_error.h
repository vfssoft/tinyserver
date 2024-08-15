#ifndef TINYSERVER_TS_ERROR_H
#define TINYSERVER_TS_ERROR_H

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
