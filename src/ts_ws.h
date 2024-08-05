#ifndef TINYSERVER_TS_WS_H
#define TINYSERVER_TS_WS_H

#include "ts_internal.h"

typedef struct ts_ws_s ts_ws_t;

struct ts_ws_s {
  ts_conn_t* conn;
  int state;
  
  ts_error_t err;
  ts_buf_t* out_buf; // used internal
  ts_buf_t* in_buf;
};

int ts_ws__init(ts_ws_t* ws, ts_conn_t* conn);
int ts_ws__destroy(ts_ws_t* ws);

int ts_ws__handshake(ts_ws_t* ws, ts_ro_buf_t* input, ts_buf_t* output);
int ts_ws__unwrap(ts_ws_t* ws, ts_ro_buf_t* input, ts_buf_t* output);
int ts_ws__wrap(ts_ws_t* ws, ts_ro_buf_t* input, ts_buf_t* output);
int ts_ws__disconnect(ts_ws_t* ws, ts_buf_t* output);

#endif //TINYSERVER_TS_WS_H
