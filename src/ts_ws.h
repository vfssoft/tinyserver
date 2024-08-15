#ifndef TINYSERVER_TS_WS_H
#define TINYSERVER_TS_WS_H

#include "ts_internal.h"

typedef struct ts_ws_frame_s ts_ws_frame_t;

// TODO: may not need this struct
struct ts_ws_frame_s {
  BOOL fin;
  int  opcode;
  ts_buf_t* payload_data;
  // no extension is supported for now
};

int ts_ws__init(ts_ws_t* ws, ts_tcp_conn_t* conn);
int ts_ws__destroy(ts_ws_t* ws);
int ts_ws__state(ts_ws_t* ws);
int ts_ws__handshake(ts_ws_t* ws, ts_ro_buf_t* input, ts_buf_t* output);
int ts_ws__unwrap(ts_ws_t* ws, ts_ro_buf_t* input, ts_buf_t* output_app, ts_buf_t* output_sock);
int ts_ws__wrap(ts_ws_t* ws, ts_ro_buf_t* input, ts_buf_t* output);
int ts_ws__disconnect(ts_ws_t* ws, ts_buf_t* output);

#endif //TINYSERVER_TS_WS_H
