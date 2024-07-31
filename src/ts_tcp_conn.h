
#ifndef TINYSERVER_TS_TCP_CONN_H
#define TINYSERVER_TS_TCP_CONN_H

#include "ts_internal.h"

int ts_conn__init(ts_server_listener_t* listener, ts_conn_t* conn);
int ts_conn__destroy(ts_server_listener_t* listener, ts_conn_t* conn);
int ts_conn__tcp_connected(ts_conn_t* conn);
int ts_conn__send_data(ts_conn_t* conn, ts_buf_t* input);
int ts_conn__close(ts_conn_t* conn, uv_close_cb cb);

#endif //TINYSERVER_TS_TCP_CONN_H
