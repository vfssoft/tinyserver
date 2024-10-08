
#ifndef TINYSERVER_TS_TCP_CONN_H
#define TINYSERVER_TS_TCP_CONN_H

#include "ts_internal.h"


struct ts_tcp_conn_s {
    uv_tcp_t uvtcp;
    ts_server_listener_t* listener;
    
    ts_conn_write_req_t* write_reqs;
    ts_tls_t* tls;
    ts_ws_t* ws;
    ts_error_t err;
    
    ts_buf_t* tls_buf;
    ts_buf_t* ws_buf;
    
    char local_addr[64]; // Maybe a little small, but let's see
    char remote_addr[64];

    void* user_data;
    uv_timer_t* timer;
    
    ts_tcp_conn_t* prev;
    ts_tcp_conn_t* next;
};

int ts_conn__init(ts_server_listener_t* listener, ts_tcp_conn_t* conn);
int ts_conn__destroy(ts_server_listener_t* listener, ts_tcp_conn_t* conn);
int ts_conn__tcp_connected(ts_tcp_conn_t* conn);
int ts_conn__send_data(ts_tcp_conn_t* conn, const char* data, int data_len);
int ts_conn__close(ts_tcp_conn_t* conn, uv_close_cb cb);

int ts_conn__has_pending_write_reqs(ts_tcp_conn_t* conn);

// timer
int ts_conn__start_timer(ts_tcp_conn_t* conn, int timeoutMS, int repeatMS);
int ts_conn__stop_timer(ts_tcp_conn_t* conn);

#endif //TINYSERVER_TS_TCP_CONN_H
