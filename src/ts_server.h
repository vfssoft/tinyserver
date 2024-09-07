
#ifndef TINYSERVER_TS_SERVER_H
#define TINYSERVER_TS_SERVER_H

#include <ts.h>
#include "internal/ts_data_buf.h"
#include "internal/ts_log.h"
#include "internal/ts_error.h"

typedef struct ts_server_s ts_server_t;
typedef struct ts_server_listener_s ts_server_listener_t;
typedef struct ts_conn_write_req_s ts_conn_write_req_t;
typedef struct ts_tcp_conn_s ts_tcp_conn_t;
typedef struct ts_tls_s ts_tls_t;
typedef struct ts_ws_s ts_ws_t;



struct ts_server_listener_s {
    uv_tcp_t uvtcp;
    uv_loop_t *uvloop;
    ts_server_t* server;
    SSL_CTX* ssl_ctx;
    
    const char* host;
    int port;
    int use_ipv6;
    int backlog;
    int protocol;
    
    char* cert;
    char* key;
    int tls_verify_mode;
    
    ts_error_t err;
};
struct ts_server_s {
    ts_server_listener_t* listeners;
    int listener_count;
    ts_callbacks_t callbacks;

    uv_idle_t uvidle;
    uv_loop_t *uvloop;
    
    ts_tcp_conn_t* conns;
    ts_log_t log;
    ts_error_t err;
};

// internal callbacks
void ts_server__internal_connected_cb(ts_server_t* server, ts_conn_t* conn, int status);
void ts_server__internal_disconnected_cb(ts_server_t* server, ts_conn_t* conn, int status);
void ts_server__internal_read_cb(ts_server_t* server, ts_conn_t* conn, const char* data, int len);
void ts_server__internal_write_cb(ts_server_t* server, ts_conn_t* conn, int status, int can_write_more);
void ts_server__internal_idle_cb(ts_server_t* server);
void ts_server__internal_timer_cb(ts_server_t* server, ts_conn_t* conn);
void ts_server__internal_log_cb(ts_server_t* server, const char* msg);

int ts_server_listener__init_default(ts_server_listener_t* listener);
int ts_server_listener__start(ts_server_listener_t* listener, ts_server_t* server, uv_connection_cb cb);
int ts_server_listener__stop(ts_server_listener_t* listener, uv_close_cb cb);

int ts_server_idle__init(ts_server_t* server);
int ts_server_idle__start(ts_server_t* server);
int ts_server_idle__stop(ts_server_t* server);

#endif //TINYSERVER_TS_SERVER_H
