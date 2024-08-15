
#ifndef TINYSERVER_TS_SERVER_H
#define TINYSERVER_TS_SERVER_H


#include "ts_data_buf.h"
#include "ts_log.h"

typedef struct ts_server_s ts_server_t;
typedef struct ts_server_listener_s ts_server_listener_t;
typedef struct ts_conn_write_req_s ts_conn_write_req_t;
typedef struct ts_tcp_conn_s ts_tcp_conn_t;
typedef struct ts_tls_s ts_tls_t;
typedef struct ts_ws_s ts_ws_t;
typedef struct ts_error_s ts_error_t;

struct ts_error_s {
    int err;
    char* msg;
};

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
    
    ts_server_connected_cb connected_cb;
    ts_server_disconnected_cb disconnected_cb;
    ts_server_read_cb read_cb;
    ts_server_write_cb write_cb;
    ts_server_idle_cb idle_cb;
    void* cb_ctx;
    
    uv_idle_t uvidle;
    uv_loop_t *uvloop;
    
    ts_tcp_conn_t* conns;
    ts_log_t log;
    ts_error_t err;
};


#endif //TINYSERVER_TS_SERVER_H
