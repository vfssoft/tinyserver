
#ifndef TINYSERVER_TS_SERVER_H
#define TINYSERVER_TS_SERVER_H

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

struct ts_conn_write_req_s {
    uv_write_t req;
    uv_buf_t buf;
    char* ptr;
    
    ts_tcp_conn_t* conn;
    
    ts_conn_write_req_t* prev;
    ts_conn_write_req_t* next;
};

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
    
    ts_tcp_conn_t* prev;
    ts_tcp_conn_t* next;
};

struct ts_tls_s {
    BIO*     appbio; // Application BIO, all IO should be done by this
    BIO*     sslbio; // SSL BIO, only used by OpenSSL
    SSL*     ssl;
    SSL_CTX* ctx;
    int      state;
    ts_tcp_conn_t* conn;
    ts_error_t err;
};

struct ts_ws_s {
    ts_tcp_conn_t* conn;
    int state;
    
    ts_error_t err;
    ts_buf_t* in_buf;
};

#endif //TINYSERVER_TS_SERVER_H
