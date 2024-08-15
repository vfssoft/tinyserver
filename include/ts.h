#ifndef TINYSERVER_TS_TCP_H
#define TINYSERVER_TS_TCP_H

#include <uv.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/engine.h>

#include "ts_data_buf.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TS_EXTERN /* nothing */

#define TS_DEFAULT_BACKLOG 128

#define TS_ERR_OUT_OF_MEMORY 0x80000001
#define TS_ERR_INVALID_WS_HEADERS 0x80000002
#define TS_ERR_INVALID_WS_FRAME 0x80000003
#define TS_ERR_WS_CLOSED 0x80000004

typedef struct ts_error_s ts_error_t;
typedef struct ts_server_listener_s ts_server_listener_t;
typedef struct ts_server_s ts_server_t;
typedef struct ts_conn_write_req_s ts_conn_write_req_t;
typedef struct ts_conn_s ts_conn_t;
typedef struct ts_tls_s ts_tls_t;
typedef struct ts_ws_s ts_ws_t;
typedef struct ts_log_s ts_log_t;

typedef int (*ts_server_connected_cb)(void* ctx, ts_server_t* server, ts_conn_t* conn, int status);
typedef int (*ts_server_disconnected_cb)(void* ctx, ts_server_t* server, ts_conn_t* conn, int status);
typedef int (*ts_server_read_cb)(void* ctx, ts_server_t* server, ts_conn_t* conn, const char* data, int len);
typedef int (*ts_server_write_cb)(void* ctx, ts_server_t* server, ts_conn_t* conn, int status, int can_write_more);
typedef int (*ts_server_idle_cb)(void* ctx, ts_server_t* server);

typedef int (*ts_log_cb)(void* ctx, int level, const char* msg);

TS_EXTERN int ts_server__init(ts_server_t* server);
TS_EXTERN int ts_server__destroy(ts_server_t server);
TS_EXTERN int ts_server__set_cb_ctx(ts_server_t* server, void* ctx);
TS_EXTERN int ts_server__set_connected_cb(ts_server_t* server, ts_server_connected_cb cb);
TS_EXTERN int ts_server__set_disconnected_cb(ts_server_t* server, ts_server_disconnected_cb cb);
TS_EXTERN int ts_server__set_read_cb(ts_server_t* server, ts_server_read_cb cb);
TS_EXTERN int ts_server__set_write_cb(ts_server_t* server, ts_server_write_cb cb);
TS_EXTERN int ts_server__set_idle_cb(ts_server_t* server, ts_server_idle_cb cb);
TS_EXTERN int ts_server__set_listener_count(ts_server_t* server, int cnt);
TS_EXTERN int ts_server__set_listener_host_port(ts_server_t* server, int idx, const char* host, int port);
TS_EXTERN int ts_server__set_listener_use_ipv6(ts_server_t* server, int idx, int use);
TS_EXTERN int ts_server__set_listener_protocol(ts_server_t* server, int idx, int proto);
TS_EXTERN int ts_server__set_listener_certs(ts_server_t* server, int idx, const char* cert, const char* key);
TS_EXTERN int ts_server__start(ts_server_t* server);
TS_EXTERN int ts_server__run(ts_server_t* server);
TS_EXTERN int ts_server__stop(ts_server_t* server);
TS_EXTERN int ts_server__write(ts_server_t* server, ts_conn_t* conn, const char* data, int len);
TS_EXTERN int ts_server__disconnect(ts_server_t* server, ts_conn_t* conn);

TS_EXTERN  int ts_server_log_set_log_level(ts_server_t* server, int log_level);
TS_EXTERN  int ts_server_log_set_log_dest(ts_server_t* server, int dest);
TS_EXTERN  int ts_server_log_set_log_dir(ts_server_t* server, const char* dir);
TS_EXTERN  int ts_server_log_set_log_cb(ts_server_t* server, void* ctx, ts_log_cb cb);

struct ts_error_s {
    int err;
    char* msg;
};

#define TS_LOG_DEST_FILE   1
#define TS_LOG_DEST_EVENT  2

#define TS_LOG_LEVEL_NONE    0
#define TS_LOG_LEVEL_ERROR   1
#define TS_LOG_LEVEL_INFO    2
#define TS_LOG_LEVEL_VERB    3
#define TS_LOG_LEVEL_DEBUG   4
#define TS_LOG_LEVEL_DEBUGEX 5

struct ts_log_s {
    int log_level;
    int log_dest;
    char* log_dir;
    void* log_ctx;
    ts_log_cb log_cb;

    int log_timestamp;
    char* log_timestamp_format;

    // internal states
    FILE* cur_log_file;

    uv_mutex_t mutex;
};

#define TS_PROTO_TCP   1
#define TS_PROTO_TLS   2
#define TS_PROTO_WS    3
#define TS_PROTO_WSS   4


#define TS_STATE_HANDSHAKING   0
#define TS_STATE_CONNECTED     1
#define TS_STATE_DISCONNECTING 2
#define TS_STATE_DISCONNECTED  3

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
    
    ts_conn_t* conns;
    ts_log_t log;
    ts_error_t err;
};

struct ts_conn_write_req_s {
    uv_write_t req;
    uv_buf_t buf;
    char* ptr;
    
    ts_conn_t* conn;
    
    ts_conn_write_req_t* prev;
    ts_conn_write_req_t* next;
};

struct ts_conn_s {
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

    ts_conn_t* prev;
    ts_conn_t* next;
};

struct ts_tls_s {
    BIO*     appbio; // Application BIO, all IO should be done by this
    BIO*     sslbio; // SSL BIO, only used by OpenSSL
    SSL*     ssl;
    SSL_CTX* ctx;
    int      state;
    ts_conn_t* conn;
    ts_error_t err;
};

struct ts_ws_s {
    ts_conn_t* conn;
    int state;
    
    ts_error_t err;
    ts_buf_t* in_buf;
};

#ifdef __cplusplus
}
#endif

#endif //TINYSERVER_TS_TCP_H
