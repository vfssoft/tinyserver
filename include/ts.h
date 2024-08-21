#ifndef TINYSERVER_TS_TCP_H
#define TINYSERVER_TS_TCP_H

#ifdef __cplusplus
extern "C" {
#endif

#define TS_EXTERN /* nothing */

#define TS_DEFAULT_BACKLOG 128

typedef void ts_t;
typedef void ts_conn_t;


typedef void (*ts_server_connected_cb)(void* ctx, ts_t* server, ts_conn_t* conn, int status);
typedef void (*ts_server_disconnected_cb)(void* ctx, ts_t* server, ts_conn_t* conn, int status);
typedef void (*ts_server_read_cb)(void* ctx, ts_t* server, ts_conn_t* conn, const char* data, int len);
typedef void (*ts_server_write_cb)(void* ctx, ts_t* server, ts_conn_t* conn, int status, int can_write_more);
typedef void (*ts_server_idle_cb)(void* ctx, ts_t* server);

typedef void (*ts_log_cb)(void* ctx, int level, const char* msg);

TS_EXTERN ts_t* ts_server__create();
TS_EXTERN int ts_server__destroy(ts_t* server);
TS_EXTERN int ts_server__set_cb_ctx(ts_t* server, void* ctx);
TS_EXTERN int ts_server__set_connected_cb(ts_t* server, ts_server_connected_cb cb);
TS_EXTERN int ts_server__set_disconnected_cb(ts_t* server, ts_server_disconnected_cb cb);
TS_EXTERN int ts_server__set_read_cb(ts_t* server, ts_server_read_cb cb);
TS_EXTERN int ts_server__set_write_cb(ts_t* server, ts_server_write_cb cb);
TS_EXTERN int ts_server__set_idle_cb(ts_t* server, ts_server_idle_cb cb);
TS_EXTERN int ts_server__set_listener_count(ts_t* server, int cnt);
TS_EXTERN int ts_server__set_listener_host_port(ts_t* server, int idx, const char* host, int port);
TS_EXTERN int ts_server__set_listener_use_ipv6(ts_t* server, int idx, int use);
TS_EXTERN int ts_server__set_listener_protocol(ts_t* server, int idx, int proto);
TS_EXTERN int ts_server__set_listener_certs(ts_t* server, int idx, const char* cert, const char* key);
TS_EXTERN int ts_server__start(ts_t* server);
TS_EXTERN int ts_server__run(ts_t* server);
TS_EXTERN int ts_server__stop(ts_t* server);
TS_EXTERN int ts_server__write(ts_t* server, ts_conn_t* conn, const char* data, int len);
TS_EXTERN int ts_server__disconnect(ts_t* server, ts_conn_t* conn);

TS_EXTERN void* ts_server__get_conn_user_data(ts_t* server, ts_conn_t* conn);
TS_EXTERN void ts_server__set_conn_user_data(ts_t* server, ts_conn_t* conn, void* user_data);
TS_EXTERN const char* ts_server__get_conn_remote_host(ts_t* server, ts_conn_t* c);

TS_EXTERN int ts_server__get_error(ts_t* server);
TS_EXTERN const char* ts_server__get_error_msg(ts_t* server);

TS_EXTERN  int ts_server_log_set_log_level(ts_t* server, int log_level);
TS_EXTERN  int ts_server_log_set_log_dest(ts_t* server, int dest);
TS_EXTERN  int ts_server_log_set_log_dir(ts_t* server, const char* dir);
TS_EXTERN  int ts_server_log_set_log_cb(ts_t* server, void* ctx, ts_log_cb cb);

// internal utils
TS_EXTERN unsigned long long ts_server__now(ts_t* server);

#define TS_LOG_DEST_FILE   1
#define TS_LOG_DEST_EVENT  2

#define TS_LOG_LEVEL_NONE    0
#define TS_LOG_LEVEL_ERROR   1
#define TS_LOG_LEVEL_INFO    2
#define TS_LOG_LEVEL_VERB    3
#define TS_LOG_LEVEL_DEBUG   4
#define TS_LOG_LEVEL_DEBUGEX 5

#define TS_PROTO_TCP   1
#define TS_PROTO_TLS   2
#define TS_PROTO_WS    3
#define TS_PROTO_WSS   4

#define TS_STATE_HANDSHAKING   0
#define TS_STATE_CONNECTED     1
#define TS_STATE_DISCONNECTING 2
#define TS_STATE_DISCONNECTED  3

#ifdef __cplusplus
}
#endif

#endif //TINYSERVER_TS_TCP_H
