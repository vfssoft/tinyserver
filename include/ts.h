#ifndef TINYSERVER_TS_TCP_H
#define TINYSERVER_TS_TCP_H

#include <tsdefs.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TS_EXTERN /* nothing */

#define TS_DEFAULT_BACKLOG 128

typedef void ts_t;
typedef void ts_conn_t;
typedef struct ts_callbacks_s ts_callbacks_t;

typedef void (*ts_server_connected_cb)(void* ctx, ts_t* server, ts_conn_t* conn, int status);
typedef void (*ts_server_disconnected_cb)(void* ctx, ts_t* server, ts_conn_t* conn, int status);
typedef void (*ts_server_read_cb)(void* ctx, ts_t* server, ts_conn_t* conn, const char* data, int len);
typedef void (*ts_server_write_cb)(void* ctx, ts_t* server, ts_conn_t* conn, int status, int can_write_more, void* write_ctx);
typedef void (*ts_server_idle_cb)(void* ctx, ts_t* server);
typedef void (*ts_server_timer_cb)(void* ctx, ts_t* server, ts_conn_t* conn);
typedef void (*ts_log_cb)(void* ctx, ts_t* server, const char* msg);

struct ts_callbacks_s {
    void* ctx;
    ts_server_connected_cb connected_cb;
    ts_server_disconnected_cb disconnected_cb;
    ts_server_read_cb read_cb;
    ts_server_write_cb write_cb;
    ts_server_idle_cb idle_cb;
    ts_server_timer_cb timer_cb;
    ts_log_cb log_cb;
};


TS_EXTERN ts_t* ts_server__create();
TS_EXTERN int ts_server__destroy(ts_t* server);
TS_EXTERN int ts_server__set_callbacks(ts_t* server, ts_callbacks_t* cbs);
TS_EXTERN int ts_server__set_listener_count(ts_t* server, int cnt);
TS_EXTERN int ts_server__set_listener_host_port(ts_t* server, int idx, const char* host, int port);
TS_EXTERN int ts_server__set_listener_use_ipv6(ts_t* server, int idx, int use);
TS_EXTERN int ts_server__set_listener_protocol(ts_t* server, int idx, int proto);
TS_EXTERN int ts_server__set_listener_certs(ts_t* server, int idx, const char* cert, const char* key);
TS_EXTERN int ts_server__start(ts_t* server);
TS_EXTERN int ts_server__run(ts_t* server);
TS_EXTERN int ts_server__stop(ts_t* server);
TS_EXTERN int ts_server__write(ts_t* server, ts_conn_t* conn, const char* data, int len, void* write_ctx);
TS_EXTERN int ts_server__disconnect(ts_t* server, ts_conn_t* conn);

TS_EXTERN void* ts_server__get_conn_user_data(ts_t* server, ts_conn_t* conn);
TS_EXTERN void ts_server__set_conn_user_data(ts_t* server, ts_conn_t* conn, void* user_data);
TS_EXTERN const char* ts_server__get_conn_remote_host(ts_t* server, ts_conn_t* c);
TS_EXTERN int ts_server__has_pending_write_reqs(ts_t* server, ts_conn_t* c);
TS_EXTERN int ts_server__conn_start_timer(ts_t* server, ts_conn_t* conn, int timeoutMS, int repeatMS);
TS_EXTERN int ts_server__conn_stop_timer(ts_t* server, ts_conn_t* conn);

TS_EXTERN int ts_server__get_error(ts_t* server);
TS_EXTERN const char* ts_server__get_error_msg(ts_t* server);

TS_EXTERN  int ts_server_log_set_log_level(ts_t* server, int log_level);
TS_EXTERN  int ts_server_log_set_log_dest(ts_t* server, int dest);
TS_EXTERN  int ts_server_log_set_log_dir(ts_t* server, const char* dir);

// internal utils
TS_EXTERN unsigned long long ts_server__now(ts_t* server);

#ifdef __cplusplus
}
#endif

#endif //TINYSERVER_TS_TCP_H
