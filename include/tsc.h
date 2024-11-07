#ifndef TINYSERVER_TSC_H
#define TINYSERVER_TSC_H

#ifdef __cplusplus
extern "C" {
#endif

#define TS_EXTERN /* nothing */


typedef void tsc_t;
typedef struct tsc_callbacks_s tsc_callbacks_t;

typedef void (*tsc_connected_cb)(void* ctx, tsc_t* c, int status);
typedef void (*tsc_disconnected_cb)(void* ctx, tsc_t* c,  int status);
typedef void (*tsc_read_cb)(void* ctx, tsc_t* c, const char* data, int len);
typedef void (*tsc_write_cb)(void* ctx, tsc_t* c, int status, int can_write_more, void* write_ctx);
typedef void (*tsc_idle_cb)(void* ctx, tsc_t* c);
typedef void (*tsc_timer_cb)(void* ctx, tsc_t* c);
typedef void (*tsc_log_cb)(void* ctx, tsc_t* c, const char* msg);

struct tsc_callbacks_s {
    void* ctx;
    tsc_connected_cb connected_cb;
    tsc_disconnected_cb disconnected_cb;
    tsc_read_cb read_cb;
    tsc_write_cb write_cb;
    tsc_idle_cb idle_cb;
    tsc_timer_cb timer_cb;
    tsc_log_cb log_cb;
};


TS_EXTERN tsc_t* ts_client__create();
TS_EXTERN int ts_client__destroy(tsc_t* c);
TS_EXTERN int ts_client__set_callbacks(tsc_t* c, tsc_callbacks_t* cbs);
TS_EXTERN int ts_client__set_host_port(tsc_t* c, int idx, const char* host, int port);
TS_EXTERN int ts_client__set_use_ipv6(tsc_t* c, int idx, int use);
TS_EXTERN int ts_client__set_protocol(tsc_t* c, int idx, int proto);
TS_EXTERN int ts_client__set_certs(tsc_t* c, int idx, const char* cert, const char* key);
TS_EXTERN int ts_client__connect(tsc_t* c);
TS_EXTERN int ts_client__run(tsc_t* c);
TS_EXTERN int ts_client__disconnect(tsc_t* c);
TS_EXTERN int ts_client__write(tsc_t* c, const char* data, int len, void* write_ctx);

TS_EXTERN int ts_client__get_error(tsc_t* c);
TS_EXTERN const char* ts_client__get_error_msg(tsc_t* c);

TS_EXTERN  int ts_client_log_set_log_level(tsc_t* c, int log_level);
TS_EXTERN  int ts_client_log_set_log_dest(tsc_t* c, int dest);
TS_EXTERN  int ts_client_log_set_log_dir(tsc_t* c, const char* dir);

// internal utils
TS_EXTERN unsigned long long ts_client__now(tsc_t* c);

#ifdef __cplusplus
}
#endif

#endif //TINYSERVER_TSC_H
