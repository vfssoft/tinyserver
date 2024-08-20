#ifndef TINYSERVER_TM_H
#define TINYSERVER_TM_H

#define TS_EXTERN /* nothing */

typedef void tm_t;
typedef struct tm_callbacks_s tm_callbacks_t;

typedef int (*tm_log_cb)(void* ctx, const char* msg);
typedef int (*tm_auth_user_cb)(void* ctx, tm_t* mq, const char* username, const char* password, int* ret_auth_ok);

struct tm_callbacks_s {
    void* cb_ctx;
    tm_log_cb log_cb;
    tm_auth_user_cb auth_cb;
};

TS_EXTERN tm_t* tm__create();
TS_EXTERN int tm_destroy(tm_t* mq);

TS_EXTERN int tm__set_listener_count(tm_t* mq, int cnt);
TS_EXTERN int tm__set_listener_host_port(tm_t* mq, int idx, const char* host, int port);
TS_EXTERN int tm__set_listener_use_ipv6(tm_t* mq, int idx, int use);
TS_EXTERN int tm__set_listener_protocol(tm_t* mq, int idx, int proto);
TS_EXTERN int tm__set_listener_certs(tm_t* mq, int idx, const char* cert, const char* key);

TS_EXTERN int tm__set_log_level(tm_t* mq, int log_level);
TS_EXTERN int tm__set_log_dest(tm_t* mq, int dest);
TS_EXTERN int tm__set_log_dir(tm_t* mq, const char* dir);

TS_EXTERN int tm__set_callbacks(tm_t* mq, tm_callbacks_t* cbs);

TS_EXTERN int tm__get_error(tm_t* mq);
TS_EXTERN const char* tm__get_error_msg(tm_t* mq);

TS_EXTERN int tm__start(tm_t* mq);
TS_EXTERN int tm__run(tm_t* mq);
TS_EXTERN int tm__stop(tm_t* mq);

#ifdef __cplusplus
}
#endif


#endif //TINYSERVER_TM_H
