
#ifndef TINYSERVER_TS_INTERNAL_H
#define TINYSERVER_TS_INTERNAL_H

#include <uv.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/engine.h>

#include <stdio.h>

#include "ts.h"
#include "ts_server.h"
#include "ts_tcp_conn.h"
#include "ts_tls.h"
#include "ts_ws.h"
#include "ts_log.h"
#include "ts_miscellany.h"
#include "ts_crypto.h"
#include "ts_mem.h"
#include "utlist.h"

#include <time.h>
#include <inttypes.h>

// help macros
#define CONTAINER_OF(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))

#ifndef BOOL
#define BOOL int
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

int ts_server_listener__init_default(ts_server_listener_t* listener);
int ts_server_listener__start(ts_server_listener_t* listener, ts_server_t* server, uv_connection_cb cb);
int ts_server_listener__stop(ts_server_listener_t* listener, uv_close_cb cb);

int ts_server_idle__init(ts_server_t* server);
int ts_server_idle__start(ts_server_t* server);
int ts_server_idle__stop(ts_server_t* server);


void ts_error__init(ts_error_t* errt);
void ts_error__reset(ts_error_t* errt);
void ts_error__set(ts_error_t* errt, int err);
void ts_error__set_msg(ts_error_t* errt, int err, const char* msg);
void ts_error__set_msgf(ts_error_t* errt, int err, const char* format, ...);
void ts_error__copy(ts_error_t* dst, ts_error_t* src);

#endif //TINYSERVER_TS_INTERNAL_H
