
#ifndef TINYSERVER_TS_INTERNAL_H
#define TINYSERVER_TS_INTERNAL_H

#include "ts_tcp.h"
#include "ts_tls.h"
#include "ts_log.h"
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

typedef struct ts_data_queue_s ts_data_queue_t;
typedef struct ts_stream_block_s ts_stream_block_t;
typedef struct ts_filter_cb_s ts_filter_cb_t;
typedef struct ts_data_pipe_s ts_data_pipe_t;

typedef int (*ts_filter_cb)(ts_data_pipe_t* dp, void* userdata);

struct ts_stream_block_s {
  char* buf;
  int   offset;
  int   len;
    
  ts_stream_block_t* prev;
  ts_stream_block_t* next;
};

struct ts_data_queue_s {
  ts_stream_block_t* in;
  ts_stream_block_t* out;
};

struct ts_filter_cb_s {
  ts_filter_cb cb;
  
  ts_filter_cb_t* prev;
  ts_filter_cb_t* next;
};

struct ts_data_pipe_s {
  ts_data_queue_t* queue;
  ts_filter_cb_t*  filters;
};

#define TS_DATA_PIPE_IN 1
#define TS_DATA_PIPE_OUT 0

ts_data_pipe_t* ts_data_pipe__create();
void ts_data_pipe__destroy(ts_data_pipe_t* dp);
int ts_data_pipe__write(ts_data_pipe_t* dp, int inout, const char* data, int len);
int ts_data_pipe__read(ts_data_pipe_t* dp, int inout, const char* data, int* len);
int ts_data_pipe__peek(ts_data_pipe_t* dp, int inout, char** data, int *out_len);

int ts_server_listener__init_default(ts_server_listener_t* listener);
int ts_server_listener__start(ts_server_listener_t* listener, ts_server_t* server, uv_connection_cb cb);
int ts_server_listener__stop(ts_server_listener_t* listener, uv_close_cb cb);

int ts_server_idle__init(ts_server_t* server);
int ts_server_idle__start(ts_server_t* server);
int ts_server_idle__stop(ts_server_t* server);

int ts_conn__init(ts_server_listener_t* listener, ts_conn_t* conn);
int ts_conn__destroy(ts_server_listener_t* listener, ts_conn_t* conn);
int ts_conn__tcp_connected(ts_conn_t* conn);
int ts_conn__send_tcp_data(ts_conn_t* conn, ts_buf_t* output);
int ts_conn__read_tcp_data(ts_conn_t* conn, uv_read_cb cb);
int ts_conn__close(ts_conn_t* conn, uv_close_cb cb);


    
void ts_error__init(ts_error_t* errt);
void ts_error__reset(ts_error_t* errt);
void ts_error__set(ts_error_t* errt, int err);
void ts_error__set_msg(ts_error_t* errt, int err, const char* msg);
void ts_error__set_msgf(ts_error_t* errt, int err, const char* format, ...);
void ts_error__copy(ts_error_t* dst, ts_error_t* src);

ts_buf_t* ts_buf__create(int cap);
void ts_buf__destroy(ts_buf_t* buf);
int ts_buf__set_length(ts_buf_t* buf, int len);
int ts_buf__get_length(ts_buf_t* buf);
int ts_buf__write(ts_buf_t* buf, const char* data, int len);
int ts_buf__read(ts_buf_t* buf, char* data, int* len);
int ts_buf__set(ts_buf_t* buf, const char* data, int len);
int ts_buf__set_str(ts_buf_t* buf, const char* str, int len);
int ts_buf__set_const(ts_buf_t* buf, const char* data, int len);

int ts_tcp__getaddrinfo(const char* host, int use_ipv6, struct addrinfo* ret);

#endif //TINYSERVER_TS_INTERNAL_H
