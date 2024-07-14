
#ifndef TINYSERVER_TS_INTERNAL_H
#define TINYSERVER_TS_INTERNAL_H

#include "ts_tcp.h"
#include "ts_mem.h"
#include "utlist.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/engine.h>

// help macros
#define CONTAINER_OF(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))

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


int ts_conn__init(ts_server_listener_t* listener, ts_conn_t* conn);
ts_conn_write_req_t* ts_conn__create_write_req(ts_conn_t* conn, char* data, int len);
void ts_conn__destroy_write_req(ts_conn_t* conn, ts_conn_write_req_t* req);

int ts_tls__init(ts_tls_t* tls);
int ts_tls__set_cert_files(ts_tls_t* tls, const char* cert, const char* key);
int ts_tls__set_verify_mode(ts_tls_t* tls, int mode);
int ts_tls__get_state(ts_tls_t* tls);
int ts_tls__handshake(ts_tls_t* tls, ts_ro_buf_t* input, ts_buf_t* output);
int ts_tls__decrypt(ts_tls_t* tls, ts_ro_buf_t* input, ts_buf_t* output);

    
ts_error_t* ts_error_create(int err);
void ts_error_destroy(ts_error_t* e);

ts_buf_t* ts_buf__create(int cap);
void ts_buf__destroy(ts_buf_t* buf);
int ts_buf__set_length(ts_buf_t* buf, int len);
int ts_buf__get_length(ts_buf_t* buf);
int ts_buf__write(ts_buf_t* buf, const char* data, int len);
int ts_buf__read(ts_buf_t* buf, const char* data, int* len);
int ts_buf__set(ts_buf_t* buf, const char* data, int len);
int ts_buf__set_const(ts_buf_t* buf, const char* data, int len);

int ts_tcp__getaddrinfo(const char* host, int use_ipv6, struct addrinfo* ret);

#endif //TINYSERVER_TS_INTERNAL_H
