
#ifndef TINYSERVER_TS_CONN__WRITE_REQ_H
#define TINYSERVER_TS_CONN__WRITE_REQ_H

#include "ts_internal.h"

// TODO: add an id for the write req
struct ts_conn_write_req_s {
    uv_write_t req;
    uv_buf_t uvbuf;
    void* write_ctx;
    
    ts_buf_t*            inter_bufs[2];
    int                  internal;
    ts_tcp_conn_t*       conn;
    ts_conn_write_req_t* prev;
    ts_conn_write_req_t* next;
};

ts_conn_write_req_t* ts_conn_write_req__create(ts_tcp_conn_t* conn, BOOL internal, void* write_ctx);
int ts_conn_write_req__destroy(ts_conn_write_req_t* req);

void ts_conn_write_req__switch_buf(ts_conn_write_req_t* req);
void ts_conn_write_req__used_unuse_bufs(ts_conn_write_req_t* req, ts_buf_t** used, ts_buf_t** unused);
ts_buf_t* ts_conn_write_req__used_buf(ts_conn_write_req_t* req);
uv_buf_t* ts_conn_write_req__uvbuf(ts_conn_write_req_t* req);

#endif //TINYSERVER_TS_CONN__WRITE_REQ_H

