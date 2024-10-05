
#ifndef TINYSERVER_TS_CONN__WRITE_REQ_H
#define TINYSERVER_TS_CONN__WRITE_REQ_H

#include "ts_internal.h"

struct ts_conn_write_req_s {
    uv_write_t req;
    uv_buf_t buf;
    
    ts_tcp_conn_t*       conn;
    ts_conn_write_req_t* prev;
    ts_conn_write_req_t* next;
};

ts_conn_write_req_t* ts_conn_write_req__create(ts_tcp_conn_t* conn, char* data, int len);
int ts_conn_write_req__destroy(ts_conn_write_req_t* req);

#endif //TINYSERVER_TS_CONN__WRITE_REQ_H

