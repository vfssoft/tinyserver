#include "ts_conn__write_req.h"

ts_conn_write_req_t* ts_conn_write_req__create(ts_tcp_conn_t* conn, char* data, int len) {
  ts_conn_write_req_t* req;
  char* ptr;
  
  req = (ts_conn_write_req_t*) ts__malloc(sizeof(ts_conn_write_req_t));
  if (req == NULL) {
    return NULL;
  }
  
  ptr = (char*) ts__malloc(len);
  if (ptr == NULL) {
    return NULL;
  }
  memcpy(ptr, data, len);
  
  req->buf = uv_buf_init(ptr, len);
  req->conn = conn;
  
  return req;
}

int ts_conn_write_req__destroy(ts_conn_write_req_t* req) {
  ts__free(req->buf.base);
  ts__free(req);
}
