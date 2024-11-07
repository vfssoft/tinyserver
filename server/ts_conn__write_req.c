#include "ts_conn__write_req.h"

ts_conn_write_req_t* ts_conn_write_req__create(ts_tcp_conn_t* conn, int internal, void* write_ctx) {
  ts_conn_write_req_t* req;
  
  req = (ts_conn_write_req_t*) ts__malloc(sizeof(ts_conn_write_req_t));
  if (req == NULL) {
    return NULL;
  }
  
  req->inter_bufs[0] = ts_buf__create(0);
  req->inter_bufs[1] = ts_buf__create(0);
  if (req->inter_bufs[0] == NULL || req->inter_bufs[1] == NULL) {
    return NULL;
  }
  
  req->conn = conn;
  req->internal = internal;
  req->write_ctx = write_ctx;
  
  return req;
}

int ts_conn_write_req__destroy(ts_conn_write_req_t* req) {
  ts_buf__destroy(req->inter_bufs[0]);
  ts_buf__destroy(req->inter_bufs[1]);
  ts__free(req);
  return 0;
}

void ts_conn_write_req__switch_buf(ts_conn_write_req_t* req) {
  // inter_bufs[0] always store the data that should be sent to peer.
  ts_buf_t* tmp = req->inter_bufs[0];
  req->inter_bufs[0] = req->inter_bufs[1];
  req->inter_bufs[1] = tmp;
}
void ts_conn_write_req__used_unuse_bufs(ts_conn_write_req_t* req, ts_buf_t** used, ts_buf_t** unused) {
  *used = req->inter_bufs[0];
  *unused = req->inter_bufs[1];
}
ts_buf_t* ts_conn_write_req__used_buf(ts_conn_write_req_t* req) {
  return req->inter_bufs[0];
}
uv_buf_t* ts_conn_write_req__uvbuf(ts_conn_write_req_t* req) {
  req->uvbuf = uv_buf_init(req->inter_bufs[0]->buf, req->inter_bufs[0]->len);
  return &req->uvbuf;
}
