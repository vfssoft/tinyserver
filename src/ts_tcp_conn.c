
#include "ts_internal.h"

int ts_conn__init(ts_server_listener_t* listener, ts_conn_t* conn) {
  int err = 0;
  
  conn->listener = listener;
  conn->write_reqs = NULL;
  
  switch (listener->protocol) {
    case TS_PROTO_TCP:
      conn->tls = NULL;
      break;
      
    case TS_PROTO_TLS:
      conn->tls = (ts_tls_t*) ts__malloc(sizeof(ts_tls_t));
      if (conn->tls == NULL) {
        err = TS_ERR_OUT_OF_MEMORY;
        goto done;
      }
      
      err = ts_tls__init(conn->tls);
      if (err) {
        goto done;
      }
      
      err = ts_tls__set_cert_files(conn->tls, listener->cert, listener->key);
      if (err) {
        goto done;
      }
      
      err = ts_tls__set_verify_mode(conn->tls, listener->tls_verify_mode);
      if (err) {
        goto done;
      }
      
      break;
  }
  
  err = uv_tcp_init(listener->uvloop, &conn->uvtcp);
  if (err) {
    return err;
  }
  
done:
  
  return err;
}

int ts_conn__destroy(ts_server_listener_t* listener, ts_conn_t* conn) {
  if (conn->tls) {
    ts_tls__destroy(conn->tls);
    ts__free(conn->tls);
  }
  return 0;
}

static int ts_conn__init_write_req(ts_conn_write_req_t* req, ts_conn_t* conn, char* data, int len) {
  req->ptr = (char*) ts__malloc(len);
  if (req->ptr == NULL) {
    return TS_ERR_OUT_OF_MEMORY;
  }
  memcpy(req->ptr, data, len);
  
  req->conn = conn;
  req->buf = uv_buf_init(req->ptr, len);
  DL_APPEND(conn->write_reqs, req);
  
  return 0;
}
static void ts_conn__destroy_write_req(ts_conn_t* conn, ts_conn_write_req_t* req) {
  DL_DELETE(conn->write_reqs, req);
  
  ts__free(req->buf.base);
  ts__free(req);
}

static void uv_on_write(uv_write_t *req, int status) {
  ts_conn_write_req_t* wr = (ts_conn_write_req_t*) req;
  ts_conn_t* conn = wr->conn;
  ts_server_t* server = conn->listener->server;
  ts_conn__destroy_write_req(conn, wr);
  
  int has_pending_write_reqs = conn->write_reqs != NULL;
  server->write_cb(server->cb_ctx, server, conn, status, !has_pending_write_reqs);
}
static void uv_on_alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
  // TODO: add mem pool
  buf->base = (char*) ts__malloc(suggested_size);
  buf->len = suggested_size;
}

int ts_conn__send_tcp_data(ts_conn_t* conn, ts_buf_t* output) {
  int err;
  
  if (output->len > 0) {
    ts_conn_write_req_t* write_req = (ts_conn_write_req_t*) ts__malloc(sizeof(ts_conn_write_req_t));
    if (write_req == NULL) {
      return TS_ERR_OUT_OF_MEMORY;
    }
    
    err = ts_conn__init_write_req(write_req, conn, output->buf, output->len);
    if (err) {
      return err;
    }
    
    err = uv_write((uv_write_t*)write_req, (uv_stream_t*)&conn->uvtcp, &write_req->buf, 1, uv_on_write);
    if (err) {
      return err;
    }
    
    ts_buf__set_length(output, 0); // reset the buf for reuse
  }
  
  return 0;
}
int ts_conn__read_tcp_data(ts_conn_t* conn, uv_read_cb cb) {
  int err;
  err = uv_read_start((uv_stream_t*) &conn->uvtcp, uv_on_alloc_buffer, cb);
  return err;
}
int ts_conn__close(ts_conn_t* conn, uv_close_cb cb) {
  uv_handle_t* h = (uv_handle_t*)&conn->uvtcp;
  if (h && !uv_is_closing(h)) {
    uv_close(h, cb);
  }
  return 0;
}