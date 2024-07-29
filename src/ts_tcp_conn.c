
#include "ts_internal.h"

int ts_conn__init(ts_server_listener_t* listener, ts_conn_t* conn) {
  int err = 0;
  
  conn->listener = listener;
  conn->write_reqs = NULL;
  ts_error__init(&conn->err);

  memset(conn->local_addr, 0, sizeof(conn->local_addr));
  memset(conn->remote_addr, 0, sizeof(conn->remote_addr));
  
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
      
      err = ts_tls__init(conn->tls, listener->ssl_ctx);
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
static void uv_on_free_buffer(const uv_buf_t* buf) {
  if (buf == NULL || buf->base == NULL || buf->len == 0) {
    return;
  }
  ts__free(buf->base);
}

static int ts_server__process_ssl_socket_data(ts_conn_t* conn, ts_ro_buf_t* input, ts_buf_t** decrypted) {
  int err = 0;
  ts_tls_t* tls = conn->tls;

  assert(tls->ssl_state == TLS_STATE_HANDSHAKING || tls->ssl_state == TLS_STATE_CONNECTED);

  while (input->len > 0) { // we have to consume all input data here

    ts_buf__set_length(tls->ssl_buf, 0);

    if (tls->ssl_state == TLS_STATE_HANDSHAKING) {
      err = ts_tls__handshake(tls, input, tls->ssl_buf);
      if (err) {
        goto done;
      }

      err = ts_conn__send_tcp_data(conn, tls->ssl_buf);
      if (err) {
        goto done;
      }

    } else {
      err = ts_tls__decrypt(tls, input, tls->ssl_buf);
      if (err) {
        goto done;
      }
    }
    
  }
  
  *decrypted = tls->ssl_buf;

  done:
  return err;
}

static void uv_on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
  int err = 0;
  ts_conn_t* conn = (ts_conn_t*) stream;
  ts_server_t* server = conn->listener->server;
  ts_tls_t* tls = conn->tls;
  ts_buf_t* ssl_decrypted = NULL;
  ts_ro_buf_t input;
  int ssl_state = 0;
  
  LOG_VERB("[%s] data received: %d", conn->remote_addr, nread);

  input.buf = buf->base;
  input.len = (int)nread;

  // nread can be zero
  if (nread > 0) {

    if (tls) {
      ssl_state = tls->ssl_state;
      assert(ssl_state == TLS_STATE_HANDSHAKING || ssl_state == TLS_STATE_CONNECTED);

      err = ts_server__process_ssl_socket_data(conn, &input, &ssl_decrypted);
      if (err) {
        goto done;
      }

      if (tls->ssl_state == TLS_STATE_HANDSHAKING) {
        goto done; // handshake is not done, nothing can be done, wait for more tcp data
      }

      if (ssl_state == TLS_STATE_HANDSHAKING && tls->ssl_state == TLS_STATE_CONNECTED) {
        // tls handshake is done
        server->connected_cb(server->cb_ctx, server, conn, 0);
      }

      input.buf = ssl_decrypted->buf;
      input.len = ssl_decrypted->len;
    }
    
    if (input.len > 0) {
      server->read_cb(server->cb_ctx, server, conn, input.buf, input.len);
    }
  }

  if (nread < 0) {
    LOG_ERROR("[%s] connection error: %d %s", conn->remote_addr, nread, uv_strerror(nread));
    ts_server__disconnect(server, conn);
  }

  uv_on_free_buffer(buf);

  done:
  return;
}

static int ts_conn__populate_addrs(ts_conn_t* conn) {
  int err;
  struct sockaddr_storage local_addr_storage;
  struct sockaddr_storage remote_addr_storage;

  int namelen = sizeof(local_addr_storage);
  err = uv_tcp_getsockname(&conn->uvtcp, (struct sockaddr*)&local_addr_storage, &namelen);
  if (err) {
    return err;
  }

  ts_sockaddr__str(&local_addr_storage, conn->local_addr, sizeof(conn->local_addr));

  namelen = sizeof(remote_addr_storage);
  err = uv_tcp_getpeername(&conn->uvtcp, (struct sockaddr*)&remote_addr_storage, &namelen);
  if (err) {
    return err;
  }

  ts_sockaddr__str(&remote_addr_storage, conn->remote_addr, sizeof(conn->remote_addr));

  return 0;
}

int ts_conn__tcp_connected(ts_conn_t* conn) {
  int err;
  ts_server_listener_t* listener = conn->listener;
  ts_server_t* server = listener->server;

  err = ts_conn__populate_addrs(conn);
  if (err) {
    return err;
  }
  
  LOG_VERB("[%s] New connection accepted", conn->remote_addr);

  if (listener->protocol == TS_PROTO_TCP) {
    err = server->connected_cb(server->cb_ctx, server, conn, 0);
    if (err) {
      return err;
    }
  }

  return ts_conn__read_tcp_data(conn, uv_on_read);
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
  if (err) {
    ts_error__set_msg(&conn->err, err, uv_strerror(err));
  }
  return err;
}
int ts_conn__close(ts_conn_t* conn, uv_close_cb cb) {
  int err;
  
  if (conn->tls) {
    ts_tls_t* tls = conn->tls;
    ts_buf__set_length(tls->ssl_buf, 0);
    err = ts_tls__disconnect(tls, tls->ssl_buf);
    err = ts_conn__send_tcp_data(conn, tls->ssl_buf);
    // TODO: log the error
  }
  
  uv_handle_t* h = (uv_handle_t*)&conn->uvtcp;
  if (h && !uv_is_closing(h)) {
    uv_close(h, cb);
  }
  return 0;
}
