
#include "ts_internal.h"

int ts_conn__init(ts_server_listener_t* listener, ts_conn_t* conn) {
  int err = 0;
  ts_server_t* server = listener->server;
  BOOL use_ssl = ts_use_ssl(listener->protocol);
  BOOL use_ws = ts_use_websocket(listener->protocol);
  
  conn->listener = listener;
  conn->write_reqs = NULL;
  conn->tls = NULL;
  conn->ws = NULL;
  memset(&(conn->uvtcp), 0, sizeof(uv_tcp_t));
  ts_error__init(&conn->err);

  memset(conn->local_addr, 0, sizeof(conn->local_addr));
  memset(conn->remote_addr, 0, sizeof(conn->remote_addr));
  
  if (use_ssl) {
    conn->tls = (ts_tls_t*) ts__malloc(sizeof(ts_tls_t));
    if (conn->tls == NULL) {
      ts_error__set(&(conn->err), TS_ERR_OUT_OF_MEMORY);
      goto done;
    }
  
    err = ts_tls__init(conn->tls, conn);
    if (err) {
      goto done;
    }
  }
  
  if (use_ws) {
    conn->ws = (ts_ws_t*) ts__malloc(sizeof(ts_ws_t));
    if (conn->ws == NULL) {
      ts_error__set(&(conn->err), TS_ERR_OUT_OF_MEMORY);
      goto done;
    }
    
    err = ts_ws__init(conn->ws, conn);
    if (err) {
      goto done;
    }
  }
  
  err = uv_tcp_init(listener->uvloop, &conn->uvtcp);
  if (err) {
    ts_error__set_msg(&(conn->err), err, uv_strerror(err));
    goto done;
  }
  
done:
  if (err) {
    LOG_ERROR("[%s] Initial connection failed: %d %s", conn->remote_addr, conn->err.err, conn->err.msg);
  }
  
  return err;
}

int ts_conn__destroy(ts_server_listener_t* listener, ts_conn_t* conn) {
  if (conn->tls) {
    ts_tls__destroy(conn->tls);
    ts__free(conn->tls);
    conn->tls = NULL;
  }
  if (conn->ws) {
    ts_ws__destroy(conn->ws);
    ts__free(conn->ws);
    conn->ws = NULL;
  }
  conn->listener = NULL;
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

static int ts_conn__process_ssl_socket_data(ts_conn_t* conn, ts_ro_buf_t* input, ts_buf_t** decrypted) {
  int err = 0;
  ts_server_t* server = conn->listener->server;
  ts_tls_t* tls = conn->tls;

  assert(tls->ssl_state == TLS_STATE_HANDSHAKING || tls->ssl_state == TLS_STATE_CONNECTED);
  ts_buf__set_length(tls->ssl_buf, 0);
  
  while (input->len > 0) { // we have to consume all input data here

    if (tls->ssl_state == TLS_STATE_HANDSHAKING) {
      err = ts_tls__handshake(tls, input, tls->ssl_buf);
      if (err) {
        ts_error__copy(&(conn->err), &(tls->err));
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
  if (err) {
    LOG_ERROR("[%s] TLS error: %d %s", conn->err.err, conn->err.msg);
  }
  return err;
}

static int ts_conn__process_ws_socket_data(ts_conn_t* conn, ts_ro_buf_t* input, ts_buf_t** unwrapped) {
  int err = 0;
  ts_server_t* server = conn->listener->server;
  ts_ws_t* ws = conn->ws;
  
  assert(ws->state == TS_WS_STATE_HANDSHAKING || ws->state == TS_WS_STATE_CONNECTED);
  ts_buf__set_length(ws->out_buf, 0);
  
  while (input->len > 0) { // we have to consume all input data here
    
    if (ws->state == TS_WS_STATE_HANDSHAKING) {
      err = ts_ws__handshake(ws, input, ws->out_buf);
      if (err) {
        ts_error__copy(&(conn->err), &(ws->err));
        goto done;
      }
      
      err = ts_conn__send_tcp_data(conn, ws->out_buf);
      if (err) {
        goto done;
      }
    } else {
      err = ts_ws__unwrap(ws, input, ws->out_buf);
      if (err) {
        goto done;
      }
    }
    
  }
  
  *unwrapped = ws->out_buf;
  
  done:
  if (err) {
    LOG_ERROR("[%s] Websocket error: %d %s", conn->err.err, conn->err.msg);
  }
  return err;
}

static void uv_on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
  int err = 0;
  ts_conn_t* conn = (ts_conn_t*) stream;
  ts_server_listener_t* listener = conn->listener;
  ts_server_t* server = listener->server;
  ts_tls_t* tls = conn->tls;
  ts_ws_t* ws = conn->ws;
  ts_buf_t* ssl_decrypted = NULL;
  ts_buf_t* ws_unwrapped = NULL;
  ts_ro_buf_t input;
  int ssl_state = 0;
  int ws_state = 0;
  
  BOOL use_ssl = ts_use_ssl(listener->protocol);
  BOOL use_ws = ts_use_websocket(listener->protocol);
  
  LOG_DEBUG("[%s] Data received: %d", conn->remote_addr, nread);

  input.buf = buf->base;
  input.len = (int)nread;

  // nread can be zero
  if (nread > 0) {

    if (use_ssl) {
      ssl_state = tls->ssl_state;
      assert(ssl_state == TLS_STATE_HANDSHAKING || ssl_state == TLS_STATE_CONNECTED);

      err = ts_conn__process_ssl_socket_data(conn, &input, &ssl_decrypted);
      if (err) {
        goto done;
      }

      if (tls->ssl_state == TLS_STATE_HANDSHAKING) {
        goto done; // handshake is not done, nothing can be done, wait for more tcp data
      }

      if (ssl_state == TLS_STATE_HANDSHAKING && tls->ssl_state == TLS_STATE_CONNECTED) {
        // tls handshake is done
        if (!use_ws) {
          server->connected_cb(server->cb_ctx, server, conn, 0);
        }
      }

      input.buf = ssl_decrypted->buf;
      input.len = ssl_decrypted->len;
    }
    
    if (ws) {
      ws_state = ws->state;
      assert(ws_state == TS_WS_STATE_HANDSHAKING || ws_state == TS_WS_STATE_CONNECTED);
  
      err = ts_conn__process_ws_socket_data(conn, &input, &ws_unwrapped);
      if (err) {
        goto done;
      }
  
      if (ws->state == TS_WS_STATE_HANDSHAKING) {
        goto done; // handshake is not done, nothing can be done, wait for more tcp data
      }
  
      if (ws_state == TS_WS_STATE_HANDSHAKING && ws->state == TS_WS_STATE_CONNECTED) {
        // ws handshake is done
        server->connected_cb(server->cb_ctx, server, conn, 0);
      }
  
      input.buf = ws_unwrapped->buf;
      input.len = ws_unwrapped->len;
    }
    
    if (input.len > 0) {
      server->read_cb(server->cb_ctx, server, conn, input.buf, input.len);
    }
  }

  if (nread < 0) {
    LOG_ERROR("[%s] Connection error: %d %s", conn->remote_addr, nread, uv_strerror(nread));
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

static int ts_conn__send_tcp_data(ts_conn_t* conn, ts_buf_t* output) {
  int err = 0;
  ts_server_t* server = conn->listener->server;
  
  if (output->len > 0) {
    LOG_DEBUG("[%s] Send data: %d", conn->remote_addr, output->len);
    
    ts_conn_write_req_t* write_req = (ts_conn_write_req_t*) ts__malloc(sizeof(ts_conn_write_req_t));
    if (write_req == NULL) {
      ts_error__set(&(conn->err), TS_ERR_OUT_OF_MEMORY);
      goto done;
    }
    
    err = ts_conn__init_write_req(write_req, conn, output->buf, output->len);
    if (err) {
      goto done;
    }
    
    err = uv_write((uv_write_t*)write_req, (uv_stream_t*)&conn->uvtcp, &write_req->buf, 1, uv_on_write);
    if (err) {
      ts_error__set_msg(&(conn->err), err, uv_strerror(err));
      goto done;
    }
    
    ts_buf__set_length(output, 0); // reset the buf for reuse
    
done:
    if (err) {
      LOG_ERROR("[%s] Send data failed: %d %s", conn->remote_addr, conn->err.err, conn->err.msg);
    }
  }
  
  return err;
}
static int ts_conn__read_tcp_data(ts_conn_t* conn, uv_read_cb cb) {
  int err;
  err = uv_read_start((uv_stream_t*) &conn->uvtcp, uv_on_alloc_buffer, cb);
  if (err) {
    ts_error__set_msg(&conn->err, err, uv_strerror(err));
  }
  return err;
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
  
  err = ts_conn__read_tcp_data(conn, uv_on_read);
  if (err) {
    return err;
  }
  
  if (listener->protocol == TS_PROTO_TCP) {
    err = server->connected_cb(server->cb_ctx, server, conn, 0);
    if (err) {
      return err;
    }
  }
  
  return 0;
}
int ts_conn__send_data(ts_conn_t* conn, ts_buf_t* input) {
  int err;
  ts_server_listener_t* listener = conn->listener;
  ts_server_t* server = listener->server;
  
  BOOL use_ssl = ts_use_ssl(listener->protocol);
  BOOL use_ws = ts_use_websocket(listener->protocol);
  
  ts_ro_buf_t roinput;
  roinput.buf = input->buf;
  roinput.len = input->len;
  
  if (use_ws) {
    ts_buf__set_length(conn->ws->out_buf, 0);
  
    err = ts_ws__wrap(conn->ws, &roinput, conn->ws->out_buf);
    if (err) {
      ts_error__copy(&(conn->err), &(conn->ws->err));
      return err;
    }
  
    roinput.buf = conn->ws->out_buf->buf;
    roinput.len = conn->ws->out_buf->len;
  }
  
  if (use_ssl) {
    ts_buf__set_length(conn->tls->ssl_buf, 0);
    
    err = ts_tls__encrypt(conn->tls, &roinput, conn->tls->ssl_buf);
    if (err) {
      ts_error__copy(&(conn->err), &(conn->tls->err));
      return err;
    }
  
    roinput.buf = conn->tls->ssl_buf->buf;
    roinput.len = conn->tls->ssl_buf->len;
  }
  
  err = ts_conn__send_tcp_data(conn, input);
  if (err) {
    return err;
  }
  
done:
  if (use_ws) {
    ts_buf__set_length(conn->ws->out_buf, 0);
  }
  if (use_ssl) {
    ts_buf__set_length(conn->tls->ssl_buf, 0);
  }
  
  ts_buf__set_length(input, 0);
  
  return 0;
}
int ts_conn__close(ts_conn_t* conn, uv_close_cb cb) {
  int err;
  ts_server_listener_t* listener = conn->listener;
  ts_server_t* server = listener->server;
  
  BOOL use_ssl = ts_use_ssl(listener->protocol);
  BOOL use_ws = ts_use_websocket(listener->protocol);
  
  if (use_ws) {
    ts_ws_t* ws = conn->ws;
    ts_buf__set_length(ws->out_buf, 0);
    err = ts_ws__disconnect(ws, ws->out_buf);
    //err = ts_conn__send_data(conn, ws->out_buf);
    // TODO: log the error
  }
  
  if (use_ssl) {
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
