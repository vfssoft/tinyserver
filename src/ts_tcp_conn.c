
#include "ts_internal.h"

int ts_conn__init(ts_server_listener_t* listener, ts_tcp_conn_t* conn) {
  int err = 0;
  ts_server_t* server = listener->server;
  BOOL use_ssl = ts_use_ssl(listener->protocol);
  BOOL use_ws = ts_use_websocket(listener->protocol);
  
  conn->listener = listener;
  conn->write_reqs = NULL;
  conn->tls = NULL;
  conn->tls_buf = NULL;
  conn->ws = NULL;
  conn->ws_buf = NULL;
  memset(&(conn->uvtcp), 0, sizeof(uv_tcp_t));
  ts_error__init(&conn->err);

  memset(conn->local_addr, 0, sizeof(conn->local_addr));
  memset(conn->remote_addr, 0, sizeof(conn->remote_addr));

  conn->user_data = NULL;
  conn->timer = NULL; // by default, the timer is disabled

  if (use_ssl) {
    conn->tls_buf = ts_buf__create(0);
    if (conn->tls_buf == NULL) {
      ts_error__set(&(conn->err), TS_ERR_OUT_OF_MEMORY);
      goto done;
    }

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
    conn->ws_buf = ts_buf__create(0);
    if (conn->ws_buf == NULL) {
      ts_error__set(&(conn->err), TS_ERR_OUT_OF_MEMORY);
      goto done;
    }

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

int ts_conn__destroy(ts_server_listener_t* listener, ts_tcp_conn_t* conn) {
  if (conn->tls) {
    ts_tls__destroy(conn->tls);
    ts__free(conn->tls);
    conn->tls = NULL;
  }
  if (conn->tls_buf) {
    ts_buf__destroy(conn->tls_buf);
    conn->tls_buf = NULL;
  }
  if (conn->ws) {
    ts_ws__destroy(conn->ws);
    ts__free(conn->ws);
    conn->ws = NULL;
  }
  if (conn->ws_buf) {
    ts_buf__destroy(conn->ws_buf);
    conn->ws_buf = NULL;
  }
  
  ts_conn__stop_timer(conn);
  conn->listener = NULL;
  return 0;
}

static int ts_conn__init_write_req(ts_conn_write_req_t* req, ts_tcp_conn_t* conn, char* data, int len) {
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
static void ts_conn__destroy_write_req(ts_tcp_conn_t* conn, ts_conn_write_req_t* req) {
  DL_DELETE(conn->write_reqs, req);
  
  ts__free(req->buf.base);
  ts__free(req);
}

static void uv_on_write(uv_write_t *req, int status) {
  ts_conn_write_req_t* wr = (ts_conn_write_req_t*) req;
  ts_tcp_conn_t* conn = wr->conn;
  ts_server_t* server = conn->listener->server;
  ts_conn__destroy_write_req(conn, wr);
  
  int has_pending_write_reqs = ts_conn__has_pending_write_reqs(conn);
  ts_server__internal_write_cb(server, conn, status, !has_pending_write_reqs);
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

static int ts_conn__send_tcp_data(ts_tcp_conn_t* conn, ts_buf_t* output) {
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
static int ts_conn__send_tls_data(ts_tcp_conn_t* conn, ts_buf_t* plain) {
  int err;
  ts_ro_buf_t roinput = {
      .buf = plain->buf,
      .len = plain->len
  };
  ts_buf__set_length(conn->tls_buf, 0);

  err = ts_tls__encrypt(conn->tls, &roinput, conn->tls_buf);
  if (err) {
    ts_error__copy(&(conn->err), &(conn->tls->err));
    goto done;
  }

  err = ts_conn__send_tcp_data(conn, conn->tls_buf);
done:
  ts_buf__set_length(plain, 0);
  return err;
}
static int ts_conn__send_websocket_data(ts_tcp_conn_t* conn, ts_buf_t* plain) {
  int err;
  ts_ro_buf_t roinput = {
      .buf = plain->buf,
      .len = plain->len
  };
  ts_buf__set_length(conn->ws_buf, 0);

  err = ts_ws__wrap(conn->ws, &roinput, conn->ws_buf);
  if (err) {
    ts_error__copy(&(conn->err), &(conn->ws->err));
    return err;
  }

  if (ts_use_ssl(conn->listener->protocol)) {
    return ts_conn__send_tls_data(conn, conn->ws_buf);
  } else {
    return ts_conn__send_tcp_data(conn, conn->ws_buf);
  }
}

static int ts_conn__process_ssl_socket_data(ts_tcp_conn_t* conn, ts_ro_buf_t* input, ts_ro_buf_t* output) {
  int err = 0;
  int old_state;
  ts_server_listener_t* listener = conn->listener;
  ts_server_t* server = listener->server;
  ts_tls_t* tls = conn->tls;

  old_state = ts_tls__state(tls);

  assert(old_state == TS_STATE_HANDSHAKING || old_state == TS_STATE_CONNECTED);
  ts_buf__set_length(conn->tls_buf, 0);

  while (input->len > 0) { // we have to consume all input data here

    if (ts_tls__state(tls) == TS_STATE_HANDSHAKING) {
      err = ts_tls__handshake(tls, input, conn->tls_buf);
      if (err) {
        ts_error__copy(&(conn->err), &(tls->err));
        goto done;
      }

      err = ts_conn__send_tcp_data(conn, conn->tls_buf);
      if (err) {
        goto done;
      }

    }

    if (ts_tls__state(tls) != TS_STATE_HANDSHAKING) {
      err = ts_tls__decrypt(tls, input, conn->tls_buf);
      if (err) {
        goto done;
      }
    }

  }

  switch (ts_tls__state(tls)) {
    case TS_STATE_HANDSHAKING:
      // After processing the input data, we're still in TLS handshaking state
      goto done; // handshake is not done, nothing can be done, wait for more tcp data

    case TS_STATE_CONNECTED:
      if (old_state == TS_STATE_HANDSHAKING) {
        // tls handshake is done
        if (!ts_use_websocket(listener->protocol)) {
          ts_server__internal_connected_cb(server, conn, 0);
        }
      }
      break;

    case TS_STATE_DISCONNECTING:
    case TS_STATE_DISCONNECTED:
      // TODO: error happen
      break;
  }

  output->buf = conn->tls_buf->buf;
  output->len = conn->tls_buf->len;

done:
  if (err) {
    LOG_ERROR("[%s] TLS error: %d %s", conn->remote_addr, conn->err.err, conn->err.msg);
  }
  return err;
}

static int ts_conn__process_ws_socket_data(ts_tcp_conn_t* conn, ts_ro_buf_t* input, ts_ro_buf_t* output) {
  int err = 0;
  int old_state;
  ts_server_t* server = conn->listener->server;
  ts_ws_t* ws = conn->ws;
  ts_buf_t* output_sock = NULL;

  old_state = ts_ws__state(ws);
  assert(old_state == TS_STATE_HANDSHAKING || old_state == TS_STATE_CONNECTED);
  ts_buf__set_length(conn->ws_buf, 0);

  output_sock = ts_buf__create(0);
  if (output_sock == NULL) {
    ts_error__set(&(conn->err), TS_ERR_OUT_OF_MEMORY);
    goto done;
  }

  while (input->len > 0) { // we have to consume all input data here

    if (ts_ws__state(ws) == TS_STATE_HANDSHAKING) {
      err = ts_ws__handshake(ws, input, conn->ws_buf);
      if (err) {
        ts_error__copy(&(conn->err), &(ws->err));
        goto done;
      }

      if (ts_use_ssl(conn->listener->protocol)) {
        err = ts_conn__send_tls_data(conn, conn->ws_buf);
      } else {
        err = ts_conn__send_tcp_data(conn, conn->ws_buf);
      }
      if (err) {
        goto done;
      }
    } else {
      err = ts_ws__unwrap(ws, input, conn->ws_buf, output_sock);
      if (err) {
        goto done;
      }
      if (output_sock->len > 0) {
        if (ts_use_ssl(conn->listener->protocol)) {
          err = ts_conn__send_tls_data(conn, output_sock);
        } else {
          err = ts_conn__send_tcp_data(conn, output_sock);
        }
      }
    }

  }

  switch (ts_ws__state(ws)) {
    case TS_STATE_HANDSHAKING:
      // After processing the input data, we're still in Websocket handshaking state
      goto done; // handshake is not done, nothing can be done, wait for more data

    case TS_STATE_CONNECTED:
      if (old_state == TS_STATE_HANDSHAKING) {
        // websocket handshake is done
        ts_server__internal_connected_cb(server, conn, 0);
      }
      break;

    case TS_STATE_DISCONNECTING:
    case TS_STATE_DISCONNECTED:
      // TODO: error happen
      break;
  }

  output->buf = conn->ws_buf->buf;
  output->len = conn->ws_buf->len;

done:
  if (err) {
    LOG_ERROR("[%s] Websocket error: %d %s", conn->remote_addr, conn->err.err, conn->err.msg);
  }
  if (output_sock) {
    ts_buf__destroy(output_sock);
  }
  return err;
}

static void uv_on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
  int err = 0;
  ts_tcp_conn_t* conn = (ts_tcp_conn_t*) stream;
  ts_server_listener_t* listener = conn->listener;
  ts_server_t* server = listener->server;
  ts_buf_t* ws_unwrapped = NULL;
  ts_ro_buf_t input;
  int ws_state = 0;
  
  LOG_DEBUG("[%s] Data received: %d", conn->remote_addr, nread);

  input.buf = buf->base;
  input.len = (int)nread;

  // nread can be zero
  if (nread > 0) {

    if (conn->tls) {
      err = ts_conn__process_ssl_socket_data(conn, &input, &input);
      if (err) {
        goto done;
      }
      if (input.len == 0) {
        goto done;
      }
    }
    
    if (conn->ws) {
      err = ts_conn__process_ws_socket_data(conn, &input, &input);
      if (err) {
        goto done;
      }
      if (input.len == 0) {
        goto done;
      }
    }
    
    if (input.len > 0) {
      ts_server__internal_read_cb(server, conn, input.buf, input.len);
    }
  }

  if (nread < 0) {
    LOG_ERROR("[%s] Connection error: %d %s", conn->remote_addr, nread, uv_strerror(nread));
    err = nread;
  }

done:
  
  if (err) {
    ts_server__disconnect(server, conn);
  }

  uv_on_free_buffer(buf);

  return;
}

static int ts_conn__populate_addrs(ts_tcp_conn_t* conn) {
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

static int ts_conn__read_tcp_data(ts_tcp_conn_t* conn, uv_read_cb cb) {
  int err;
  err = uv_read_start((uv_stream_t*) &conn->uvtcp, uv_on_alloc_buffer, cb);
  if (err) {
    ts_error__set_msg(&conn->err, err, uv_strerror(err));
  }
  return err;
}
int ts_conn__tcp_connected(ts_tcp_conn_t* conn) {
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
    ts_server__internal_connected_cb(server, conn, 0);
  }
  
  return 0;
}
int ts_conn__send_data(ts_tcp_conn_t* conn, ts_buf_t* input) {
  int err;
  ts_server_listener_t* listener = conn->listener;
  ts_server_t* server = listener->server;

  if (ts_use_websocket(conn->listener->protocol)) {
    err = ts_conn__send_websocket_data(conn, input);
  } else if (ts_use_ssl(conn->listener->protocol)) {
    err = ts_conn__send_tls_data(conn, input);
  } else {
    err = ts_conn__send_tcp_data(conn, input);
  }

done:
  if (err == 0) {
    ts_buf__set_length(input, 0);
  }
  
  return err;
}
int ts_conn__close(ts_tcp_conn_t* conn, uv_close_cb cb) {
  int err;
  ts_server_listener_t* listener = conn->listener;
  ts_server_t* server = listener->server;
  
  BOOL use_ssl = ts_use_ssl(listener->protocol);
  BOOL use_ws = ts_use_websocket(listener->protocol);

  if (use_ws) {
    ts_buf__set_length(conn->ws_buf, 0);
    err = ts_ws__disconnect(conn->ws, conn->ws_buf);
    if (use_ssl) {
      err = ts_conn__send_tls_data(conn, conn->ws_buf);
    } else {
      err = ts_conn__send_tcp_data(conn, conn->ws_buf);
    }
    // TODO: log the error
  } else if (use_ssl) {
    ts_buf__set_length(conn->tls_buf, 0);
    err = ts_tls__disconnect(conn->tls, conn->tls_buf);
    err = ts_conn__send_tcp_data(conn, conn->tls_buf);
    // TODO: log the error
  }

  uv_handle_t* h = (uv_handle_t*)&conn->uvtcp;
  if (h && !uv_is_closing(h)) {
    uv_close(h, cb);
  }
  return 0;
}

int ts_conn__has_pending_write_reqs(ts_tcp_conn_t* conn) {
  return conn->write_reqs != NULL;
}


static void uv_on_timer_cb(uv_timer_t* timer) {
  ts_tcp_conn_t* conn = (ts_tcp_conn_t*) timer->data;
  ts_server__internal_timer_cb(conn->listener->server, conn);
}
static void uv_on_timer_close_cb(uv_handle_t* timer) {
  //ts_tcp_conn_t* conn = (ts_tcp_conn_t*) timer->data;
  //ts__free(conn->timer);
  //conn->timer = NULL;
  ts__free(timer);
}
int ts_conn__start_timer(ts_tcp_conn_t* conn, int timeoutMS, int repeatMS) {
  int err;
  
  conn->timer = (uv_timer_t*) ts__malloc(sizeof(uv_timer_t));
  if (conn->timer == NULL) {
    ts_error__set(&conn->err, TS_ERR_OUT_OF_MEMORY);
    return TS_ERR_OUT_OF_MEMORY;
  }
  conn->timer->data = conn; // attach the conn to timer
  
  err = uv_timer_init(conn->listener->uvloop, conn->timer);
  if (err) {
    ts_error__set_msg(&conn->err, err, uv_strerror(err));
    return err;
  }
  err = uv_timer_start(conn->timer, uv_on_timer_cb, timeoutMS, repeatMS);
  if (err) {
    ts_error__set_msg(&conn->err, err, uv_strerror(err));
    return err;
  }
  
  return 0;
}
int ts_conn__stop_timer(ts_tcp_conn_t* conn) {
  if (conn->timer && !uv_is_closing(conn->timer)) {
    uv_timer_stop(conn->timer);
    uv_close((uv_handle_t*)conn->timer, uv_on_timer_close_cb);
  }
  return 0;
}