
#include "ts_internal.h"

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

static void uv_on_tcp_conn_close(uv_handle_t* handle) {
  ts_conn_t* conn = (ts_conn_t*)handle;
  ts_server_listener_t* listener = conn->listener;
  ts_server_t* server = listener->server;
 
  server->disconnected_cb(server->cb_ctx, server, conn, 0);

  uv_read_stop((uv_stream_t*)&conn->uvtcp);
  
  DL_DELETE(server->conns, conn);
  ts_conn__destroy(listener, conn);
  ts__free(conn);
}
static void uv_on_listener_close(uv_handle_t* handle) {
  ts_server_listener_t* listener = (ts_server_listener_t*)handle;
  ts_server_t* server = listener->server;
  
  server->listener_count--;
  assert(server->listener_count >= 0);
  if (server->listener_count == 0) {
    ts__free(server->listeners);
    server->listeners = NULL;
  }
  return;
}

static void uv_on_write(uv_write_t *req, int status) {
  ts_conn_write_req_t* wr = (ts_conn_write_req_t*) req;
  ts_conn_t* conn = wr->conn;
  ts_server_t* server = conn->listener->server;
  ts_conn__destroy_write_req(conn, wr);
  
  int write_more = !ts_conn__has_pending_write_req(conn);
  server->write_cb(server->cb_ctx, server, conn, status, write_more);
}

static int ts_server__send_tcp_data(ts_conn_t* conn, ts_buf_t* output) {
  int err;
  ts_conn_write_req_t* write_req;
  
  if (output->len > 0) {
    write_req = ts_conn__create_write_req(conn, output->buf, output->len);
    if (write_req == NULL) {
      return TS_ERR_OUT_OF_MEMORY;
    }
  
    err = uv_write((uv_write_t*)write_req, (uv_stream_t*)&conn->uvtcp, &write_req->buf, 1, uv_on_write);
    if (err) {
      return err;
    }
  
    ts_buf__set_length(output, 0); // reset the buf for reuse
  }
  
  return 0;
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
  
      err = ts_server__send_tcp_data(conn, tls->ssl_buf);
      if (err) {
        goto done;
      }
      
    } else {
      err = ts_tls__decrypt(tls, input, tls->ssl_buf);
      if (err) {
        goto done;
      }
      *decrypted = tls->ssl_buf;
    }
    
  }
  
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
    
    server->read_cb(server->cb_ctx, server, conn, input.buf, input.len);
    
  }
  
  if (nread < 0) {
    ts_server__disconnect(server, conn);
  }
  
  uv_on_free_buffer(buf);
  
done:
  return;
}
static void uv_on_new_tcp_connection(uv_stream_t *stream, int status) {
  if (status < 0) {
    return;
  }
  
  int err;
  ts_server_listener_t* listener = (ts_server_listener_t*) stream;
  ts_server_t* server = listener->server;
  ts_conn_t* conn = (ts_conn_t*) ts__malloc(sizeof(ts_conn_t));
  if (conn == NULL) {
    return;
  }
  
  DL_APPEND(server->conns, conn);
  
  err = ts_conn__init(listener, conn);
  if (err) {
    goto done;
  }

  err = uv_accept((uv_stream_t*) &listener->uvtcp, (uv_stream_t*) &conn->uvtcp);
  if (err == 0) {
    if (listener->protocol == TS_PROTO_TCP) {
      err = server->connected_cb(server->cb_ctx, server, conn, 0);
    }

    err = uv_read_start((uv_stream_t*) &conn->uvtcp, uv_on_alloc_buffer, uv_on_read);
  }

  if (err) {
    ts_server__disconnect(server, conn);
  }
  
done:
  return;
}
static void uv_on_idle(uv_idle_t *handle) {
  ts_server_t* server = CONTAINER_OF(handle, ts_server_t, uvidle);
  server->idle_cb(server->cb_ctx, server);
}

static int ts_server__default_connected_cb(void* ctx, ts_server_t* server, ts_conn_t* conn, int status) {
  return 0;
}
static int ts_server__default_disconnected_cb(void* ctx, ts_server_t* server, ts_conn_t* conn, int status) {
  return 0;
}
static int ts_server__default_write_cb(void* ctx, ts_server_t* server, ts_conn_t* conn, int status, int write_more) {
  return 0;
}
static int ts_server__default_idle_cb(void* ctx, ts_server_t* server) {
  return 0;
}


int ts_server__init(ts_server_t* server) {
  server->listeners = NULL;
  server->listener_count = 0;
  
  server->connected_cb = ts_server__default_connected_cb;
  server->disconnected_cb = ts_server__default_disconnected_cb;
  server->read_cb = NULL;
  server->write_cb = ts_server__default_write_cb;
  server->idle_cb = ts_server__default_idle_cb;
  server->cb_ctx = NULL;
  
  server->conns = NULL;
  ts_error__init(&server->err);

  ts_log__init(&server->log);
  
  server->uvloop = uv_default_loop();
  uv_idle_init(server->uvloop, &server->uvidle);
  
  return 0;
}
int ts_server__destroy(ts_server_t server) {
  ts_log__destroy(&server.log);
  return 0; // TODO
}

int ts_server__start(ts_server_t* server) {
  int err;
  ts_server_listener_t* listener;
  
  for (int i = 0; i < server->listener_count; i++) {
    err = ts_server_listener__init(&server->listeners[i], server);
    if (err) {
      goto done;
    }
  }
  
  for (int i = 0; i < server->listener_count; i++) {
    listener = &server->listeners[i];
    // TODO:
    err = uv_listen((uv_stream_t*)&(listener->uvtcp), listener->backlog, uv_on_new_tcp_connection);
    if (err) {
      return err;
    }
  }
  
  uv_idle_start(&(server->uvidle), uv_on_idle);
  
done:
  return err;
}
int ts_server__run(ts_server_t* server) {
  return uv_run(server->uvloop, UV_RUN_NOWAIT);
}
int ts_server__stop(ts_server_t* server) {
  uv_idle_stop(&server->uvidle);
  
  // TODO: add a stop flag to stop accepting new connections
  ts_conn_t* cur_conn = NULL;
  DL_FOREACH(server->conns, cur_conn) {
    ts_server__disconnect(server, cur_conn);
  }
  // wait for all conns are closed
  while (server->conns != NULL) {
    uv_run(server->uvloop, UV_RUN_NOWAIT);
  }
  
  for (int i = 0; i < server->listener_count; i++) {
    uv_close((uv_handle_t*)&server->listeners[i].uvtcp, uv_on_listener_close);
  }
  
  while (uv_run(server->uvloop, UV_RUN_NOWAIT) != 0) {}
  
  return 0;
}
int ts_server__write(ts_server_t* server, ts_conn_t* conn, const char* data, int len) {
  int err;
  ts_buf_t* buf = ts_buf__create(0);
  ts_buf__set_const(buf, data,len);

  err = ts_server__send_tcp_data(conn, buf);

  ts_buf__destroy(buf);
  return err;
}
int ts_server__disconnect(ts_server_t* server, ts_conn_t* conn) {
  uv_handle_t* h = (uv_handle_t*)&conn->uvtcp;
  if (h && !uv_is_closing(h)) {
    uv_close(h, uv_on_tcp_conn_close);
  }
  return 0;
}


