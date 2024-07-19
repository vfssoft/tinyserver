
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

void ts_server__set_errmsg(ts_server_t* server, const char* msg) {
  if (server->err_msg) {
    ts__free(server->err_msg);
  }
  if (msg == NULL || strlen(msg) == 0) {
    server->err_msg = NULL;
  } else {
    server->err_msg = ts__strdup(msg);
  }
}
void ts_server__set_errmsg_f(ts_server_t* server, const char* format, ...) {
  char buf[256];
  va_list args;
  va_start(args, format);
  snprintf(buf, sizeof(buf), format, args);
  va_end(args);
  
  ts_server__set_errmsg(server, buf);
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
  server->err_msg = NULL;

  ts_log__init(&server->log);
  
  server->uvloop = uv_default_loop();
  uv_idle_init(server->uvloop, &server->uvidle);
  
  return 0;
}

int ts_server__destroy(ts_server_t server) {
  ts_log__destroy(&server.log);
  return 0; // TODO
}

int ts_server__set_cb_ctx(ts_server_t* server, void* ctx) {
  server->cb_ctx = ctx;
  return 0;
}
int ts_server__set_connected_cb(ts_server_t* server, ts_server_connected_cb cb) {
  server->connected_cb = cb;
  return 0;
}
int ts_server__set_disconnected_cb(ts_server_t* server, ts_server_disconnected_cb cb) {
  server->disconnected_cb = cb;
  return 0;
}
int ts_server__set_read_cb(ts_server_t* server, ts_server_read_cb cb) {
  server->read_cb = cb;
  return 0;
}
int ts_server__set_write_cb(ts_server_t* server, ts_server_write_cb cb) {
  server->write_cb = cb;
  return 0;
}
int ts_server__set_idle_cb(ts_server_t* server, ts_server_idle_cb cb) {
  server->idle_cb = cb;
  return 0;
}
int ts_server__set_listener_count(ts_server_t* server, int cnt) {
  if (server->listener_count > 0) {
    ts__free(server->listeners);
  }

  server->listener_count = cnt;
  server->listeners = NULL;
  if (cnt > 0) {
    server->listeners = (ts_server_listener_t*) ts__malloc(sizeof(ts_server_listener_t) * cnt);
    if (server->listeners == NULL) {
      return TS_ERR_OUT_OF_MEMORY;
    }
  }

  for (int i = 0; i < cnt; i++) {
    ts_server_listener_t* l = &server->listeners[i];
    l->host = "0.0.0.0";
    l->port = 0;
    l->use_ipv6 = 0;
    l->backlog = TS_DEFAULT_BACKLOG;
    l->protocol = TS_PROTO_TCP;
    l->cert = "";
    l->key = "";
    l->tls_verify_mode = 0;
  }

  return 0;
}
int ts_server__set_listener_host_port(ts_server_t* server, int idx, const char* host, int port){
  ts_server_listener_t* l = &server->listeners[idx];
  l->host = ts__strdup(host);
  l->port = port;
  return 0;
}
int ts_server__set_listener_use_ipv6(ts_server_t* server, int idx, int use) {
  server->listeners[idx].use_ipv6 = use;
  return 0;
}
int ts_server__set_listener_protocol(ts_server_t* server, int idx, int proto) {
  server->listeners[idx].protocol = proto;
  return 0;
}

static int ts_server__listener_bind(ts_server_listener_t* listener) {
  int err;

  struct sockaddr addr = { 0 };
  struct sockaddr_in* in4 = (struct sockaddr_in*)&addr;
  struct sockaddr_in6* in6 = (struct sockaddr_in6*)&addr;

  int use_ipv6 = listener->use_ipv6;
  const char* host = listener->host;
  int port = listener->port;

  if (use_ipv6) {
    in6->sin6_family = AF_INET6;
    err = uv_inet_pton(AF_INET6, host, &in6->sin6_addr);
  } else {
    in4->sin_family = AF_INET;
    err = uv_inet_pton(AF_INET, host, &in4->sin_addr);
  }
  if (err) {
    ts_server__set_errmsg(listener->server, "invalid host");
  }

  if (err) {
    if (ts_tcp__getaddrinfo(host, use_ipv6, &addr) == 0) {
      err = 0;
      ts_server__set_errmsg(listener->server, NULL);
    }
  }

  if (err) {
    return err;
  }

  if (use_ipv6) {
    in6->sin6_port = htons(port);
  } else {
    in4->sin_port = htons(port);
  }

  err = uv_tcp_bind(&listener->uvtcp, &addr, 0);
  if (err) {
    ts_server__set_errmsg(listener->server, uv_strerror(err));
  }
  return err;
}
static int ts_server__listener_init(ts_server_t* server, int listener_index) {
  int err;
  ts_server_listener_t* listener = &(server->listeners[listener_index]);

  listener->server = server;
  listener->uvloop = server->uvloop;

  err = uv_tcp_init(listener->uvloop, &listener->uvtcp);
  if (err) {
    return err;
  }

  err = ts_server__listener_bind(listener);
  if (err) {
    return err;
  }

  return 0;
}

int ts_server__start(ts_server_t* server) {
  int err;
  ts_server_listener_t* listener;
  
  for (int i = 0; i < server->listener_count; i++) {
    err = ts_server__listener_init(server, i);
    if (err) {
      goto done;
    }
  }
  
  for (int i = 0; i < server->listener_count; i++) {
    listener = &server->listeners[i];
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


