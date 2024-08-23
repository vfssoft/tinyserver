
#include "ts_internal.h"


static void uv_on_tcp_conn_close(uv_handle_t* handle) {
  ts_tcp_conn_t* conn = (ts_tcp_conn_t*)handle;
  ts_server_listener_t* listener = conn->listener;
  ts_server_t* server = listener->server;
 
  server->disconnected_cb(server->cb_ctx, server, conn, 0);

  uv_read_stop((uv_stream_t*)&conn->uvtcp);
  
  LOG_DEBUG_EX("[%s] Remove connection from connections collection", conn->remote_addr);
  DL_DELETE(server->conns, conn);
  
  LOG_DEBUG("[%s] Free connection", conn->remote_addr);
  ts_conn__destroy(listener, conn);
  ts__free(conn);
}
static void uv_on_listener_close(uv_handle_t* handle) {
  ts_server_listener_t* listener = CONTAINER_OF(handle, ts_server_listener_t, uvtcp);
  ts_server_t* server = listener->server;
  
  server->listener_count--;
  assert(server->listener_count >= 0);
  LOG_DEBUG("Current listener count: %d", server->listener_count);
  if (server->listener_count == 0) {
    LOG_DEBUG_EX("All listeners are stopped, free listeners");
    ts__free(server->listeners);
    server->listeners = NULL;
  }
  return;
}

static void uv_on_new_tcp_connection(uv_stream_t *stream, int status) {
  int err;
  ts_server_listener_t* listener = CONTAINER_OF(stream, ts_server_listener_t, uvtcp);
  ts_server_t* server = listener->server;
  ts_tcp_conn_t* conn;
  
  if (status < 0) {
    LOG_ERROR("New connection error: %d %s", status, uv_strerror(status));
    return;
  }
  
  conn = (ts_conn_t*) ts__malloc(sizeof(ts_tcp_conn_t));
  if (conn == NULL) {
    LOG_ERROR("New connection error: Out of memory");
    return;
  }
  
  DL_APPEND(server->conns, conn);
  
  err = ts_conn__init(listener, conn);
  if (err) {
    goto done;
  }

  err = uv_accept((uv_stream_t*) &listener->uvtcp, (uv_stream_t*) &conn->uvtcp);
  if (err == 0) {
    err = ts_conn__tcp_connected(conn);
  } else {
    ts_error__set_msg(&conn->err, err, uv_strerror(err));
    goto done;
  }
  
done:
  if (err) {
    LOG_ERROR("Accept new connection failed: %d %s, disconnect it", err, conn->err.msg);
    ts_server__disconnect(server, conn);
  }
}

static void ts_server__default_connected_cb(void* ctx, ts_t* server, ts_conn_t* conn, int status) {}
static void ts_server__default_disconnected_cb(void* ctx, ts_t* server, ts_conn_t* conn, int status) {}
static void ts_server__default_write_cb(void* ctx, ts_t* server, ts_conn_t* conn, int status, int write_more) {}
static void ts_server__default_idle_cb(void* ctx, ts_t* server) {}
static void ts_server__default_read_cb(void* ctx, ts_t* server, ts_conn_t* conn, const char* data, int len) {}

ts_t* ts_server__create() {
  ts_server_t* server = (ts_server_t*) ts__malloc(sizeof(ts_server_t));
  memset(server, 0, sizeof(ts_server_t));
  server->listeners = NULL;
  server->listener_count = 0;
  
  server->connected_cb = ts_server__default_connected_cb;
  server->disconnected_cb = ts_server__default_disconnected_cb;
  server->read_cb = ts_server__default_read_cb;
  server->write_cb = ts_server__default_write_cb;
  server->idle_cb = ts_server__default_idle_cb;
  server->cb_ctx = NULL;
  
  server->conns = NULL;
  ts_error__init(&server->err);

  ts_log__init(&server->log);
  
  server->uvloop = uv_default_loop();

  ts_server_idle__init(server);
  
  return server;
}
int ts_server__destroy(ts_t* s) {
  ts_server_t* server = (ts_server_t*) s;
  ts_log__destroy(&server->log);
  return 0; // TODO
}

int ts_server__start(ts_t* s) {
  int err;
  ts_server_t* server = (ts_server_t*) s;
  ts_server_listener_t* listener;
  
  LOG_INFO("Start server");
  
  for (int i = 0; i < server->listener_count; i++) {
    listener = &(server->listeners[i]);
    err = ts_server_listener__start(listener, server, uv_on_new_tcp_connection);
    if (err) {
      ts_error__copy(&server->err, &listener->err);
      goto done;
    }
  }
  
  err = ts_server_idle__start(server);
  if (err) {
    goto done;
  }
  
done:
  if (err == 0) {
    LOG_INFO("Server started");
  } else {
    LOG_ERROR("Server started failed: %d %s", server->err.err, server->err.msg);
  }
  
  return err;
}
int ts_server__run(ts_t* s) {
  ts_server_t* server = (ts_server_t*) s;
  return uv_run(server->uvloop, UV_RUN_NOWAIT);
}
int ts_server__stop(ts_t* s) {
  int err = 0;
  ts_server_t* server = (ts_server_t*) s;
  
  LOG_INFO("Stop server");
  ts_server_idle__stop(server);
  
  // TODO: add a stop flag to stop accepting new connections
  int conn_count = 0;
  ts_tcp_conn_t* cur_conn = NULL;
  DL_COUNT(server->conns, cur_conn, conn_count);
  LOG_DEBUG("Close all connections: %d", conn_count);

  DL_FOREACH(server->conns, cur_conn) {
    ts_server__disconnect(server, cur_conn);
  }
  // wait for all conns are closed
  while (server->conns != NULL) {
    uv_run(server->uvloop, UV_RUN_NOWAIT);
  }
  
  LOG_DEBUG("Stop all listeners: %d", server->listener_count);
  for (int i = 0; i < server->listener_count; i++) {
    ts_server_listener__stop(&(server->listeners[i]), uv_on_listener_close);
  }
  while (server->listeners != NULL) {
    uv_run(server->uvloop, UV_RUN_NOWAIT);
  }
  
  // Run uv_run as least once so that the uv_idle_t handle will be closed.
  // The above uv_run are guarded with if statements, it may not be run.
  uv_run(server->uvloop, UV_RUN_NOWAIT);
  
  err = uv_loop_close(server->uvloop);
  server->uvloop = NULL;
  if (err) {
    ts_error__set_msg(&(server->err), err, uv_strerror(err));
  }
  
done:
  if (err == 0) {
    LOG_INFO("Server stopped");
  } else {
    LOG_ERROR("Server stopped failed: %d %s", server->err.err, server->err.msg);
  }

  return err;
}
int ts_server__write(ts_t* s, ts_conn_t* conn, const char* data, int len) {
  int err;
  ts_server_t* server = (ts_server_t*) s;
  ts_buf_t* buf = ts_buf__create(0);
  ts_buf__set(buf, data, len);

  err = ts_conn__send_data(conn, buf);

  ts_buf__destroy(buf);
  return err;
}
int ts_server__disconnect(ts_t* s, ts_conn_t* c) {
  int err;
  ts_server_t* server = (ts_server_t*) s;
  ts_tcp_conn_t* conn = (ts_tcp_conn_t*) c;
  LOG_VERB("[%s] Disconnect from the peer(user initiated)", conn->remote_addr);
  err = ts_conn__close(conn, uv_on_tcp_conn_close);
  return err;
}
void* ts_server__get_conn_user_data(ts_t* s, ts_conn_t* c) {
  //ts_server_t* server = (ts_server_t*) s;
  ts_tcp_conn_t* conn = (ts_tcp_conn_t*) c;
  return conn->user_data;
}
void ts_server__set_conn_user_data(ts_t* s, ts_conn_t* c, void* user_data) {
  //ts_server_t* server = (ts_server_t*) s;
  ts_tcp_conn_t* conn = (ts_tcp_conn_t*) c;
  conn->user_data = user_data;
}
const char* ts_server__get_conn_remote_host(ts_t* s, ts_conn_t* c) {
  //ts_server_t* server = (ts_server_t*) s;
  ts_tcp_conn_t* conn = (ts_tcp_conn_t*) c;
  return conn->remote_addr;
}
int ts_server__has_pending_write_reqs(ts_t* server, ts_conn_t* c) {
  //ts_server_t* server = (ts_server_t*) s;
  ts_tcp_conn_t* conn = (ts_tcp_conn_t*) c;
  return ts_conn__has_pending_write_reqs(conn);
}
int ts_server__get_error(ts_t* s) {
  ts_server_t* server = (ts_server_t*) s;
  return server->err.err;
}
const char* ts_server__get_error_msg(ts_t* s) {
  ts_server_t* server = (ts_server_t*) s;
  return server->err.msg;
}

ts_log_t* ts_server__get_log(ts_t* s) {
  ts_server_t* server = (ts_server_t*) s;
  return &(server->log);
}

unsigned long long ts_server__now(ts_t* s) {
  ts_server_t* server = (ts_server_t*) s;
  return uv_now(server->uvloop);
}

