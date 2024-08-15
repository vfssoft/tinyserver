#include "ts_internal.h"


int ts_server__set_cb_ctx(ts_t* s, void* ctx) {
  ts_server_t* server = (ts_server_t*) s;
  server->cb_ctx = ctx;
  return 0;
}
int ts_server__set_connected_cb(ts_t* s, ts_server_connected_cb cb) {
  ts_server_t* server = (ts_server_t*) s;
  server->connected_cb = cb;
  return 0;
}
int ts_server__set_disconnected_cb(ts_t* s, ts_server_disconnected_cb cb) {
  ts_server_t* server = (ts_server_t*) s;
  server->disconnected_cb = cb;
  return 0;
}
int ts_server__set_read_cb(ts_t* s, ts_server_read_cb cb) {
  ts_server_t* server = (ts_server_t*) s;
  server->read_cb = cb;
  return 0;
}
int ts_server__set_write_cb(ts_t* s, ts_server_write_cb cb) {
  ts_server_t* server = (ts_server_t*) s;
  server->write_cb = cb;
  return 0;
}
int ts_server__set_idle_cb(ts_t* s, ts_server_idle_cb cb) {
  ts_server_t* server = (ts_server_t*) s;
  server->idle_cb = cb;
  return 0;
}
int ts_server__set_listener_count(ts_t* s, int cnt) {
  ts_server_t* server = (ts_server_t*) s;
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
    ts_server_listener__init_default(&server->listeners[i]);
  }

  return 0;
}
int ts_server__set_listener_host_port(ts_t* s, int idx, const char* host, int port){
  ts_server_t* server = (ts_server_t*) s;
  ts_server_listener_t* l = &server->listeners[idx];
  l->host = ts__strdup(host);
  l->port = port;
  return 0;
}
int ts_server__set_listener_use_ipv6(ts_t* s, int idx, int use) {
  ts_server_t* server = (ts_server_t*) s;
  server->listeners[idx].use_ipv6 = use;
  return 0;
}
int ts_server__set_listener_protocol(ts_t* s, int idx, int proto) {
  ts_server_t* server = (ts_server_t*) s;
  server->listeners[idx].protocol = proto;
  return 0;
}
int ts_server__set_listener_certs(ts_t* s, int idx, const char* cert, const char* key) {
  ts_server_t* server = (ts_server_t*) s;
  server->listeners[idx].cert = ts__strdup(cert);
  server->listeners[idx].key  = ts__strdup(key);
  return 0;
}


int ts_server_log_set_log_level(ts_t* s, int log_level) {
  ts_server_t* server = (ts_server_t*) s;
  server->log.log_level = log_level;
  return 0;
}
int ts_server_log_set_log_dest(ts_t* s, int dest) {
  ts_server_t* server = (ts_server_t*) s;
  server->log.log_dest = dest;
  return 0;
}
int ts_server_log_set_log_dir(ts_t* s, const char* dir) {
  ts_server_t* server = (ts_server_t*) s;
  server->log.log_dir = ts__strdup(dir);
  return 0;
}
int ts_server_log_set_log_cb(ts_t* s, void* ctx, ts_log_cb cb) {
  ts_server_t* server = (ts_server_t*) s;
  server->log.log_ctx = ctx;
  server->log.log_cb = cb;
  return 0;
}