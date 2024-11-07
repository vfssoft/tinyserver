#include "ts_internal.h"


int ts_server__set_callbacks(ts_t* s, ts_callbacks_t* cbs) {
  ts_server_t* server = (ts_server_t*) s;
  memcpy(&(server->callbacks), cbs, sizeof(ts_callbacks_t));
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