#include "ts_internal.h"

int ts_server_log_set_log_level(ts_server_t* server, int log_level) {
  server->log.log_level = log_level;
  return 0;
}
int ts_server_log_set_log_dest(ts_server_t* server, int dest) {
  server->log.log_dest = dest;
  return 0;
}
int ts_server_log_set_log_dir(ts_server_t* server, const char* dir) {
  server->log.log_dir = ts__strdup(dir);
  return 0;
}
int ts_server_log_set_log_cb(ts_server_t* server, void* ctx, ts_log_cb cb) {
  server->log.log_ctx = ctx;
  server->log.log_cb = cb;
  return 0;
}