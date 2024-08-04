#include "ts_internal.h"

static void uv_on_idle(uv_idle_t *handle) {
  ts_server_t* server = CONTAINER_OF(handle, ts_server_t, uvidle);
  server->idle_cb(server->cb_ctx, server);
}

int ts_server_idle__init(ts_server_t* server) {
  int err;
  server->uvidle = (uv_idle_t*) ts__malloc(sizeof(uv_idle_t));
  if (server->uvidle == NULL) {
    ts_error__set(&(server->err), TS_ERR_OUT_OF_MEMORY);
    return server->err.err;
  }
  memset(server->uvidle, 0, sizeof(uv_idle_t));
  err = uv_idle_init(server->uvloop, server->uvidle);
  return err;
}

int ts_server_idle__start(ts_server_t* server) {
  int err;
  err = uv_idle_start(server->uvidle, uv_on_idle);
  return err;
}

int ts_server_idle__stop(ts_server_t* server) {
  int err = 0;
  if (server->uvidle != NULL) {
    err = uv_idle_stop(server->uvidle);
    ts__free(server->uvidle);
    server->uvidle = NULL;
  }
  return err;
}