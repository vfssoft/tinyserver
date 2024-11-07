#include "ts_internal.h"

static void uv_on_idle(uv_idle_t *handle) {
  ts_server_t* server = CONTAINER_OF(handle, ts_server_t, uvidle);
  ts_server__internal_idle_cb(server);
}

int ts_server_idle__init(ts_server_t* server) {
  int err;
  memset(&(server->uvidle), 0, sizeof(uv_idle_t));
  err = uv_idle_init(server->uvloop, &(server->uvidle));
  if (err) {
    ts_error__set_msg(&(server->err), err, uv_strerror(err));
  }
  return err;
}

int ts_server_idle__start(ts_server_t* server) {
  int err;
  err = uv_idle_start(&(server->uvidle), uv_on_idle);
  if (err) {
    ts_error__set_msg(&(server->err), err, uv_strerror(err));
  }
  return err;
}

int ts_server_idle__stop(ts_server_t* server) {
  int err;
  err = uv_idle_stop(&server->uvidle);
  if (err) {
    ts_error__set_msg(&(server->err), err, uv_strerror(err));
    goto done;
  }
done:
  uv_close((uv_handle_t*)&(server->uvidle), NULL);
  return err;
}