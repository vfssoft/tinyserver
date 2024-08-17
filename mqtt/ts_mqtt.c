
#include "ts_mqtt.h"

#include <internal/ts_mem.h>

static void tm__copy_server_err(tm_server_t* tm, ts_t* ts) {
  ts_error__set_msg(
      &(tm->err),
      ts_server__get_error(ts),
      ts_server__get_error_msg(ts)
  );
}

tm_t* tm__create() {
  tm_server_t* s = (tm_server_t*) ts__malloc(sizeof(tm_server_t));
  memset(s, 0, sizeof(tm_server_t));
  
  s->server = ts_server__create();
  if (s->server) {
    return NULL;
  }
  
  ts_error__reset(&(s->err));
  
  return s;
}
int tm_destroy(tm_t* mq) {
  tm_server_t* s = (tm_server_t*) mq;
  
  if (s->server) {
    ts_server__destroy(s->server);
  }
  s->server = NULL;

  ts__free(s);
  return 0;
}

int tm__set_listener_count(tm_t* mq, int cnt) {
  int err = 0;
  tm_server_t* s = (tm_server_t*) mq;
  err = ts_server__set_listener_count(s->server, cnt);
  if (err) {
    tm__copy_server_err(s, s->server);
  }
  return err;
}

int tm__set_listener_host_port(tm_t* mq, int idx, const char* host, int port) {
  int err = 0;
  tm_server_t* s = (tm_server_t*) mq;
  err = ts_server__set_listener_host_port(s->server, idx, host, port);
  if (err) {
    tm__copy_server_err(s, s->server);
  }
  return err;
}
int tm__set_listener_use_ipv6(tm_t* mq, int idx, int use) {
  int err = 0;
  tm_server_t* s = (tm_server_t*) mq;
  err = ts_server__set_listener_use_ipv6(s->server, idx, use);
  if (err) {
    tm__copy_server_err(s, s->server);
  }
  return err;
}
int tm__set_listener_protocol(tm_t* mq, int idx, int proto) {
  int err = 0;
  tm_server_t* s = (tm_server_t*) mq;
  err = ts_server__set_listener_protocol(s->server, idx, proto);
  if (err) {
    tm__copy_server_err(s, s->server);
  }
  return err;
}
int tm__set_listener_certs(tm_t* mq, int idx, const char* cert, const char* key) {
  int err = 0;
  tm_server_t* s = (tm_server_t*) mq;
  err = ts_server__set_listener_certs(s->server, idx, cert, key);
  if (err) {
    tm__copy_server_err(s, s->server);
  }
  return err;
}

int tm__set_log_level(tm_t* mq, int log_level) {
  int err = 0;
  tm_server_t* s = (tm_server_t*) mq;
  err = ts_server_log_set_log_level(s->server, log_level);
  if (err) {
    tm__copy_server_err(s, s->server);
  }
  return err;
}
int tm__set_log_dest(tm_t* mq, int dest) {
  int err = 0;
  tm_server_t* s = (tm_server_t*) mq;
  err = ts_server_log_set_log_dest(s->server, dest);
  if (err) {
    tm__copy_server_err(s, s->server);
  }
  return err;
}
int tm__set_log_dir(tm_t* mq, const char* dir) {
  int err = 0;
  tm_server_t* s = (tm_server_t*) mq;
  err = ts_server_log_set_log_dir(s->server, dir);
  if (err) {
    tm__copy_server_err(s, s->server);
  }
  return err;
}

int tm__set_callbacks(tm_t* mq, tm_callbacks_t* cbs) {
  int err = 0;
  tm_server_t* s = (tm_server_t*) mq;
  memcpy(&(s->callbacks), cbs, sizeof(tm_callbacks_t));
  
  err = ts_server_log_set_log_cb(s->server, cbs->cb_ctx, (ts_log_cb) cbs->log_cb);
  if (err) {
    tm__copy_server_err(s, s->server);
  }
  
  return err;
}

int tm__start(tm_t* mq) {
  int err = 0;
  tm_server_t* s = (tm_server_t*) mq;
  
  err = ts_server__start(s->server);
  if (err) {
    tm__copy_server_err(s, s->server);
  }
  
done:
  return err;
}
int tm__run(tm_t* mq) {
  int err = 0;
  tm_server_t* s = (tm_server_t*) mq;
  
  err = ts_server__run(s->server);
  if (err) {
    tm__copy_server_err(s, s->server);
  }
  
done:
  return err;
}
int tm__stop(tm_t* mq) {
  int err = 0;
  tm_server_t* s = (tm_server_t*) mq;
  
  err = ts_server__stop(s->server);
  if (err) {
    tm__copy_server_err(s, s->server);
  }
  
done:
  return err;
}

int tm__get_error(tm_t* mq) {
  tm_server_t* s = (tm_server_t*) mq;
  return s->err.err;
}
const char* tm__get_error_msg(tm_t* mq) {
  tm_server_t* s = (tm_server_t*) mq;
  return s->err.msg;
}

