
#include "mqtt.h"
#include "mqtt_conn.h"

#include <assert.h>
#include <internal/ts_mem.h>
#include <internal/ts_log.h>

static void tm__copy_server_err(tm_server_t* tm, ts_t* ts) {
  ts_error__set_msg(
      &(tm->err),
      ts_server__get_error(ts),
      ts_server__get_error_msg(ts)
  );
}

static void tm__conn_connected_cb(void* ctx, ts_t* server, ts_conn_t* conn, int status) {
  tm_server_t* s = (tm_server_t*) ctx;
  tm_mqtt_conn_t* mqtt_conn = NULL;
  ts_error_t err;
  assert(status == 0);
  
  ts_error__init(&err);
  
  mqtt_conn = tm_mqtt_conn__create(s);
  if (mqtt_conn == NULL) {
    ts_error__set(&err, TS_ERR_OUT_OF_MEMORY);
    goto done;
  }
  
  ts_server__set_conn_user_data(server, conn, mqtt_conn);
  
done:
  if (err.err) {
    LOG_ERROR(
        "[%s] Failed to create MQTT connection: %d %s, drop the connection",
        ts_server__get_conn_remote_host(server, conn),
        err.err, err.msg
    );
    ts_server__disconnect(server, conn);
  }
}
static void tm__conn_disconnected_cb(void* ctx, ts_t* server, ts_conn_t* conn, int status) {
  //tm_server_t* s = (tm_server_t*) ctx;
  tm_mqtt_conn_t* mqtt_conn;
  
  tm_mqtt_conn__process_tcp_disconnect(server, conn);
  
  mqtt_conn = (tm_mqtt_conn_t* )ts_server__get_conn_user_data(server, conn);
  if (mqtt_conn) {
    tm_mqtt_conn__destroy(mqtt_conn);
  }
}
static void tm__conn_read_cb(void* ctx, ts_t* server, ts_conn_t* conn, const char* data, int len) {
  tm_server_t* s = (tm_server_t*) ctx;

}
static void tm__conn_write_cb(void* ctx, ts_t* server, ts_conn_t* conn, int status, int can_write_more) {
  tm_mqtt_conn__write_cb(server, conn, status, can_write_more);
}
static void tm__idle_cb(void* ctx, ts_t* server) {
  tm_server_t* s = (tm_server_t*) ctx;
}

tm_t* tm__create() {
  tm_server_t* s = (tm_server_t*) ts__malloc(sizeof(tm_server_t));
  memset(s, 0, sizeof(tm_server_t));
  
  s->server = ts_server__create();
  if (s->server == NULL) {
    return NULL;
  }
  
  s->topics = tm_topics__create();
  if (s->topics == NULL) {
    return NULL;
  }
  
  ts_error__reset(&(s->err));

  ts_server__set_cb_ctx(s->server, s);
  ts_server__set_connected_cb(s->server, tm__conn_connected_cb);
  ts_server__set_read_cb(s->server, tm__conn_read_cb);
  ts_server__set_write_cb(s->server, tm__conn_write_cb);
  ts_server__set_disconnected_cb(s->server, tm__conn_disconnected_cb);
  ts_server__set_idle_cb(s->server, tm__idle_cb);
  
  ts_mutex__init(&(s->sessions_mu));
  ts_mutex__init(&(s->messages_mu));
  return s;
}
int tm_destroy(tm_t* mq) {
  tm_server_t* s = (tm_server_t*) mq;
  
  if (s->server) {
    ts_server__destroy(s->server);
  }
  s->server = NULL;

  if (s->topics) {
    tm_topics__destroy(s->topics);
  }
  s->topics = NULL;
  
  ts_mutex__destroy(&(s->sessions_mu));
  ts_mutex__destroy(&(s->messages_mu));

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


tm_mqtt_session_t* tm__find_session(tm_server_t* s, const char* client_id) {
  tm_mqtt_session_t* sess;
  
  ts_mutex__lock(&(s->sessions_mu));
  HASH_FIND_STR(s->sessions, client_id, sess);
  ts_mutex__unlock(&(s->sessions_mu));
  
  return sess;
}
tm_mqtt_session_t* tm__create_session(tm_server_t* s, const char* client_id) {
  tm_mqtt_session_t* sess;
  
  sess = tm_mqtt_session__create(client_id);
  if (sess == NULL) {
    return NULL;
  }
  
  ts_mutex__lock(&(s->sessions_mu));
  HASH_ADD_STR(s->sessions, client_id, sess);
  ts_mutex__unlock(&(s->sessions_mu));

  return sess;
}
int tm__remove_session(tm_server_t* s, tm_mqtt_session_t* sess) {
  ts_mutex__lock(&(s->sessions_mu));
  HASH_DEL(s->sessions, sess);
  ts_mutex__unlock(&(s->sessions_mu));
  
  tm_mqtt_session__destroy(sess);
  return 0;
}


static tm_mqtt_msg_core_t* tm__create_message_core(tm_server_t* s, const char* topic, const char* payload, int payload_len) {
  tm_mqtt_msg_core_t* msg_core;

  msg_core = tm_mqtt_msg_core__create(topic, payload, payload_len);
  if (msg_core == NULL) {
    return NULL;
  }

  ts_mutex__lock(&(s->messages_mu));
  DL_APPEND(s->message_cores, msg_core);
  ts_mutex__unlock(&(s->messages_mu));

  return msg_core;
}
static int tm__ref_message_core(tm_server_t* s, tm_mqtt_msg_core_t* msg_core) {
  tm_mqtt_msg_core__add_ref(msg_core); // add ref
  return 0;
}
static int tm__unref_message_core(tm_server_t* s, tm_mqtt_msg_core_t* msg_core) {
  int msg_core_ref_cnt;

  msg_core_ref_cnt = tm_mqtt_msg_core__dec_ref(msg_core);

  if (msg_core_ref_cnt == 0) {
    ts_mutex__lock(&(s->messages_mu));
    DL_DELETE(s->message_cores, msg_core);
    ts_mutex__unlock(&(s->messages_mu));

    tm_mqtt_msg_core__destroy(msg_core);
  }

  return 0;
}
tm_mqtt_msg_t* tm__create_message(tm_server_t* s, const char* topic, const char* payload, int payload_len, int dup, int qos, int retain) {
  tm_mqtt_msg_t* msg;
  tm_mqtt_msg_core_t* msg_core;

  msg = (tm_mqtt_msg_t*) ts__malloc(sizeof(tm_mqtt_msg_t));
  if (msg == NULL) {
    return NULL;
  }
  msg_core = tm__create_message_core(s, topic, payload, payload_len);
  if (msg_core == NULL) {
    return NULL;
  }

  tm__ref_message_core(s, msg_core);

  msg->msg_core = msg_core;
  msg->flags = (dup ? 4 : 0) | (qos << 1) | retain;
  msg->state = MSG_STATE_INIT;

  return msg;
}

void tm__remove_message(tm_server_t* s, tm_mqtt_msg_t* msg) {
  tm__unref_message_core(s, msg->msg_core);
  ts__free(msg);
}


