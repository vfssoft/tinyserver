#include "mqtt_session.h"

#include <ts.h>
#include <internal/ts_mem.h>

static tm_mqtt_session_t* tm_mqtt_session__create(const char* client_id) {
  tm_mqtt_session_t* sess;
  
  sess = (tm_mqtt_session_t*) ts__malloc(sizeof(tm_mqtt_session_t));
  if (sess == NULL) {
    return NULL;
  }
  
  sess->conn = NULL;
  sess->client_id = NULL;
  sess->clean_session = 1;
  sess->in_msgs = NULL;
  sess->out_msgs = NULL;
  
  ts_error__init(&(sess->err));
  
  sess->client_id = ts__strdup(client_id);
  if (sess->client_id == NULL) {
    return NULL;
  }
  
  return sess;
}
static int tm_mqtt_session__destroy(tm_mqtt_session_t* sess) {
  if (sess->client_id) {
    ts__free(sess->client_id);
  }
  
  ts__free(sess);
  return 0;
}

void* tm_mqtt_session__conn(tm_mqtt_session_t* sess) {
  return sess->conn;
}
void tm_mqtt_session__attach(tm_mqtt_session_t* sess, void* conn) {
  sess->conn = conn;
}
void* tm_mqtt_session__detach(tm_mqtt_session_t* sess) {
  void* conn = sess->conn;
  sess->conn = NULL;

  // Mark all pending messages as failed
  // Drop QoS0 messages
  tm_mqtt_msg_t* msg;
  tm_mqtt_msg_t* tmp;
  DL_FOREACH_SAFE(sess->out_msgs, msg, tmp) {
    if (tm_mqtt_msg__qos(msg) == 0) {
      tm_mqtt_session__remove_out_msg(sess, msg);
    } else {
      tm_mqtt_msg__set_failed(msg, TRUE);
    }
  }
  DL_FOREACH_SAFE(sess->in_msgs, msg, tmp) {
    if (tm_mqtt_msg__qos(msg) == 0) {
      tm_mqtt_session__remove_in_msg(sess, msg);
    } else {
      tm_mqtt_msg__set_failed(msg, TRUE);
    }
  }

  return conn;
}

int tm_mqtt_session__add_in_msg(tm_mqtt_session_t* sess, tm_mqtt_msg_t* msg) {
  DL_APPEND(sess->in_msgs, msg); // no lock
  return 0;
}
int tm_mqtt_session__remove_in_msg(tm_mqtt_session_t* sess, tm_mqtt_msg_t* msg) {
  // TODO: unref the msg
  DL_DELETE(sess->in_msgs, msg); // no lock
  return 0;
}
tm_mqtt_msg_t* tm_mqtt_session__find_in_msg(tm_mqtt_session_t* sess, int pkt_id) {
  tm_mqtt_msg_t* cur;
  DL_FOREACH(sess->in_msgs, cur) {
    if (cur->pkt_id == pkt_id) {
      return cur;
    }
  }
  return NULL;
}

int tm_mqtt_session__add_out_msg(tm_mqtt_session_t* sess, tm_mqtt_msg_t* msg) {
  DL_APPEND(sess->out_msgs, msg); // no lock
  return 0;
}
int tm_mqtt_session__remove_out_msg(tm_mqtt_session_t* sess, tm_mqtt_msg_t* msg) {
  // TODO: unref the msg
  DL_DELETE(sess->out_msgs, msg); // no lock
  return 0;
}
tm_mqtt_msg_t* tm_mqtt_session__find_out_msg(tm_mqtt_session_t* sess, int pkt_id) {
  tm_mqtt_msg_t* cur;
  DL_FOREACH(sess->out_msgs, cur) {
    if (cur->pkt_id == pkt_id) {
      return cur;
    }
  }
  return NULL;
}
tm_mqtt_msg_t* tm_mqtt_session__get_next_msg_to_send(tm_mqtt_session_t* sess) {
  tm_mqtt_msg_t* cur;
  DL_FOREACH(sess->out_msgs, cur) {
    if (tm_mqtt_msg__failed(cur) > 0) {
      return cur; // resend the current msg to the client
    }
    if (tm_mqtt_msg__get_state(cur) == MSG_STATE_TO_PUBLISH) {
      return cur; // send the current msg to the client, first time.
    }
  }
  return NULL;
}



tm_session_mgr_t* tm_session_mgr__create() {
  tm_session_mgr_t* mgr;
  
  mgr = (tm_session_mgr_t*) ts__malloc(sizeof(tm_session_mgr_t));
  if (mgr == NULL) {
    return NULL;
  }
  memset(mgr, 0, sizeof(tm_session_mgr_t));
  
  ts_mutex__init(&(mgr->mu));
  
  return mgr;
}
void tm_session_mgr__destroy(tm_session_mgr_t* mgr) {
  ts_mutex__destroy(&(mgr->mu));
  ts__free(mgr);
}

tm_mqtt_session_t* tm_session_mgr__find(tm_session_mgr_t* mgr, const char* client_id) {
  tm_mqtt_session_t* sess;
  
  ts_mutex__lock(&(mgr->mu));
  HASH_FIND_STR(mgr->sessions, client_id, sess);
  ts_mutex__unlock(&(mgr->mu));
  
  return sess;
}
tm_mqtt_session_t* tm_session_mgr__add(tm_session_mgr_t* mgr, const char* client_id) {
  tm_mqtt_session_t* sess;
  
  sess = tm_mqtt_session__create(client_id);
  if (sess == NULL) {
    return NULL;
  }
  
  ts_mutex__lock(&(mgr->mu));
  HASH_ADD_STR(mgr->sessions, client_id, sess);
  ts_mutex__unlock(&(mgr->mu));
  
  return sess;
}
int tm_session_mgr__delete(tm_session_mgr_t* mgr, tm_mqtt_session_t* sess) {
  ts_mutex__lock(&(mgr->mu));
  HASH_DEL(mgr->sessions, sess);
  ts_mutex__unlock(&(mgr->mu));
  
  tm_mqtt_session__destroy(sess);
  return 0;
}