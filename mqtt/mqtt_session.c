#include "mqtt_session.h"

#include <ts.h>
#include <internal/ts_mem.h>

tm_mqtt_session_t* tm_mqtt_session__create(const char* client_id) {
  tm_mqtt_session_t* sess;
  
  sess = (tm_mqtt_session_t*) ts__malloc(sizeof(tm_mqtt_session_t));
  if (sess == NULL) {
    return NULL;
  }
  
  sess->connected = 0;
  sess->client_id = NULL;
  sess->clean_session = 1;
  sess->in_msgs = NULL;
  sess->out_msgs = NULL;
  
  ts_error__init(&(sess->err));
  
  sess->client_id = (char*) ts__malloc(strlen(client_id));
  if (sess->client_id == NULL) {
    return NULL;
  }
  strcpy(sess->client_id, client_id);
  
  return sess;
}
int tm_mqtt_session__destroy(tm_mqtt_session_t* sess) {
  if (sess->client_id) {
    ts__free(sess->client_id);
  }
  
  ts__free(sess);
  return 0;
}

int tm_mqtt_session__add_in_msg(tm_mqtt_session_t* sess, tm_mqtt_msg_t* msg) {
  DL_APPEND(sess->in_msgs, msg); // no lock
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
tm_mqtt_msg_t* tm_mqtt_session__find_out_msg(tm_mqtt_session_t* sess, int pkt_id) {
  tm_mqtt_msg_t* cur;
  DL_FOREACH(sess->out_msgs, cur) {
    if (cur->pkt_id == pkt_id) {
      return cur;
    }
  }
  return NULL;
}