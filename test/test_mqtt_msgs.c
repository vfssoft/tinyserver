
#include "test_mqtt_msgs.h"

#include <string.h>
#include <stdlib.h>


msg_t* msg__create(const char* topic, const char* payload, int payload_len, int qos, int retained, int dup) {
  msg_t* m = (msg_t*) malloc(sizeof(msg_t));
  memset(m, 0, sizeof(msg_t));
  
  m->topic = strdup(topic);
  m->payload = malloc(payload_len);
  memcpy(m->payload, payload, payload_len);
  m->payload_len = payload_len;
  m->qos = qos;
  m->retained = retained;
  m->dup = dup;
  
  return m;
}
void msg__destroy(msg_t* m) {
  if (m->topic) {
    free(m->topic);
  }
  if (m->payload) {
    free(m->payload);
  }
  free(m);
}
msg_t* msg__clone(msg_t* m) {
  return msg__create(
    m->topic,
    m->payload,
    m->payload_len,
    m->qos,
    m->retained,
    m->dup
  );
}




static void msgs__ensure_cap(msgs_t* msgs, int cap) {
  if (msgs->cap >= cap) {
    return;
  }
  
  cap = (cap + 7) / 8 * 8;
  msg_t** new_buf = (msg_t**) malloc(sizeof(msg_t*) * cap);
  memset(new_buf, 0, sizeof(msg_t*) * cap);
  
  for (int i = 0; i < msgs->count; i++) {
    new_buf[i] = msg__clone(msgs->buf[i]);
    msg__destroy(msgs->buf[i]);
  }
  
  if (msgs->buf) {
    free(msgs->buf);
  }
  
  msgs->buf = new_buf;
  msgs->cap = cap;
}
msgs_t* msgs__create(int cap) {
  msgs_t* msgs = (msgs_t*) malloc(sizeof(msgs_t));
  memset(msgs, 0, sizeof(msgs_t));
  
  msgs->buf = NULL;
  msgs->count = 0;
  msgs->cap = 0;
  
  if (cap == 0) cap = 8;
  msgs__ensure_cap(msgs, cap);
  
  return msgs;
}
void msgs__destroy(msgs_t* msgs) {
  for (int i = 0; i < msgs->count; i++) {
    msg__destroy(msgs->buf[i]);
  }
  
  if (msgs->buf) {
    free(msgs->buf);
  }
}
msgs_t* msgs__clone(msgs_t* msgs) {
  msgs_t* new_msgs = msgs__create(msgs->count);
  for (int i = 0; i < msgs->count; i++) {
    msgs__add(new_msgs, msgs->buf[i]);
  }
  return new_msgs;
}
void msgs__add(msgs_t* msgs, msg_t* m) {
  msgs__ensure_cap(msgs, msgs->count + 1);
  msgs->buf[msgs->count] = m;
  msgs->count++;
}
void msgs__add2(msgs_t* msgs, const char* topic, const char* payload, int payload_len, int qos, int retained, int dup) {
  msg_t* m = msg__create(topic, payload, payload_len, qos, retained, dup);
  msgs__add(msgs, m);
}
int msgs__count(msgs_t* msgs) {
  return msgs == NULL ? 0 : msgs->count;
}
msg_t* msgs__at(msgs_t* msgs, int idx) {
  return msgs->buf[idx];
}
