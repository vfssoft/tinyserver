#include "mqtt_message.h"

#include <internal/ts_mem.h>

tm_mqtt_msg_core_t* tm_mqtt_msg_core__create(const char* topic, const char* payload, int payload_len) {
  tm_mqtt_msg_core_t* msg_core;

  msg_core = (tm_mqtt_msg_core_t*) ts__malloc(sizeof(tm_mqtt_msg_core_t));
  if (msg_core == NULL) {
    return NULL;
  }
  memset(msg_core, 0, sizeof(tm_mqtt_msg_core_t));

  msg_core->topic = ts_buf__create(0);
  if (msg_core->topic == NULL) {
    return NULL;
  }
  ts_buf__set(msg_core->topic, topic, strlen(topic));

  if (payload_len) {
    msg_core->payload = ts_buf__create(0);
    if (msg_core->payload == NULL) {
      return NULL;
    }
    ts_buf__set(msg_core->payload, payload, payload_len);
  }

  return msg_core;

}
int tm_mqtt_msg_core__destroy(tm_mqtt_msg_core_t* msg_core) {
  if (msg_core->topic) {
    ts_buf__destroy(msg_core->topic);
  }
  if (msg_core->payload) {
    ts_buf__destroy(msg_core->payload);
  }

  ts__free(msg_core);
  return 0;
}

int tm_mqtt_msg_core__add_ref(tm_mqtt_msg_core_t* msg_core) {
  msg_core->ref_count++;
  return msg_core->ref_count;
}
int tm_mqtt_msg_core__dec_ref(tm_mqtt_msg_core_t* msg_core) {
  msg_core->ref_count--;
  assert(msg_core->ref_count >= 0);
  return msg_core->ref_count;
}

int tm_mqtt_msg__get_state(tm_mqtt_msg_t* msg) {
  return msg->state;
}
int tm_mqtt_msg__change_state(tm_mqtt_msg_t* msg, int new_state) {
  // TODO:

  return 0;
}
