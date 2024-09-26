#include "mqtt_message.h"

#include <internal/ts_mem.h>

static tm_mqtt_msg_core_t* tm_mqtt_msg_core__create(const char* topic, const char* payload, int payload_len) {
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
static int tm_mqtt_msg_core__destroy(tm_mqtt_msg_core_t* msg_core) {
  if (msg_core->topic) {
    ts_buf__destroy(msg_core->topic);
  }
  if (msg_core->payload) {
    ts_buf__destroy(msg_core->payload);
  }

  ts__free(msg_core);
  return 0;
}

static int tm_mqtt_msg_core__add_ref(tm_mqtt_msg_core_t* msg_core) {
  msg_core->ref_count++;
  return msg_core->ref_count;
}
static int tm_mqtt_msg_core__dec_ref(tm_mqtt_msg_core_t* msg_core) {
  msg_core->ref_count--;
  assert(msg_core->ref_count >= 0);
  return msg_core->ref_count;
}

int tm_mqtt_msg__retain(tm_mqtt_msg_t* msg) {
  return (msg->flags & 0x01) == 0x01;
}
void tm_mqtt_msg__set_retain(tm_mqtt_msg_t* msg, int retain) {
  if (retain) {
    msg->flags |= 0x01;
  } else {
    msg->flags &= ~0x01;
  }
}
int tm_mqtt_msg__qos(tm_mqtt_msg_t* msg) {
  return (msg->flags & 0x06) >> 1;
}
void tm_mqtt_msg__set_qos(tm_mqtt_msg_t* msg, int qos) {
  msg->flags &= ~0x06;
  msg->flags |= (qos << 1);
}
int tm_mqtt_msg__dup(tm_mqtt_msg_t* msg) {
  return (msg->flags & 0x80) == 0x80;
}
void tm_mqtt_msg__set_dup(tm_mqtt_msg_t* msg, int dup) {
  if (dup) {
    msg->flags |= 0x80;
  } else {
    msg->flags &= ~0x80;
  }
}

unsigned long long tm_mqtt_msg__id(tm_mqtt_msg_t* msg) {
  return msg->id;
}

int tm_mqtt_msg__get_state(tm_mqtt_msg_t* msg) {
  return msg->state;
}
int tm_mqtt_msg__set_state(tm_mqtt_msg_t* msg, int state) {
  msg->state = state;
  return 0;
}
int tm_mqtt_msg__update_state(tm_mqtt_msg_t* msg) {
  int qos = tm_mqtt_msg__qos(msg);
  
  switch (msg->state) {
    case MSG_STATE_INIT:
      return -1;
    
    // Outgoing
    case MSG_STATE_TO_PUBLISH: // start state for outgoing
      if (qos == 0) {
        msg->state = MSG_STATE_DONE;
      } else if (qos == 1) {
        msg->state = MSG_STATE_WAIT_PUBACK;
      } else if (qos == 2) {
        msg->state = MSG_STATE_WAIT_PUBREC;
      } else {
        assert(0);
      }
      break;
    
    case MSG_STATE_WAIT_PUBACK:
      msg->state = MSG_STATE_DONE;
      break;
    
    case MSG_STATE_WAIT_PUBREC:
      msg->state = MSG_STATE_SEND_PUBREL;
      break;
    
    case MSG_STATE_SEND_PUBREL:
      msg->state = MSG_STATE_WAIT_PUBCOMP;
      break;
    
    case MSG_STATE_WAIT_PUBCOMP:
      msg->state = MSG_STATE_DONE;
      break;
    
    // Incoming
    case MSG_STATE_RECEIVE_PUB: // start state for incoming
      if (qos == 0) {
        msg->state = MSG_STATE_DONE;
      } else if (qos == 1) {
        msg->state = MSG_STATE_SEND_PUBACK;
      } else if (qos == 2) {
        msg->state = MSG_STATE_SEND_PUBREC;
      } else {
        assert(0);
      }
      break;
    
    case MSG_STATE_SEND_PUBACK:
      msg->state = MSG_STATE_DONE;
      break;
    
    case MSG_STATE_SEND_PUBREC:
      msg->state = MSG_STATE_WAIT_PUBREL;
      break;
    
    case MSG_STATE_WAIT_PUBREL:
      msg->state = MSG_STATE_SEND_PUBCOMP;
      break;
    
    case MSG_STATE_SEND_PUBCOMP:
      msg->state = MSG_STATE_DONE;
      break;
    
    case MSG_STATE_DONE:
      return -1;
    
    default:
      return -1; // invalid state
  }
  
  return 0;
}


tm_msg_mgr_t* tm_msg_mgr__create() {
  tm_msg_mgr_t* mgr;
  
  mgr = (tm_msg_mgr_t*) ts__malloc(sizeof(tm_msg_mgr_t));
  if (mgr == NULL) {
    return NULL;
  }
  memset(mgr, 0, sizeof(tm_msg_mgr_t));
  
  mgr->next_msg_id = 1; // start from 1
  
  ts_mutex__init(&(mgr->mu));
  
  return mgr;
}
int tm_msg_mgr__destroy(tm_msg_mgr_t* mgr) {
  ts_mutex__destroy(&(mgr->mu));
  
  // TODO: free messages, cores
  
  return 0;
}

tm_mqtt_msg_t* tm_msg_mgr__add(tm_msg_mgr_t* mgr, const char* topic, const char* payload, int payload_len, int dup, int qos, int retain) {
  tm_mqtt_msg_t* msg = NULL;
  tm_mqtt_msg_core_t* msg_core = NULL;
  
  msg = (tm_mqtt_msg_t*) ts__malloc_zeros(sizeof(tm_mqtt_msg_t));
  if (msg == NULL) {
    return NULL;
  }
  
  msg_core = tm_mqtt_msg_core__create(topic, payload, payload_len);
  if (msg_core == NULL) {
    return NULL;
  }
  
  tm_mqtt_msg_core__add_ref(msg_core); // add ref
  
  msg->msg_core = msg_core;
  msg->flags = (dup ? 4 : 0) | (qos << 1) | retain;
  msg->state = MSG_STATE_INIT;
  
  ts_mutex__lock(&(mgr->mu));
  msg->id = mgr->next_msg_id;
  mgr->next_msg_id++; // assume it won't overflow
  
  DL_APPEND(mgr->message_cores, msg_core);
  DL_APPEND(mgr->messages, msg);
  ts_mutex__unlock(&(mgr->mu));
  
  return msg;
}
int tm_msg_mgr__unuse(tm_msg_mgr_t* mgr, tm_mqtt_msg_t* msg) {
  int msg_core_ref_cnt;
  
  ts_mutex__lock(&(mgr->mu));
  
  msg_core_ref_cnt = tm_mqtt_msg_core__dec_ref(msg->msg_core);
  if (msg_core_ref_cnt == 0) {
    DL_DELETE(mgr->message_cores, msg->msg_core);
    DL_DELETE(mgr->messages, msg);
  
    tm_mqtt_msg_core__destroy(msg->msg_core);
    ts__free(msg);
  }
  
  ts_mutex__unlock(&(mgr->mu));
  
  return 0;
}