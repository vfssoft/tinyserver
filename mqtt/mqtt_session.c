#include "mqtt_session.h"

#include <ts.h>
#include <internal/ts_mem.h>

tm_mqtt_session_t* tm_mqtt_session__create(const char* client_id) {
  tm_mqtt_session_t* sess;
  
  sess = (tm_mqtt_session_t*) ts__malloc(sizeof(tm_mqtt_session_t));
  if (sess == NULL) {
    return NULL;
  }
  
  sess->connected = FALSE;
  sess->client_id = NULL;
  sess->clean_session = TRUE;
  
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
}

