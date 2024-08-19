
#include "mqtt_conn.h"

#include <internal/ts_mem.h>

tm_mqtt_conn_t* tm_mqtt_conn__create(tm_server_t* s) {
  tm_mqtt_conn_t* conn;
  
  conn = (tm_mqtt_conn_t*) ts__malloc(sizeof(tm_mqtt_conn_t));
  if (conn == NULL) {
    return NULL;
  }
  memset(conn, 0, sizeof(tm_mqtt_conn_t));
  
  conn->server = s;
  
  return conn;
}

int tm_mqtt_conn__destroy(tm_mqtt_conn_t* conn) {
  if (conn) {
    if (conn->client_id) {
      ts__free(conn->client_id);
    }
    
    if (conn->in_buf) {
      ts_buf__destroy(conn->in_buf);
    }
    
    ts__free(conn);
  }
  
  return 0;
}

int tm_mqtt_conn__data_in(tm_mqtt_conn_t* conn, const char* data, int len) {

}