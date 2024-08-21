
#include "mqtt_conn.h"

#include <internal/ts_log.h>

int tm_mqtt_conn__process_disconnect(ts_t* server, ts_conn_t* c) {
  tm_mqtt_conn_t* conn;
  tm_server_t* s;
  const char* conn_id = ts_server__get_conn_remote_host(server, c);
  
  conn = (tm_mqtt_conn_t*) ts_server__get_conn_user_data(server, c);
  s = conn->server;
  
  if (conn->will) {
    LOG_VERB("[%s] Client is disconnected gracefully, discard the Will message silently");
    tm__remove_message(s, conn->will);
    conn->will = NULL;
  }
  
  return tm_mqtt_conn__process_tcp_disconnect(server, c);
}

int tm_mqtt_conn__process_tcp_disconnect(ts_t* server, ts_conn_t* c) {
  tm_mqtt_conn_t* conn;
  tm_server_t* s;
  const char* conn_id = ts_server__get_conn_remote_host(server, c);
  
  conn = (tm_mqtt_conn_t*) ts_server__get_conn_user_data(server, c);
  s = conn->server;
  
  tm_mqtt_conn__abort(server, c);
  
  if (!conn->session->connected) {
    return 0;
  }
  
  conn->session->connected = 0;
  
  if (conn->will) {
    LOG_VERB("[%s] Client is disconnected abnormally, publish the Will message silently");
    // TODO: publish Will message
    tm__remove_message(s, conn->will);
    conn->will = NULL;
  }
  
  // conn->session = NULL;
  s->callbacks.disconnected_cb(s->callbacks.cb_ctx, server, c);
  return 0;
}