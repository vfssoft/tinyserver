#include "mqtt_conn.h"

#include <internal/ts_log.h>

int tm_mqtt_conn__process_pingreq(ts_t* server, ts_conn_t* c) {
  int err;
  tm_mqtt_conn_t* conn;
  tm_server_t* s;
  const char* conn_id = ts_server__get_conn_remote_host(server, c);
  
  conn = (tm_mqtt_conn_t*) ts_server__get_conn_user_data(server, c);
  s = conn->server;
  
  char pingresp[] = { 0x0D, 0 };
  
  err = ts_server__write(server, c, pingresp, 2); // No need to call tm_mqtt_conn__send_packet()
  if (err) {
    LOG_ERROR("[%s] Send PINGRESP failed: %d", conn_id, err);
    tm_mqtt_conn__abort(server, c);
  }
  
  return 0;
}