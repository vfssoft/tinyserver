#include "mqtt_conn.h"

#include <internal/ts_log.h>

int tm_mqtt_conn__process_pingreq(ts_t* server, ts_conn_t* c, const char* pkt_bytes, int pkt_bytes_len) {
  int err;
  tm_mqtt_conn_t* conn;
  tm_server_t* s;
  const char* conn_id = ts_server__get_conn_remote_host(server, c);
  
  conn = (tm_mqtt_conn_t*) ts_server__get_conn_user_data(server, c);
  s = conn->server;
  
  LOG_DUMP(pkt_bytes, pkt_bytes_len, "[%s][%s] Receive [PINGREQ]", conn_id, conn->session->client_id);
  
  char pingresp[] = { 0xD0, 0 };
  
  LOG_DUMP(pingresp, 2, "[%s][%s] Send [PINGRESP]", conn_id, conn->session->client_id);
  
  err = tm_mqtt_conn__send_packet(server, c, pingresp, 2, -1, NULL);
  if (err) {
    LOG_ERROR("[%s][%s] Send PINGRESP failed: %d", conn_id, conn->session->client_id, err);
    tm_mqtt_conn__abort(server, c);
  }
  
  return 0;
}