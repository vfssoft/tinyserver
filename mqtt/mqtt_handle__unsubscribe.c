#include "mqtt_conn.h"
#include "mqtt_utils.h"

#include <internal/ts_log.h>
#include <internal/ts_miscellany.h>

static int tm_mqtt_conn__send_unsuback(ts_t* server, ts_conn_t* c, int pkt_id) {
  char unsuback[4];
  unsuback[0] = (char)0xB0;
  unsuback[1] = (char)(2);
  uint162bytes_be(pkt_id, unsuback+2);
  return ts_server__write(server, c, unsuback, 4);
}

int tm_mqtt_conn__process_unsubscribe(ts_t* server, ts_conn_t* c, const char* pkt_bytes, int pkt_bytes_len, int variable_header_off) {
  int err;
  tm_mqtt_conn_t* conn;
  tm_server_t* s;
  tm_packet_decoder_t* decoder;
  const char* tmp_ptr = "";
  int tmp_val, tmp_len, pkt_id;
  char topic[65536];
  const char* conn_id = ts_server__get_conn_remote_host(server, c);
  
  conn = (tm_mqtt_conn_t*) ts_server__get_conn_user_data(server, c);
  s = conn->server;
  decoder = &conn->decoder;
  
  tm_packet_decoder__set(decoder, pkt_bytes + variable_header_off, pkt_bytes_len - variable_header_off);
  
  err = tm_packet_decoder__read_int16(decoder, &pkt_id);
  if (err) {
    LOG_ERROR("[%s] Invalid Packet Identifier", conn_id);
    tm_mqtt_conn__abort(server, c);
    goto done;
  }
  
  if (tm_packet_decoder__available(decoder) == 0) {
    LOG_ERROR("[%s] No Topic filter in the UNSUBSCRIBE packet", conn_id);
    tm_mqtt_conn__abort(server, c);
    goto done;
  }
  
  while (tm_packet_decoder__available(decoder) > 0) {
    err = tm_packet_decoder__read_int16_string(decoder, &tmp_len, &tmp_ptr);
    if (err || tmp_len == 0 || tmp_len >= 65536) {
      LOG_ERROR("[%s] Invalid Topic Filter", conn_id);
      tm_mqtt_conn__abort(server, c);
      goto done;
    }
    memcpy(topic, tmp_ptr, tmp_len);
    topic[tmp_len] = 0;
    
    s->callbacks.unsubscribe_cb(s->callbacks.cb_ctx, s, c, topic);
    
    err = tm__on_unsubscription(server, c, topic);
    if (err) {
      tm_mqtt_conn__abort(server, c);
      goto done;
    }
    
  }
  
  err = tm_mqtt_conn__send_unsuback(server, c, pkt_id);
  if (err) {
    LOG_ERROR("[%s] Fail to send UNSUBACK", conn_id);
    tm_mqtt_conn__abort(server, c);
    goto done;
  }
  
done:
  return 0;
}