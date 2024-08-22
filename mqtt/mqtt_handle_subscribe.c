#include "mqtt_conn.h"
#include "mqtt_utils.h"

#include <internal/ts_log.h>
#include <internal/ts_miscellany.h>

static int tm_mqtt_conn__send_suback(ts_t* server, ts_conn_t* c, int pkt_id, char* return_codes, int return_code_count) {
  char suback[64];
  suback[0] = (char)0x90;
  suback[1] = (char)(2 + return_code_count);
  uint162bytes_be(pkt_id, suback+2);
  memcpy(suback + 4, return_codes, return_code_count);

  return ts_server__write(server, c, suback, 4 + return_code_count);
}

int tm_mqtt_conn__process_subscribe(ts_t* server, ts_conn_t* c, const char* pkt_bytes, int pkt_bytes_len, int variable_header_off) {
  int err;
  tm_mqtt_conn_t* conn;
  tm_server_t* s;
  tm_packet_decoder_t* decoder;
  const char* tmp_ptr = "";
  int tmp_val, tmp_len, pkt_id, granted_qos;
  char topic[65536];
  char return_codes[32]; // at most 32
  int return_codes_count = 0;
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
  
  while (tm_packet_decoder__available(decoder) > 0) {
    err = tm_packet_decoder__read_int16_string(decoder, &tmp_len, &tmp_ptr);
    if (err || tmp_len == 0 || tmp_len >= 65536) {
      LOG_ERROR("[%s] Invalid Topic Filter", conn_id);
      tm_mqtt_conn__abort(server, c);
      goto done;
    }
    memcpy(topic, tmp_ptr, tmp_len);
    topic[tmp_len] = 0;
  
    err = tm_packet_decoder__read_byte(decoder, &granted_qos);
    if (err || !tm__is_valid_qos(granted_qos)) {
      LOG_ERROR("[%s] Invalid Topic Filter", conn_id);
      tm_mqtt_conn__abort(server, c);
      goto done;
    }
    
    s->callbacks.subscriber_cb(s->callbacks.cb_ctx, s, c, topic, granted_qos, &granted_qos);
    return_codes[return_codes_count++] = (char)granted_qos;
    
    if (tm__is_valid_qos(granted_qos)) {
      err = tm__on_subscription(server, c, topic, granted_qos);
      if (err) {
        tm_mqtt_conn__abort(server, c);
        goto done;
      }
    }
    
  }
  
  if (return_codes_count == 0) {
    LOG_ERROR("[%s] No Topic filter/Request QoS in the Subscribe packet", conn_id);
    tm_mqtt_conn__abort(server, c);
    goto done;
  }
  
  err = tm_mqtt_conn__send_suback(server, c, pkt_id, return_codes, return_codes_count);
  if (err) {
    LOG_ERROR("[%s] Fail to send SUBACK", conn_id);
    tm_mqtt_conn__abort(server, c);
    goto done;
  }
  
done:
  return 0;
}

