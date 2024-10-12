#include "mqtt_conn.h"
#include "mqtt_utils.h"

#include <internal/ts_log.h>
#include <internal/ts_miscellany.h>

static int tm_mqtt_conn__send_puback(ts_t* server, ts_conn_t* c, int pkt_id, tm_mqtt_msg_t* msg) {
  char puback[4] = { 0x40, 0x02, 0x00, 0x00 };
  uint162bytes_be(pkt_id, puback+2);
  return tm_mqtt_conn__send_packet(server, c, puback, 4, pkt_id, msg);
}
static int tm_mqtt_conn__send_pubrec(ts_t* server, ts_conn_t* c, int pkt_id, tm_mqtt_msg_t* msg) {
  char pubrec[4] = { 0x52, 0x02, 0x00, 0x00 };
  uint162bytes_be(pkt_id, pubrec+2);
  return tm_mqtt_conn__send_packet(server, c, pubrec, 4, pkt_id, msg);
}
static int tm_mqtt_conn__send_pubrel(ts_t* server, ts_conn_t* c, int pkt_id, tm_mqtt_msg_t* msg) {
  char pubrel[4] = { 0x62, 0x02, 0x00, 0x00 };
  uint162bytes_be(pkt_id, pubrel+2);
  return tm_mqtt_conn__send_packet(server, c, pubrel, 4, pkt_id, msg);
}
static int tm_mqtt_conn__send_pubcomp(ts_t* server, ts_conn_t* c, int pkt_id, tm_mqtt_msg_t* msg) {
  char pubcomp[4] = { 0x70, 0x02, 0x00, 0x00 };
  uint162bytes_be(pkt_id, pubcomp+2);
  return tm_mqtt_conn__send_packet(server, c, pubcomp, 4, pkt_id, msg);
}

int tm_mqtt_conn__process_publish(ts_t* server, ts_conn_t* c, const char* pkt_bytes, int pkt_bytes_len, int variable_header_off) {
  int err;
  tm_mqtt_conn_t* conn;
  tm_server_t* s;
  tm_packet_decoder_t* decoder;
  const char* tmp_ptr = "";
  int tmp_len, pkt_id = 0;
  char topic[65536];
  char first_byte = pkt_bytes[0];
  int dup = (pkt_bytes[0] & 0x08) == 0x08;
  int qos = (pkt_bytes[0] & 0x06) >> 1;
  tm_mqtt_msg_t* msg;

  conn = (tm_mqtt_conn_t*) ts_server__get_conn_user_data(server, c);
  s = conn->server;
  decoder = &conn->decoder;

  tm_packet_decoder__set(decoder, pkt_bytes + variable_header_off, pkt_bytes_len - variable_header_off);

  if (!tm__is_valid_qos(qos)) {
    LOG_ERROR("[%s] Invalid QoS", conn->session->client_id);
    tm_mqtt_conn__abort(server, c);
    goto done;
  }
  if (qos == 0 && dup) {
    LOG_ERROR("[%s] Invalid DUP flag with the QoS is 0", conn->session->client_id);
    tm_mqtt_conn__abort(server, c);
    goto done;
  }

  err = tm_packet_decoder__read_int16_string(decoder, &tmp_len, &tmp_ptr);
  if (err || tmp_len == 0) {
    LOG_ERROR("[%s] Invalid Topic Name", conn->session->client_id);
    tm_mqtt_conn__abort(server, c);
    goto done;
  }
  memcpy(topic, tmp_ptr, tmp_len);
  topic[tmp_len] = 0;

  if (qos != 0) {
    err = tm_packet_decoder__read_int16(decoder, &pkt_id);
    if (err || pkt_id <= 0) {
      LOG_ERROR("[%s] Invalid Packet Id", conn->session->client_id);
      tm_mqtt_conn__abort(server, c);
      goto done;
    }
  }

  msg = tm__create_message(
      s,
      topic,
      tm_packet_decoder__ptr(decoder), tm_packet_decoder__available(decoder),
      dup, qos, (first_byte & 0x01) == 0x01
  );
  if (msg == NULL) {
    LOG_ERROR("[%s] Out of memory", conn->session->client_id);
    tm_mqtt_conn__abort(server, c);
    goto done;
  }
  msg->pkt_id = pkt_id;
  
  LOG_VERB(
      "[%s] Received a message: MID=%" PRIu64 ", Topic='%s', Qos=%d, Retain=%d",
      conn->session->client_id,
      msg->id,
      topic,
      qos,
      dup
  );

  tm_mqtt_session__add_in_msg(conn->session, msg);
  tm_mqtt_msg__set_state(msg, MSG_STATE_RECEIVE_PUB);
  
  err = tm_mqtt_conn__update_msg_state(server, c, msg);
  if (err) {
    tm_mqtt_conn__abort(server, c);
    goto done;
  }

  if (qos == 0){
    // nothing
  } else if (qos == 1) {
    err = tm_mqtt_conn__send_puback(server, c, pkt_id, msg);
    if (err) {
      LOG_ERROR("[%s] Failed to send PUBACK", conn->session->client_id);
      tm_mqtt_conn__abort(server, c);
      goto done;
    }
  } else if (qos == 2) {
    err = tm_mqtt_conn__send_pubrec(server, c, pkt_id, msg);
    if (err) {
      LOG_ERROR("[%s] Failed to send PUBREC", conn->session->client_id);
      tm_mqtt_conn__abort(server, c);
      goto done;
    }
  }
done:
  return 0;
}

int tm_mqtt_conn__process_puback(ts_t* server, ts_conn_t* c, const char* pkt_bytes, int pkt_bytes_len, int variable_header_off) {
  int err;
  tm_mqtt_conn_t* conn;
  tm_server_t* s;
  tm_packet_decoder_t* decoder;
  int pkt_id;
  tm_mqtt_msg_t* msg;
  
  conn = (tm_mqtt_conn_t*) ts_server__get_conn_user_data(server, c);
  s = conn->server;
  decoder = &conn->decoder;
  
  tm_packet_decoder__set(decoder, pkt_bytes + variable_header_off, pkt_bytes_len - variable_header_off);
  
  err = tm_packet_decoder__read_int16(decoder, &pkt_id);
  if (err || pkt_id <= 0) {
    LOG_ERROR("[%s] Invalid Packet id", conn->session->client_id);
    tm_mqtt_conn__abort(server, c);
    goto done;
  }
  
  msg = tm_mqtt_session__find_out_msg(conn->session, pkt_id);
  if (msg == NULL) {
    LOG_ERROR("[%s] Invalid Packet id", conn->session->client_id);
    tm_mqtt_conn__abort(server, c);
    goto done;
  }
  if (tm_mqtt_msg__qos(msg) != 1 || tm_mqtt_msg__get_state(msg) != MSG_STATE_WAIT_PUBACK) {
    LOG_ERROR("[%s] Invalid Message state", conn->session->client_id);
    tm_mqtt_conn__abort(server, c);
    goto done;
  }
  
  tm_mqtt_conn__update_msg_state(server, c, msg);
  
done:
  return 0;
}
int tm_mqtt_conn__process_pubrec(ts_t* server, ts_conn_t* c, const char* pkt_bytes, int pkt_bytes_len, int variable_header_off) {
  int err;
  tm_mqtt_conn_t* conn;
  tm_server_t* s;
  tm_packet_decoder_t* decoder;
  int pkt_id;
  tm_mqtt_msg_t* msg;
  
  conn = (tm_mqtt_conn_t*) ts_server__get_conn_user_data(server, c);
  s = conn->server;
  decoder = &conn->decoder;
  
  tm_packet_decoder__set(decoder, pkt_bytes + variable_header_off, pkt_bytes_len - variable_header_off);
  
  err = tm_packet_decoder__read_int16(decoder, &pkt_id);
  if (err || pkt_id <= 0) {
    LOG_ERROR("[%s] Invalid Packet id", conn->session->client_id);
    tm_mqtt_conn__abort(server, c);
    goto done;
  }
  
  msg = tm_mqtt_session__find_out_msg(conn->session, pkt_id);
  if (msg == NULL) {
    LOG_ERROR("[%s] Invalid Packet id", conn->session->client_id);
    tm_mqtt_conn__abort(server, c);
    goto done;
  }
  if (tm_mqtt_msg__qos(msg) != 2 || tm_mqtt_msg__get_state(msg) != MSG_STATE_WAIT_PUBREC) {
    LOG_ERROR("[%s] Invalid Message state", conn->session->client_id);
    tm_mqtt_conn__abort(server, c);
    goto done;
  }
  
  tm_mqtt_conn__update_msg_state(server, c, msg);
  err = tm_mqtt_conn__send_pubrel(server, c, pkt_id, msg);
  if (err) {
    LOG_ERROR("[%s] Failed to send PUBREL", conn->session->client_id);
    tm_mqtt_conn__abort(server, c);
    goto done;
  }
  
done:
  return 0;
}
int tm_mqtt_conn__process_pubrel(ts_t* server, ts_conn_t* c, const char* pkt_bytes, int pkt_bytes_len, int variable_header_off) {
  int err;
  tm_mqtt_conn_t* conn;
  tm_server_t* s;
  tm_packet_decoder_t* decoder;
  int pkt_id;
  tm_mqtt_msg_t* msg;
  
  conn = (tm_mqtt_conn_t*) ts_server__get_conn_user_data(server, c);
  s = conn->server;
  decoder = &conn->decoder;
  
  tm_packet_decoder__set(decoder, pkt_bytes + variable_header_off, pkt_bytes_len - variable_header_off);
  
  err = tm_packet_decoder__read_int16(decoder, &pkt_id);
  if (err || pkt_id <= 0) {
    LOG_ERROR("[%s] Invalid Packet id", conn->session->client_id);
    tm_mqtt_conn__abort(server, c);
    goto done;
  }
  
  msg = tm_mqtt_session__find_in_msg(conn->session, pkt_id);
  if (msg == NULL || tm_mqtt_msg__qos(msg) != 2) {
    LOG_ERROR("[%s] Invalid Packet id", conn->session->client_id);
    tm_mqtt_conn__abort(server, c);
    goto done;
  }
  
  tm_mqtt_conn__update_msg_state(server, c, msg);
  err = tm_mqtt_conn__send_pubcomp(server, c, pkt_id, msg);
  if (err) {
    LOG_ERROR("[%s] Failed to send PUBCOMP", conn->session->client_id);
    tm_mqtt_conn__abort(server, c);
    goto done;
  }
  
done:
  return 0;
}
int tm_mqtt_conn__process_pubcomp(ts_t* server, ts_conn_t* c, const char* pkt_bytes, int pkt_bytes_len, int variable_header_off) {
  int err;
  tm_mqtt_conn_t* conn;
  tm_server_t* s;
  tm_packet_decoder_t* decoder;
  int pkt_id;
  tm_mqtt_msg_t* msg;
  
  conn = (tm_mqtt_conn_t*) ts_server__get_conn_user_data(server, c);
  s = conn->server;
  decoder = &conn->decoder;
  
  tm_packet_decoder__set(decoder, pkt_bytes + variable_header_off, pkt_bytes_len - variable_header_off);
  
  err = tm_packet_decoder__read_int16(decoder, &pkt_id);
  if (err) {
    LOG_ERROR("[%s] Invalid Packet id", conn->session->client_id);
    tm_mqtt_conn__abort(server, c);
    goto done;
  }
  
  msg = tm_mqtt_session__find_out_msg(conn->session, pkt_id);
  if (msg == NULL) {
    LOG_ERROR("[%s] Invalid Packet id", conn->session->client_id);
    tm_mqtt_conn__abort(server, c);
    goto done;
  }
  if (tm_mqtt_msg__qos(msg) != 2 || tm_mqtt_msg__get_state(msg) != MSG_STATE_WAIT_PUBCOMP) {
    LOG_ERROR("[%s] Invalid Message state", conn->session->client_id);
    tm_mqtt_conn__abort(server, c);
    goto done;
  }
  
  tm_mqtt_conn__update_msg_state(server, c, msg);
  
done:
  return 0;
}
