
#include "mqtt_conn.h"
#include "mqtt_packets.h"

#include <internal/ts_mem.h>
#include <internal/ts_log.h>
#include <internal/ts_miscellany.h>


tm_mqtt_conn_t* tm_mqtt_conn__create(tm_server_t* s, ts_conn_t* c) {
  tm_mqtt_conn_t* conn;
  
  conn = (tm_mqtt_conn_t*) ts__malloc(sizeof(tm_mqtt_conn_t));
  if (conn == NULL) {
    return NULL;
  }
  memset(conn, 0, sizeof(tm_mqtt_conn_t));
  
  conn->in_buf = ts_buf__create(64);
  if (conn->in_buf == NULL) {
    return NULL;
  }

  tm_packet_decoder__set(&(conn->decoder), NULL, 0);
  ts_error__init(&(s->err));

  conn->server = s;
  
  conn->next_recv_time = ts_server__now(s->server) + 5000;
  ts_server__set_conn_user_data(s->server, c, conn);
  ts_server__conn_start_timer(s->server, c, 1000, 1000);
  
  conn->next_pkt_id = 1;
  
  return conn;
}

int tm_mqtt_conn__destroy(ts_t* server, ts_conn_t* c) {
  tm_mqtt_conn_t* conn;
  tm_server_t* s;
  
  conn = (tm_mqtt_conn_t*) ts_server__get_conn_user_data(server, c);
  //s = conn->server; // conn may be NULL
  
  if (conn) {
    if (conn->session) {
      // TODO:
    }
    
    if (conn->in_buf) {
      ts_buf__destroy(conn->in_buf);
    }
  
    ts_server__conn_stop_timer(server, c);
    ts_server__set_conn_user_data(server, c, NULL);
    
    ts__free(conn);
  }
  
  return 0;
}

void tm_mqtt_conn__abort(ts_t* server, ts_conn_t* c) {
  ts_server__disconnect(server, c);
}
int tm_mqtt_conn__send_packet(ts_t* server, ts_conn_t* c, const char* data, int len, int pkt_id, tm_mqtt_msg_t* msg) {
  int err;
  tm_mqtt_conn_t* conn;
  const char* conn_id = ts_server__get_conn_remote_host(server, c);
  
  conn = (tm_mqtt_conn_t*) ts_server__get_conn_user_data(server, c);
  
  return ts_server__write(server, c, data, len, NULL);
}


static int tm_mqtt_conn__process_in_pkt(ts_t* server, ts_conn_t* c, const char* pkt_bytes, int pkt_bytes_len, int variable_header_off) {
  tm_mqtt_conn_t* conn;
  
  conn = (tm_mqtt_conn_t*) ts_server__get_conn_user_data(server, c);
  int pkt_type = (pkt_bytes[0] & 0xF0) >> 4;

  if (conn->session == NULL && pkt_type != PKT_TYPE_CONNECT) {
    LOG_ERROR("[%s] First packet should be CONNECT", ts_server__get_conn_remote_host(server, c));
    tm_mqtt_conn__abort(server, c);
    return TS_ERR_MALFORMED_MQTT_PACKET;
  }

  switch (pkt_type) {

    case PKT_TYPE_CONNECT:
      if (conn->session && tm_mqtt_session__conn(conn->session) != NULL) {
        LOG_ERROR("[%s] Already connected but receive another CONNECT", ts_server__get_conn_remote_host(server, c));
        tm_mqtt_conn__abort(server, c);
        return 0;
      }

      return tm_mqtt_conn__process_connect(server, c, pkt_bytes, pkt_bytes_len, variable_header_off);

    case PKT_TYPE_PUBLISH:
      return tm_mqtt_conn__process_publish(server, c, pkt_bytes, pkt_bytes_len, variable_header_off);

    case PKT_TYPE_PUBACK:
      return tm_mqtt_conn__process_puback(server, c, pkt_bytes, pkt_bytes_len, variable_header_off);

    case PKT_TYPE_PUBREC:
      return tm_mqtt_conn__process_pubrec(server, c, pkt_bytes, pkt_bytes_len, variable_header_off);

    case PKT_TYPE_PUBREL:
      return tm_mqtt_conn__process_pubrel(server, c, pkt_bytes, pkt_bytes_len, variable_header_off);

    case PKT_TYPE_PUBCOMP:
      return tm_mqtt_conn__process_pubcomp(server, c, pkt_bytes, pkt_bytes_len, variable_header_off);

    case PKT_TYPE_SUBSCRIBE:
      return tm_mqtt_conn__process_subscribe(server, c, pkt_bytes, pkt_bytes_len, variable_header_off);

    case PKT_TYPE_UNSUBSCRIBE:
      return tm_mqtt_conn__process_unsubscribe(server, c, pkt_bytes, pkt_bytes_len, variable_header_off);

    case PKT_TYPE_PINGREQ:
      return tm_mqtt_conn__process_pingreq(server, c);

    case PKT_TYPE_DISCONNECT:
      return tm_mqtt_conn__process_disconnect(server, c);

    default:
      LOG_ERROR("[%s] Unkonwn Control Packet Type(%d)", ts_server__get_conn_remote_host(server, c), pkt_type);
      tm_mqtt_conn__abort(server, c);
      break;
  }
  return 0;
}
void tm_mqtt_conn__data_in(ts_t* server, ts_conn_t* c, const char* data, int len) {
  int err;
  tm_mqtt_conn_t* conn;
  int total_bytes_consumed = 0;
  BOOL parsed = FALSE;
  int pkt_bytes_cnt = 0;
  unsigned int remaining_length = 0;
  BOOL use_in_buf = FALSE;
  const char* buf;
  int buf_len;
  ts_error_t errt;
  
  conn = (tm_mqtt_conn_t*) ts_server__get_conn_user_data(server, c);
  ts_error__init(&errt);
  
  if (conn->keep_alive > 0) {
    conn->next_recv_time = ts_server__now(server) + (int)(conn->keep_alive * 1000 * 1.5);
  }
  
  if (ts_buf__get_length(conn->in_buf) == 0) {
    buf = data;
    buf_len = len;
    use_in_buf = FALSE;
  } else {
    ts_buf__write(conn->in_buf, data, len);
    buf = conn->in_buf->buf;
    buf_len = conn->in_buf->len;
    use_in_buf = TRUE;
  }

  while (1) {
    ts_error__reset(&errt);
    parsed = tm__parse_packet(buf, buf_len, &pkt_bytes_cnt, &remaining_length, &errt);

    if (errt.err) { // check the parse error first
      LOG_ERROR("[%s] Failed to read MQTT control packet", ts_server__get_conn_remote_host(server, c));
      tm_mqtt_conn__abort(server, c);
      goto done;
    }

    if (!parsed) {
      if (use_in_buf) {
        ts_buf__read(conn->in_buf, NULL, &total_bytes_consumed);
      } else {
        // append the left data to the in_buf
        ts_buf__write(conn->in_buf, buf, buf_len);
      }

      goto done; // more data is expected, do nothing now
    }

    // parse successfully
    err = tm_mqtt_conn__process_in_pkt(server, c, buf, pkt_bytes_cnt, pkt_bytes_cnt - remaining_length);
    if (err) {
      goto done;
    }

    buf += pkt_bytes_cnt;
    buf_len -= pkt_bytes_cnt;
    total_bytes_consumed += pkt_bytes_cnt;
  }

done:
  return;
}

void tm_mqtt_conn__write_cb(ts_t* server, ts_conn_t* c, int status, int can_write_more) {
  int err;
  tm_mqtt_conn_t* conn;
  tm_mqtt_msg_t* msg;
  const char* conn_id = ts_server__get_conn_remote_host(server, c);
  
  conn = (tm_mqtt_conn_t*) ts_server__get_conn_user_data(server, c);
  
  if (status != 0) {
    LOG_ERROR("[%s] Write failed: %d %s, abort the connection", conn_id, status, uv_strerror(status));
    // TODO: mark the fail state
    tm_mqtt_conn__abort(server, c);
  }
}

void tm_mqtt_conn__timer_cb(ts_t* server, ts_conn_t* c) {
  int err;
  tm_mqtt_conn_t* conn;
  const char* conn_id = ts_server__get_conn_remote_host(server, c);
  conn = (tm_mqtt_conn_t*) ts_server__get_conn_user_data(server, c);
  
  if (conn->next_recv_time > 0) {
    // When keep_alive is zero and the client connected, conn->next_recv_time should be zero
    unsigned long long now = ts_server__now(server);
    if (now > conn->next_recv_time) {
      LOG_ERROR("[%s] Client has been idle for too long(KeepAlive:%d), disconnect from it", conn_id, conn->keep_alive);
      tm_mqtt_conn__abort(server, c);
    }
  }
}

int tm_mqtt_conn__update_msg_state(ts_t* server, ts_conn_t* c, tm_mqtt_msg_t* msg) {
  int err;
  int old_state, new_state;
  tm_mqtt_conn_t* conn;
  const char* conn_id;
  
  conn_id = ts_server__get_conn_remote_host(server, c);
  conn = (tm_mqtt_conn_t*) ts_server__get_conn_user_data(server, c);
  
  old_state = tm_mqtt_msg__get_state(msg);
  err = tm_mqtt_msg__update_state(msg);
  if (err) {
    LOG_ERROR("[%s] Invalid message state: current state: %d", conn_id, old_state);
    tm_mqtt_conn__abort(server, c);
    return err;
  }
  new_state = tm_mqtt_msg__get_state(msg);
  
  tm__internal_msg_cb(conn->server, conn, msg, old_state, new_state);
  
  LOG_DEBUG_EX("[%s] Update message state: %d -> %d", conn_id, old_state, new_state);
  
  if (new_state == MSG_STATE_DONE) {
    tm_mqtt_session__remove_in_msg(conn->session, msg);
    tm__on_publish_received(conn->server, c, msg);
  }
  
  return 0;
}

static int tm_mqtt_conn__encode_remaining_length(int remaining_len, char* bytes) {
  char b = 0;
  int offset = 0;
  
  do {
    b = remaining_len % 128;
    remaining_len = remaining_len / 128;
    
    // if there are more data to encode, set the top bit of this byte
    if (remaining_len > 0) { b |= 128; }
    
    bytes[offset] = b;
    offset++;
  } while (remaining_len > 0);

  return offset;
}
static char* tm_mqtt_conn__encode_msg(tm_mqtt_msg_t* msg, int* len) {
  int pkt_id;
  int qos = tm_mqtt_msg__qos(msg);
  const char* topic;
  int topic_len;
  const char* payload;
  int payload_len;
  
  int remaining_len;
  char* pkt_bytes;
  int offset;
  
  pkt_id = msg->pkt_id;
  topic = msg->msg_core->topic->buf;
  topic_len = msg->msg_core->topic->len;
  payload = msg->msg_core->payload->buf;
  payload_len = msg->msg_core->payload->len;
  
  remaining_len = 2 + topic_len + payload_len;
  if (qos != 0) {
    remaining_len += 2;
  }
  
  pkt_bytes = (char*) ts__malloc(remaining_len + 1 + 4); // 1 for first byte, 4 for bytes of remaining length
  if (pkt_bytes == NULL) {
    return NULL;
  }
  
  pkt_bytes[0] = (0x03 << 4) | msg->flags;
  offset = 1;
  offset += tm_mqtt_conn__encode_remaining_length(remaining_len, pkt_bytes+1);
  
  uint162bytes_be(topic_len, pkt_bytes + offset);
  offset += 2;
  
  memcpy(pkt_bytes+offset, topic, topic_len);
  offset += topic_len;
  
  if (qos > 0) {
    uint162bytes_be(pkt_id, pkt_bytes + offset);
    offset += 2;
  }
  
  memcpy(pkt_bytes + offset, payload, payload_len);
  offset += payload_len;
  
  *len = offset;
  return pkt_bytes;
}

int tm_mqtt_conn__on_subscribed_msg_in(ts_t* server, ts_conn_t* c, tm_mqtt_msg_t* msg) {
  int err;
  tm_server_t* s;
  tm_mqtt_conn_t* conn;
  char* pkt_bytes;
  int pkt_bytes_len = 0;
  const char* conn_id = ts_server__get_conn_remote_host(server, c);
  conn = (tm_mqtt_conn_t*) ts_server__get_conn_user_data(server, c);
  s = conn->server;
  
  tm_mqtt_session__add_out_msg(conn->session, msg);
  
  msg->pkt_id = conn->next_pkt_id;
  conn->next_pkt_id++;
  
  pkt_bytes = tm_mqtt_conn__encode_msg(msg, &pkt_bytes_len);
  if (pkt_bytes == NULL) {
    LOG_ERROR("[%s] Out of memory", conn->session->client_id);
    tm_mqtt_conn__abort(server, c);
    return 0;
  }
  
  err = tm_mqtt_conn__send_packet(server, c, pkt_bytes, pkt_bytes_len, msg->pkt_id, msg);
  ts__free(pkt_bytes);
  
  if (err) {
    LOG_ERROR("[%s] Failed to publish message to the client: %d", conn->session->client_id, err);
    tm_mqtt_conn__abort(server, c);
    return 0;
  }
  
  return 0;
}