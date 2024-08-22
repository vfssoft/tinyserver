
#include "mqtt_conn.h"
#include "mqtt_packets.h"

#include <internal/ts_mem.h>
#include <internal/ts_log.h>


tm_mqtt_conn_t* tm_mqtt_conn__create(tm_server_t* s) {
  tm_mqtt_conn_t* conn;
  
  conn = (tm_mqtt_conn_t*) ts__malloc(sizeof(tm_mqtt_conn_t));
  if (conn == NULL) {
    return NULL;
  }
  memset(conn, 0, sizeof(tm_mqtt_conn_t));

  tm_packet_decoder__set(&(conn->decoder), NULL, 0);
  ts_error__init(&(s->err));

  conn->server = s;
  
  return conn;
}

int tm_mqtt_conn__destroy(tm_mqtt_conn_t* conn) {
  if (conn) {
    if (conn->session) {
      // TODO:
    }
    
    if (conn->in_buf) {
      ts_buf__destroy(conn->in_buf);
    }
    
    ts__free(conn);
  }
  
  return 0;
}

void tm_mqtt_conn__abort(ts_t* server, ts_conn_t* c) {
  ts_server__disconnect(server, c);
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
      if (conn->session->connected) {
        LOG_ERROR("[%s] Already connected but receive another CONNECT", ts_server__get_conn_remote_host(server, c));
        tm_mqtt_conn__abort(server, c);
        return 0;
      }

      return tm_mqtt_conn__process_connect(server, c, pkt_bytes, pkt_bytes_len, variable_header_off);

    case PKT_TYPE_PUBLISH:
      break;

    case PKT_TYPE_PUBACK:
      break;

    case PKT_TYPE_PUBREC:
      break;

    case PKT_TYPE_PUBREL:
      break;

    case PKT_TYPE_PUBCOMP:
      break;

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
int tm_mqtt_conn__data_in(ts_t* server, ts_conn_t* c, const char* data, int len) {
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
  conn->last_active_time = ts_server__now(server);
  
  return 0;
}