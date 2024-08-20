
#include "mqtt_conn.h"
#include "mqtt_packets.h"

#include <internal/ts_mem.h>

tm_mqtt_conn_t* tm_mqtt_conn__create(tm_server_t* s) {
  tm_mqtt_conn_t* conn;
  
  conn = (tm_mqtt_conn_t*) ts__malloc(sizeof(tm_mqtt_conn_t));
  if (conn == NULL) {
    return NULL;
  }
  memset(conn, 0, sizeof(tm_mqtt_conn_t));

  ts_error__init(&(s->err));

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

static int tm_mqtt_conn__process_connect(tm_mqtt_conn_t* conn, const char* pkt_bytes, int pkt_bytes_len, int variable_header_off) {
  int err;



}

static int tm_mqtt_conn__process_in_pkt(tm_mqtt_conn_t* conn, const char* pkt_bytes, int pkt_bytes_len, int variable_header_off) {
  int pkt_type = (pkt_bytes[0] & 0xF0) >> 4;

  if (!conn->connected && pkt_type != PKT_TYPE_CONNECT) {
    ts_error__set_msg(&(conn->err), TS_ERR_PROTOCOL_ERROR, "First packet should be CONNECT");
    return TS_ERR_PROTOCOL_ERROR;
  }

  switch (pkt_type) {

    case PKT_TYPE_CONNECT:
      if (conn->connected) {
        ts_error__set_msg(&(conn->err), TS_ERR_PROTOCOL_ERROR, "Already connected but receive another CONNECT");
        return TS_ERR_PROTOCOL_ERROR;
      }

      return tm_mqtt_conn__process_connect(conn, pkt_bytes, pkt_bytes_len, variable_header_off);

    case PKT_TYPE_CONNACK:
      break;

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
      break;

    case PKT_TYPE_SUBACK:
      break;

    case PKT_TYPE_UNSUBSCRIBE:
      break;

    case PKT_TYPE_UNSUBACK:
      break;

    case PKT_TYPE_PINGREQ:
      break;

    case PKT_TYPE_PINGRESP:
      break;

    case PKT_TYPE_DISCONNECT:
      break;

    default:
      ts_error__set_msgf(&(conn->err), TS_ERR_MALFORMED_MQTT_PACKET, "Unkonwn Control Packet Type(%d)", pkt_type);
      return TS_ERR_MALFORMED_MQTT_PACKET;
  }
  return 0;
}
int tm_mqtt_conn__data_in(tm_mqtt_conn_t* conn, const char* data, int len) {
  int err;
  int total_bytes_consumed = 0;
  BOOL parsed = FALSE;
  int pkt_bytes_cnt = 0;
  unsigned int remaining_length = 0;
  BOOL use_in_buf = FALSE;
  const char* buf;
  int buf_len;

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
    ts_error__reset(&(conn->err));
    parsed = tm__parse_packet(buf, buf_len, &pkt_bytes_cnt, &remaining_length, &conn->err);

    if (conn->err.err) { // check the parse error first
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
    err = tm_mqtt_conn__process_in_pkt(conn, buf, pkt_bytes_cnt, pkt_bytes_cnt - remaining_length);
    if (err) {
      goto done;
    }

    buf += pkt_bytes_cnt;
    buf_len -= pkt_bytes_cnt;
    total_bytes_consumed += pkt_bytes_cnt;
  }

done:
  if (conn->err.err) {
    // TODO: disconnect from the client
  }
}