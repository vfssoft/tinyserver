
#include "mqtt_conn.h"
#include "mqtt_packets.h"

#include <internal/ts_mem.h>
#include <internal/ts_log.h>
#include <internal/ts_crypto.h>

#include <inttypes.h>

#define MAX_CLIENT_ID_LEN 512

// Connection Return Code
#define RETURN_CODE_ACCEPTED                       0x00
#define RETURN_CODE_UNACCEPTABLE_PROTOCOL_VERSION  0x01
#define RETURN_CODE_IDENTIFIER_REJECTED            0x02
#define RETURN_CODE_SERVER_UNAVAILABLE             0x03
#define RETURN_CODE_BAD_USER_OR_PASSWORD           0x04
#define RETURN_CODE_NOT_AUTHORIZED                 0x05

static void tm_mqtt_conn__generate_client_id(ts_t* server, ts_conn_t* c, char* client_id) {
  // Parts: "tmp_client_id", remote host, address of conn, random
  const char *remote_host = ts_server__get_conn_remote_host(server, c);
  unsigned long long random_val = crypto__random_int64();
  
  sprintf(client_id, "tmp_client_id_%s_%" PRIu64 "%" PRIu64, remote_host, (uint64_t)c, (uint64_t) random_val);
}

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
static int tm_mqtt_conn__send_connack(ts_t* server, ts_conn_t* c, BOOL sp, int return_code) {
  char connack[4] = { 0x20, 0x01, (char)(sp & 0xFF), (char)(return_code & 0xFF) };
  return ts_server__write(server, c, connack, 4);
}
static void tm_mqtt_conn__abort(ts_t* server, ts_conn_t* c) {
  ts_server__disconnect(server, c);
}
static void tm_mqtt_conn__send_connack_abort(ts_t* server, ts_conn_t* c, int return_code) {
  tm_mqtt_conn__send_connack(server, c, FALSE, return_code); // ignore error
  tm_mqtt_conn__abort(server, c);
}

static int tm_mqtt_conn__process_connect(ts_t* server, ts_conn_t* c, const char* pkt_bytes, int pkt_bytes_len, int variable_header_off) {
  int err;
  tm_mqtt_conn_t* conn;
  tm_server_t* s;
  int tmp_len;
  const char* tmp_ptr = "";
  int tmp_val;
  int connect_flags = 0;
  char* username = NULL;
  char* password = NULL;
  BOOL auth_ok = FALSE;
  char client_id[MAX_CLIENT_ID_LEN];
  BOOL session_present = FALSE;
  BOOL clean_session;
  tm_packet_decoder_t* decoder;
  const char* conn_id = ts_server__get_conn_remote_host(server, c);
  
  conn = (tm_mqtt_conn_t*) ts_server__get_conn_user_data(server, c);
  s = conn->server;
  decoder = &conn->decoder;
  
  tm_packet_decoder__set(decoder, pkt_bytes + variable_header_off, pkt_bytes_len - variable_header_off);

  err = tm_packet_decoder__read_int16_string(decoder, &tmp_len, &tmp_ptr);
  if (err || tmp_len != 4 || strcmp(tmp_ptr, "MQTT") != 0) {
    LOG_ERROR("[%s] Invalid protocol name", conn_id);
    tm_mqtt_conn__abort(server, c);
    goto done;
  }

  err = tm_packet_decoder__read_byte(decoder, &tmp_val);
  if (err || tmp_val != 4) {
    LOG_ERROR("[%s] Invalid protocol level", conn_id);
    tm_mqtt_conn__send_connack_abort(server, c, RETURN_CODE_UNACCEPTABLE_PROTOCOL_VERSION);
    goto done;
  }

  err = tm_packet_decoder__read_byte(decoder, &connect_flags);
  if (err || (connect_flags & 0x01) != 0) {
    LOG_ERROR("[%s] Invalid Connect Flags", conn_id);
    tm_mqtt_conn__abort(server, c);
    goto done;
  }
  clean_session = (connect_flags & 0x02) == 0x02;

  err = tm_packet_decoder__read_int16(decoder, &(conn->keep_alive));
  if (err) {
    LOG_ERROR("[%s] Invalid Keep Alive", conn_id);
    tm_mqtt_conn__abort(server, c);
    goto done;
  }

  err = tm_packet_decoder__read_int16_string(decoder, &tmp_len, &tmp_ptr);
  if (err) {
    LOG_ERROR("[%s] Invalid Client Id", conn_id);
    tm_mqtt_conn__abort(server, c);
    goto done;
  }
  if (tmp_len >= MAX_CLIENT_ID_LEN) {
    LOG_ERROR("[%s] Client Id is too long", conn_id);
    tm_mqtt_conn__send_connack_abort(server, c, RETURN_CODE_IDENTIFIER_REJECTED);
    goto done;
  }
  memcpy(client_id, tmp_ptr, tmp_len);
  if (tmp_len == 0) {
    // empty client id
    if (!clean_session) {
      LOG_ERROR("[%s] Zero client id but want to persist session state", conn_id);
      tm_mqtt_conn__send_connack_abort(server, c, RETURN_CODE_IDENTIFIER_REJECTED);
      goto done;
    }
    tm_mqtt_conn__generate_client_id(server, c, client_id);
  } else {
    // TODO: validate the client id
  }
  
  conn->session = tm__find_session(s, client_id);
  session_present = !clean_session && conn->session != NULL;
  
  if (clean_session && conn->session) {
    LOG_DEBUG("[%s] Clear the previous session state", conn_id);
    tm__remove_session(s, conn->session);
    conn->session = NULL;
  }
  if (conn->session == NULL) {
    LOG_DEBUG("[%s] Create new session for the current client", conn_id);
    conn->session = tm__create_session(s, client_id);
    if (conn->session == NULL) {
      LOG_ERROR("[%s] Out of memory", conn_id);
      tm_mqtt_conn__abort(server, c);
      goto done;
    }
  }
  conn->session->clean_session = clean_session;

  if ((connect_flags & 0x04) == 0x04) { // will flag
    // TODO: will topic
    err = tm_packet_decoder__read_int16_string(decoder, &tmp_len, &tmp_ptr);
    if (err) {
      LOG_ERROR("[%s] Invalid Will Topic", conn_id);
      tm_mqtt_conn__abort(server, c);
      goto done;
    }

    // TODO: Will Message
    err = tm_packet_decoder__read_int16_string(decoder, &tmp_len, &tmp_ptr);
    if (err) {
      LOG_ERROR("[%s] Invalid Will Message", conn_id);
      tm_mqtt_conn__abort(server, c);
      goto done;
    }
  } else {
    // TODO: validate the Will QoS, Will Retain flags
  }

  if ((connect_flags & 0x40) == 0x40) {
    err = tm_packet_decoder__read_int16_string(decoder, &tmp_len, &tmp_ptr);
    if (err) {
      LOG_ERROR("[%s] Invalid Username", conn_id);
      tm_mqtt_conn__abort(server, c);
      goto done;
    }
    
    username = (char*) ts__malloc(tmp_len);
    if (username) {
      LOG_ERROR("[%s] Out of memory", conn_id);
      tm_mqtt_conn__abort(server, c);
      goto done;
    }
    memcpy(username, tmp_ptr, tmp_len);
  }
  if ((connect_flags & 0x80) == 0x80) {
    err = tm_packet_decoder__read_int16_string(decoder, &tmp_len, &tmp_ptr);
    if (err) {
      LOG_ERROR("[%s] Invalid Password", conn_id);
      tm_mqtt_conn__abort(server, c);
      goto done;
    }
  
    password = (char*) ts__malloc(tmp_len);
    if (password) {
      LOG_ERROR("[%s] Out of memory", conn_id);
      tm_mqtt_conn__abort(server, c);
      goto done;
    }
    memcpy(password, tmp_ptr, tmp_len);
  }
  
  // auth user
  s->callbacks.auth_cb(s->callbacks.cb_ctx, s, username, password, &auth_ok);
  if (!auth_ok) {
    LOG_ERROR("[%s] Authorized failed", conn_id);
    tm_mqtt_conn__send_connack_abort(server, c, RETURN_CODE_BAD_USER_OR_PASSWORD);
    goto done;
  }

  err = tm_mqtt_conn__send_connack(server, c, session_present, RETURN_CODE_ACCEPTED);
  if (err) {
    tm_mqtt_conn__abort(server, c);
    goto done;
  }

  conn->session->connected = TRUE;

done:
  
  if (username) {
    ts__free(username);
  }
  if (password) {
    ts__free(password);
  }
  
  return err;
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
  return 0;
}