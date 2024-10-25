#include "mqtt_conn.h"
#include "mqtt_utils.h"

#include <tm.h>
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

static int tm_mqtt_conn__send_connack(ts_t* server, ts_conn_t* c, BOOL sp, int return_code) {
  tm_mqtt_conn_t* conn = (tm_mqtt_conn_t*) ts_server__get_conn_user_data(server, c);
  char connack[4] = { 0x20, 0x02, (char)(sp & 0xFF), (char)(return_code & 0xFF) };
  LOG_DUMP(connack, 4, "[%s][%s] Send [CONNACK]", ts_server__get_conn_remote_host(server, c), conn->session == NULL ? "CLIENT_ID_PLACEHOLDER" : conn->session->client_id);
  return tm_mqtt_conn__send_packet(server, c, connack, 4, -1, NULL);
}

static void tm_mqtt_conn__send_connack_abort(ts_t* server, ts_conn_t* c, int return_code) {
  tm_mqtt_conn__send_connack(server, c, FALSE, return_code); // ignore error
  tm_mqtt_conn__abort(server, c);
}

int tm_mqtt_conn__process_connect(ts_t* server, ts_conn_t* c, const char* pkt_bytes, int pkt_bytes_len, int variable_header_off) {
  int err;
  tm_mqtt_conn_t* conn;
  tm_server_t* s;
  ts_conn_t* prev_c;
  tm_mqtt_conn_t* prev_conn;
  int tmp_len;
  const char* tmp_ptr = "";
  int tmp_val;
  int connect_flags = 0;
  int will_qos;
  int will_retain;
  ts_buf_t* will_topic = NULL;
  ts_buf_t* username = NULL;
  ts_buf_t* password = NULL;
  BOOL auth_ok = FALSE;
  char client_id[MAX_CLIENT_ID_LEN];
  BOOL session_present = FALSE;
  BOOL clean_session;
  tm_packet_decoder_t* decoder;
  ts_error_t errt;
  const char* conn_id = ts_server__get_conn_remote_host(server, c);
  
  conn = (tm_mqtt_conn_t*) ts_server__get_conn_user_data(server, c);
  s = conn->server;
  decoder = &conn->decoder;
  
  LOG_DUMP(pkt_bytes, pkt_bytes_len, "[%s] Receive [CONNECT]", ts_server__get_conn_remote_host(server, c));
  
  ts_error__init(&errt);
  tm_packet_decoder__set(decoder, pkt_bytes + variable_header_off, pkt_bytes_len - variable_header_off);
  
  err = tm_packet_decoder__read_int16_string(decoder, &tmp_len, &tmp_ptr);
  if (err || tmp_len != 4 || strncmp(tmp_ptr, "MQTT", 4) != 0) {
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
  client_id[tmp_len] = 0;

  LOG_VERB("[%s][%s] New MQTT client is coming", conn_id, client_id);

  if (tmp_len == 0) {
    // empty client id
    if (!clean_session) {
      LOG_ERROR("[%s][%s] Zero client id but want to persist session state", conn_id, client_id);
      tm_mqtt_conn__send_connack_abort(server, c, RETURN_CODE_IDENTIFIER_REJECTED);
      goto done;
    }
    tm_mqtt_conn__generate_client_id(server, c, client_id);
  } else {
    // TODO: validate the client id
  }
  
  conn->session = tm__find_session(s, client_id);
  session_present = !clean_session && conn->session != NULL;
  
  if (conn->session && tm_mqtt_session__conn(conn->session)) {
    LOG_VERB("[%s][%s] The current session is attached to a another client with the same client id, disconnect the previous client", conn_id, client_id);
    prev_c = tm_mqtt_session__conn(conn->session);
    prev_conn = (tm_mqtt_conn_t*) ts_server__get_conn_user_data(server, prev_c);

    prev_conn->session = NULL; // un-reference the current session
    tm_mqtt_conn__abort(server, prev_c);
    clean_session = 1; // force a new session for the current connection
  }

  if (clean_session && conn->session) {
    LOG_DEBUG("[%s][%s] Clear the previous session state", conn_id, client_id);
    tm__remove_session(s, conn->session);
    conn->session = NULL;
  }
  if (conn->session == NULL) {
    LOG_DEBUG("[%s][%s] Create new session for the current client", conn_id, client_id);
    conn->session = tm__create_session(s, client_id);
    if (conn->session == NULL) {
      LOG_ERROR("[%s][%s] Out of memory", conn_id,  client_id);
      tm_mqtt_conn__abort(server, c);
      goto done;
    }
  }
  conn->session->clean_session = clean_session;
  
  will_qos = (connect_flags & 0x18) >> 3;
  will_retain = (connect_flags & 0x20) == 0x20;
  if ((connect_flags & 0x04) == 0x04) { // will flag
    if (!tm__is_valid_qos(will_qos)) {
      LOG_ERROR("[%s][%s] Invalid Will QoS", conn_id, client_id);
      tm_mqtt_conn__abort(server, c);
      goto done;
    }
    
    err = tm_packet_decoder__read_int16_string(decoder, &tmp_len, &tmp_ptr);
    if (err) {
      LOG_ERROR("[%s][%s] Invalid Will Topic", conn_id, client_id);
      tm_mqtt_conn__abort(server, c);
      goto done;
    }
    err = tm_topics__valid_topic_name(tmp_ptr, tmp_len, &errt);
    if (err) {
      LOG_ERROR("[%s][%s] Invalid Will Topic: %s", conn_id, client_id, errt.msg);
      tm_mqtt_conn__abort(server, c);
      goto done;
    }
    will_topic = tm__string(tmp_ptr, tmp_len);
    if (will_topic == NULL) {
      LOG_ERROR("[%s][%s] Out of memory", conn_id, client_id);
      tm_mqtt_conn__abort(server, c);
      goto done;
    }
    
    err = tm_packet_decoder__read_int16_string(decoder, &tmp_len, &tmp_ptr);
    if (err) {
      LOG_ERROR("[%s][%s] Invalid Will Message", conn_id, client_id);
      tm_mqtt_conn__abort(server, c);
      goto done;
    }
    
    conn->will = tm__create_message(
        s,
        will_topic->buf,
        tmp_ptr, tmp_len, // payload
        0,
        will_qos,
        will_retain
    );
    if (conn->will == NULL) {
      LOG_ERROR("[%s][%s] Invalid Will Message", conn_id, client_id);
      tm_mqtt_conn__abort(server, c);
      goto done;
    }
    
  } else {
    if (will_qos != 0 || will_retain == 1) {
      LOG_ERROR("[%s][%s] Invalid Reserved flags", conn_id, client_id);
      tm_mqtt_conn__abort(server, c);
      goto done;
    }
  }
  
  if ((connect_flags & 0x40) == 0x40) {
    if ((connect_flags & 0x80) == 0) {
      LOG_ERROR("[%s][%s] Username flags is on, but Password flag is off", conn_id, client_id);
      tm_mqtt_conn__abort(server, c);
      goto done;
    }
    
    err = tm_packet_decoder__read_int16_string(decoder, &tmp_len, &tmp_ptr);
    if (err) {
      LOG_ERROR("[%s][%s] Invalid Username", conn_id, client_id);
      tm_mqtt_conn__abort(server, c);
      goto done;
    }
    
    username = tm__string(tmp_ptr, tmp_len);
    if (username == NULL) {
      LOG_ERROR("[%s][%s] Out of memory", conn_id, client_id);
      tm_mqtt_conn__abort(server, c);
      goto done;
    }
  
    err = tm_packet_decoder__read_int16_string(decoder, &tmp_len, &tmp_ptr);
    if (err) {
      LOG_ERROR("[%s][%s] Invalid Password", conn_id, client_id);
      tm_mqtt_conn__abort(server, c);
      goto done;
    }
  
    password = tm__string(tmp_ptr, tmp_len);
    if (password == NULL) {
      LOG_ERROR("[%s][%s] Out of memory", conn_id, client_id);
      tm_mqtt_conn__abort(server, c);
      goto done;
    }
    
  } else {
    if ((connect_flags & 0x80) == 0x80) {
      LOG_ERROR("[%s][%s] Username flags is off, but Password flag is on", conn_id, client_id);
      tm_mqtt_conn__abort(server, c);
      goto done;
    }
  }
  
  // auth user
  tm__internal_auth_user_cb(
      s,
      username == NULL ? NULL : username->buf,
      password == NULL ? NULL : password->buf,
      &auth_ok
  );
  if (!auth_ok) {
    LOG_ERROR("[%s][%s] Authorized failed", conn_id, client_id);
    tm_mqtt_conn__send_connack_abort(server, c, RETURN_CODE_BAD_USER_OR_PASSWORD);
    goto done;
  }
  
  err = tm_mqtt_conn__send_connack(server, c, session_present, RETURN_CODE_ACCEPTED);
  if (err) {
    tm_mqtt_conn__abort(server, c);
    goto done;
  }
  
  tm_mqtt_session__attach(conn->session, c);
  
  tm__internal_connected_cb(s, c);
  
  if (conn->will) {
    if (tm_mqtt_msg__retain(conn->will)) {
      tm__on_retain_message(conn->server, c, conn->will);
    }
    tm__internal_msg_cb(conn->server, conn, conn->will, MSG_STATE_RECEIVE_PUB, MSG_STATE_DONE);
  }
  LOG_INFO("[%s][%s] Connected", conn_id, conn->session->client_id);
  
done:
  
  if (username) {
    ts_buf__destroy(username);
  }
  if (password) {
    ts_buf__destroy(password);
  }
  if (will_topic) {
    ts_buf__destroy(will_topic);
  }
  
  return err;
}
