
#include "ts_ws.h"


#define TS_WS_OPCODE_CONTINUATION_FRAME 0
#define TS_WS_OPCODE_TEXT_FRAME         1
#define TS_WS_OPCODE_BINARY_FRAME       2
// 3-7 are reserved
#define TS_WS_OPCODE_CONNECTION_CLOSE   8
#define TS_WS_OPCODE_PING               9
#define TS_WS_OPCODE_PONG               10

#define TS_WS_STATUS_CODE_NORMAL_CLOSURE        1000
#define TS_WS_STATUS_CODE_GOING_AWAY            1001
#define TS_WS_STATUS_CODE_PROTOCOL_ERROR        1002
#define TS_WS_STATUS_CODE_DATA_UNACCEPTABLE     1003
// 1004-1006 reserved
#define TS_WS_STATUS_CODE_MSG_TYPE_INCONSISTENT 1007
#define TS_WS_STATUS_CODE_POLICY_VIOLATED       1008
#define TS_WS_STATUS_CODE_MSG_TOO_BIG           1009
#define TS_WS_STATUS_CODE_EXTENSION_NEGOTIATE   1010
#define TS_WS_STATUS_CODE_UNEXPECTED_CONDITION  1011


static char* ts_ws__parse_line(char* p, char* ret_line) {
  char* end_of_line = NULL;
  int line_len = 0;
  
  end_of_line = strstr(p, "\r\n");
  if (end_of_line == NULL) {
    ret_line[0] = '\0';
    return p;
  }
  
  line_len = (int)(end_of_line - p);
  memcpy(ret_line, p, line_len);
  ret_line[line_len] = '\0';
  
  return end_of_line + 2; // 2: skip the CRLF
}
static void ts_ws__parse_request_line(char* line, char** method, char** url, char** version) {
  *method = NULL;
  *url = NULL;
  *version = NULL;
  
  int sp1 = -1;
  int sp2 = -1;
  
  for (int i = 0; i < strlen(line); i++) {
    if (line[i] == ' ') {
      if (sp1 < 0) {
        sp1 = i;
      } else {
        sp2 = i;
        break;
      }
    }
  }
  
  if (sp1 > 0 && sp2 > 0) {
    // it's only valid if we found exactly two spaces
    *method = line;
    line[sp1] = '\0';
    *url = line + sp1 + 1;
    line[sp2] = '\0';
    *version = line + sp2 + 1;
  }
}
static void ts_ws__parse_header(char* line, char** key, char** value) {
  *key = line;
  *value = NULL;
  
  char* p = line;
  while (p != NULL && *p != ':') p++;
  if (p == NULL) return;
  
  *p = '\0';
  *value = p + 1;

  *key = str_trim(*key, " \t");
  *value = str_trim(*value, " \t");
}

static int ts_ws_frame__init(ts_ws_frame_t* frame) {
  memset(frame, 0, sizeof(ts_ws_frame_t));
  
  frame->payload_data = ts_buf__create(0);
  if (frame->payload_data == NULL) {
    return TS_ERR_OUT_OF_MEMORY;
  }
  
  return 0;
}
static int ts_ws_frame__destroy(ts_ws_frame_t* frame) {
  if (frame->payload_data) {
    ts_buf__destroy(frame->payload_data);
    frame->payload_data = NULL;
  }
  return 0;
}
static int ts_ws__decode_frame(ts_ws_t* ws, ts_ws_frame_t* frame, BOOL* ok) {
  int err = 0;
  ts_buf_t* buf = ws->in_buf;
  int offset = 0; // next byte to read
  BOOL masked = FALSE;
  char masking_key[4];
  
  *ok = FALSE;
  
  if (buf->len < 2) return 0;
  
  frame->fin    = (buf->buf[0] & 0x80) == 0x80;
  frame->opcode = (buf->buf[0] & 0x0F);
  masked        = (buf->buf[1] & 0x80) == 0x80;
  
  unsigned long long payload_len = buf->buf[1] & 0x7F;
  if (payload_len <= 125) {
    // payload_len is current value
    offset = 2;
  } else if (payload_len == 126) {
    if (buf->len < 4) {
      return 0;
    }
    payload_len = bytes2uint16_be(buf->buf + 2);
    offset = 4;
  } else if (payload_len == 127) {
    if (buf->len < 10) {
      return 0;
    }
    payload_len = bytes2uint64_be(buf->buf + 2);
    offset = 10;
  }
  
  if (masked) {
    if (offset + 4 > buf->len) return 0;
    memcpy(masking_key, buf->buf + offset, 4);
    offset += 4;
  } else {
    ts_error__set_msg(&(ws->err), TS_ERR_INVALID_WS_FRAME, "Websocket frame is not masked");
    goto done;
  }
  
  if (offset + payload_len > buf->len) return 0;
  
  ts_buf__set(frame->payload_data, buf->buf + offset, payload_len);
  offset += payload_len;
  
  ts_buf__read(buf, NULL, &offset);
  
  // unmake the data
  for (int i = 0; i < payload_len; i++) {
    frame->payload_data->buf[i] ^= masking_key[i%4];
  }
  
  *ok = TRUE;
  
done:
  return ws->err.err;
}
static int ts_ws__encode_frame(ts_ws_t* ws, int opcode, const char* payload, int payload_len, ts_buf_t* output) {
  // for simply, encode all payload into a single frame
  int err;
  char ws_header_buf[10];
  int ws_header_len = 0;

  ws_header_buf[0] = 0x80 | (char)opcode; // Fin, opcode(Binary, Text).

  if (payload_len <= 125) {
    ws_header_buf[1]= (char)(payload_len & 0x7F);
    ws_header_len = 2;
  } else if (payload_len <= 0xFFFF) {
    ws_header_buf[1]= 126;
    uint162bytes_be(payload_len, ws_header_buf + 2);
    ws_header_len = 4;
  } else {
    // we're the writer, we will never send data more than max int 32
    ws_header_buf[1]= 127;
    uint642bytes_be(payload_len, ws_header_buf + 2);
    ws_header_len = 10;
  }
  
  err = ts_buf__write(output, ws_header_buf, ws_header_len);
  if (err) {
    goto done;
  }
  
  // As the server side, the application data is not masked.
  // no masking key
  
  err = ts_buf__write(output, payload, payload_len);
  if (err) {
    goto done;
  }
  
done:
  return err;
}
static void ts_ws__decode_close_error(ts_ws_t* ws, ts_ws_frame_t* frame) {
  // it must contain as least two-byte integer if application data is included
  if (frame->payload_data->len >= 2) {
    int status_code = frame->payload_data->buf[0] << 8 | frame->payload_data->buf[1];
    char* reason = (char*)"no reason";
    if (frame->payload_data->len > 2) {
      reason = frame->payload_data->buf + 2;
    }
    ts_error__set_msgf(&(ws->err), TS_ERR_WS_CLOSED, "status code: %d, reason: %s", status_code, reason);
  }
}

int ts_ws__init(ts_ws_t* ws, ts_tcp_conn_t* conn) {
  ts_server_listener_t* listener = conn->listener;
  ts_server_t* server = listener->server;
  
  ws->conn = conn;
  ws->state = TS_STATE_HANDSHAKING;
  ts_error__init(&ws->err);
  
  ws->in_buf = ts_buf__create(0);
  if (ws->in_buf == NULL) {
    ts_error__set(&(ws->err), TS_ERR_OUT_OF_MEMORY);
    goto done;
  }
  
done:
  if (ws->err.err) {
    LOG_ERROR("[%s][WS] Initial WS for connection failed: %d %s", conn->remote_addr, ws->err.err, ws->err.msg);
  }
  return 0;
}
int ts_ws__destroy(ts_ws_t* ws) {
  ws->conn = NULL;
  return 0;
}

int ts_ws__state(ts_ws_t* ws) {
  return ws->state;
}

int ts_ws__handshake(ts_ws_t* ws, ts_ro_buf_t* input, ts_buf_t* output) {
  int err;
  char *p, *method, *url, *version;
  char *header_name, *header_value;
  char* end_of_headers = NULL;
  char line[1024];
  char seckey[80] = { 0 };
  char seckey_accept[20];
  char sub_protocols[64] = { 0 };
  char resp_buf[2048] = { 0 };

  BOOL req_line_parsed = FALSE;
  BOOL has_host_hdr = FALSE;
  BOOL has_upgrade_hdr = FALSE;
  BOOL has_connection_hdr = FALSE;
  BOOL has_version_hdr = FALSE;

  ts_tcp_conn_t* conn = ws->conn;
  ts_server_t* server = conn->listener->server;
  
  LOG_VERB("[%s][WS] Websocket handshaking", conn->remote_addr);
  
  ts_buf__write_str(ws->in_buf, input->buf, input->len);
  
  end_of_headers = strstr(ws->in_buf->buf, "\r\n\r\n");
  if (end_of_headers == NULL) {
    return 0; // more data is needed
  }
  
  p = ws->in_buf->buf;
  while (p < end_of_headers) {
    p = ts_ws__parse_line(p, line);
    
    if (line[0] == 0) {
      break; // no more lines
    }
    
    if (!req_line_parsed) {
      req_line_parsed = TRUE;
      // parse the first line of the HTTP Upgrade request
      // Example: GET /chat HTTP/1.1
      ts_ws__parse_request_line(line, &method, &url, &version);
      if (method == NULL || url == NULL || version == NULL || stricmp(method, "GET") != 0 || stricmp(version, "HTTP/1.1") != 0) {
        ts_error__set_msg(&(ws->err), TS_ERR_INVALID_WS_HEADERS, "Invalid Websocket Upgrade request");
        goto bad_request;
      }
      //strcmp(url_buf, url);
      // TODO: handle the url
    } else {
      ts_ws__parse_header(line, &header_name, &header_value);
      if (header_name == NULL || header_value == NULL) {
        ts_error__set_msg(&(ws->err), TS_ERR_INVALID_WS_HEADERS, "Invalid Websocket header");
        goto bad_request;
      }

      if (stricmp(header_name, "Host") == 0) {
        has_host_hdr = TRUE;
        // nothing now
      } else if (stricmp(header_name, "Upgrade") == 0) {
        if (strcmp(header_value, "websocket") != 0) {
          ts_error__set_msgf(&(ws->err), TS_ERR_INVALID_WS_HEADERS, "Invalid Websocket Upgrade header value: %s", header_value);
          goto bad_request;
        }
        has_upgrade_hdr = TRUE;
      } else if (stricmp(header_name, "Connection") == 0) {
        if (stricmp(header_value, "Upgrade") != 0) {
          ts_error__set_msgf(&(ws->err), TS_ERR_INVALID_WS_HEADERS, "Invalid Websocket Connection header value: %s", header_value);
          goto bad_request;
        }
        has_connection_hdr = TRUE;
      } else if (stricmp(header_name, "Sec-WebSocket-Key") == 0) {
        strcpy(seckey, header_value);
      } else if (stricmp(header_name, "Sec-WebSocket-Version") == 0) {
        if (stricmp(header_value, "13") != 0) {
          ts_error__set_msgf(&(ws->err), TS_ERR_INVALID_WS_HEADERS, "Invalid Websocket Sec-WebSocket-Version header value: %s", header_value);
          goto bad_request;
        }
        has_version_hdr = TRUE;
      } else if (stricmp(header_name, "Sec-WebSocket-Protocol") == 0) {
        strcpy(sub_protocols, header_value);
      }

      // ignore: Origin, Sec-WebSocket-Extensions
    }
  }

  if (!has_host_hdr || !has_upgrade_hdr || !has_connection_hdr || strlen(seckey) == 0 || !has_version_hdr) {
    ts_error__set_msg(&(ws->err), TS_ERR_INVALID_WS_HEADERS, "Invalid Websocket important header missed");
    goto bad_request;
  }

  // calc sec key accept
  strcpy(seckey + strlen(seckey), "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
  crypto__sha1(seckey, strlen(seckey), seckey_accept);
  b64_encode(seckey_accept, 20, seckey); // reuse seckey buf to store the encoded Sec-WebSocket-Accept

  // send 101
  sprintf(
      resp_buf,

      "HTTP/1.1 101 Switching Protocols\r\n"
      "Upgrade: websocket\r\n"
      "Connection: Upgrade\r\n"
      "Sec-WebSocket-Accept: %s\r\n"
      "\r\n",

      seckey
  );

  ts_buf__write(output, resp_buf, strlen(resp_buf));
  ws->state = TS_STATE_CONNECTED;
  LOG_VERB("[%s][WS] Websocket handshake ok", conn->remote_addr);

bad_request:
  if (ws->err.err) {
    // send 400
    sprintf(
        resp_buf,
        "HTTP/1.1 400 Bad Request\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n"
        "\r\n"
    );
    ts_buf__write(output, resp_buf, strlen(resp_buf));
  }

done:
  if (ws->err.err) {
    LOG_ERROR("[%s][WS] Websocket handshake failed: %d %s", conn->remote_addr, ws->err.err, ws->err.msg);
    ws->state = TS_STATE_DISCONNECTED;
  }
  ts_buf__set_length(ws->in_buf, 0); // clear buf
  input->len = 0;
  return ws->err.err;
}

int ts_ws__unwrap(ts_ws_t* ws, ts_ro_buf_t* input, ts_buf_t* output_app, ts_buf_t* output_sock) {
  int err = 0;
  ts_ws_frame_t frame;
  BOOL ok = FALSE;
  
  err = ts_ws_frame__init(&frame);
  if (err) {
    ts_error__set(&(ws->err), TS_ERR_OUT_OF_MEMORY);
    goto done;
  }
  
  ts_buf__write(ws->in_buf, input->buf, input->len);
  
  while (1) {
    err = ts_ws__decode_frame(ws, &frame, &ok);
    if (err) {
      goto done;
    }
    
    if (!ok) {
      // no more frame to decode
      goto done;
    }
    
    switch (frame.opcode) {
      case TS_WS_OPCODE_CONTINUATION_FRAME:
        if (frame.fin == 1) {
          ts_error__set_msg(&(ws->err), TS_ERR_INVALID_WS_FRAME, "Continuation frame should set FIN to 0");
          goto done;
        }
        // go through
        
      case TS_WS_OPCODE_TEXT_FRAME:
      case TS_WS_OPCODE_BINARY_FRAME:
        ts_buf__write(output_app, frame.payload_data->buf, frame.payload_data->len);
        break;
      
      case TS_WS_OPCODE_CONNECTION_CLOSE:
        if (ws->state == TS_STATE_DISCONNECTING) {
          ws->state = TS_STATE_DISCONNECTED;
          goto done;
        } else {
          ws->state = TS_STATE_DISCONNECTING;
          ts_ws__decode_close_error(ws, &frame);
          err = ts_ws__encode_frame(ws, TS_WS_OPCODE_CONNECTION_CLOSE, NULL, 0, output_sock);
          if (err) {
            goto done;
          }
        }
        break;
      
      case TS_WS_OPCODE_PING:
        // send pong
        err = ts_ws__encode_frame(ws, TS_WS_OPCODE_PONG, frame.payload_data->buf, frame.payload_data->len, output_sock);
        if (err) {
          goto done;
        }
        break;
      
      case TS_WS_OPCODE_PONG:
        // nothing for now, maybe should record the keep alive time.
        break;
      
      default:
        ts_error__set_msgf(&(ws->err), TS_ERR_INVALID_WS_FRAME, "Invalid frame type: %d", frame.opcode);
        goto done;
    }
    
    // clear the payload
    ts_buf__set_length(frame.payload_data, 0);
  }
  
done:
  ts_ws_frame__destroy(&frame);
  input->len = 0;
  return err;
}

int ts_ws__wrap(ts_ws_t* ws, ts_ro_buf_t* input, ts_buf_t* output) {
  return ts_ws__encode_frame(ws, TS_WS_OPCODE_BINARY_FRAME, input->buf, input->len, output);
}

int ts_ws__disconnect(ts_ws_t* ws, ts_buf_t* output) {
  int err = 0;

  err = ts_ws__encode_frame(ws, TS_WS_OPCODE_CONNECTION_CLOSE, NULL, 0, output);
  if (err) {
    goto done;
  }

done:
  ws->state = TS_STATE_DISCONNECTING;
  return err;
}