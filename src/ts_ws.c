
#include "ts_ws.h"

#define TS_WS_STATE_HANDSHAKING  0
#define TS_WS_STATE_CONNECTED    1
#define TS_WS_STATE_DISCONNECTED 2

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
  
  
  
}

int ts_ws__init(ts_ws_t* ws, ts_conn_t* conn) {
  ts_server_listener_t* listener = conn->listener;
  ts_server_t* server = listener->server;
  
  ws->conn = conn;
  ws->state = TS_WS_STATE_HANDSHAKING;
  ts_error__init(&ws->err);
  
  ws->out_buf = ts_buf__create(0);
  if (ws->out_buf == NULL) {
    ts_error__set(&(ws->err), TS_ERR_OUT_OF_MEMORY);
    goto done;
  }
  
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

int ts_ws__handshake(ts_ws_t* ws, ts_ro_buf_t* input, ts_buf_t* output) {
  int err;
  char *p, *method, *url, *version;
  char* end_of_headers = NULL;
  char line[1024];
  char url_buf[256] = { 0 };
  
  ts_conn_t* conn = ws->conn;
  ts_server_t* server = conn->listener->server;
  
  LOG_VERB("[%s][WS] WS handshaking", conn->remote_addr);
  
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
    
    if (url[0] == 0) {
      // parse the first line of the HTTP Upgrade request
      // Example: GET /chat HTTP/1.1
      ts_ws__parse_request_line(line, &method, &url, &version);
      if (method == NULL || url == NULL || version == NULL || stricmp(method, "GET") != 0 || stricmp(version, "HTTP/1.1") != 0) {
        ts_error__set_msg(&(ws->err), TS_ERR_INVALID_WS_HEADERS, "Invalid Websocket Upgrade request");
        goto done;
      }
      strcmp(url_buf, url);
    } else {
    
    }
  
  }
  
done:
  return ws->err.err;
}