
#include "mytcp.h"

static int WSA_START_UP = 0;
static int OPENSSL_INITIALIZED = 0;
static uv_mutex_t mutex;

static void lock() {
  uv_mutex_lock(&mutex);
}
static void unlock() {
  uv_mutex_unlock(&mutex);
}

int mytcp__init_mutex() {
  uv_mutex_init(&mutex);
  return 0;
}
int mytcp__destroy_mutex() {
  uv_mutex_destroy(&mutex);
  return 0;
}

static void mytcp__wsa_startup() {
  lock();
  if (!WSA_START_UP) {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
      exit(-1);
    }
#endif
  
    WSA_START_UP = 1;
  }

  unlock();
}
static void mytcp__init_openssl() {
  lock();
  if (!OPENSSL_INITIALIZED) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    OPENSSL_INITIALIZED = 1;
  }
  unlock();
}

static int mytcp__tcp_connect(mytcp_t* tcp, const char* host, int port) {
  int err;
  struct sockaddr_in addr;

  mytcp__wsa_startup();

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr(host);
  addr.sin_port = htons(port);

  tcp->socket = socket(AF_INET, SOCK_STREAM, 0);
  if (tcp->socket < 0) {
    return -1;
  }

  return connect(tcp->socket, (struct sockaddr *)&addr, sizeof(addr));
}
static int mytcp__tcp_disconnect(mytcp_t* tcp) {
  int err;
#ifdef _WIN32
  err = closesocket(tcp->socket);
#else
  err = close(tcp->socket);
#endif
  tcp->socket = 0;
  return err;
}
static int mytcp__tcp_write(mytcp_t* tcp, const char* data, int len) {
  int err;

  err = send(tcp->socket, data, len, 0);
  if (err < 0) {
    mytcp__disconnect(tcp);
  }
  return err;
}
static int mytcp__tcp_read(mytcp_t* tcp, char* data, int len) {
  int err;

  memset(data, 0, len);

  err = recv(tcp->socket, data, len, 0);
  if (err < 0) {
    mytcp__disconnect(tcp);
  }

  return err;
}

static int mytcp__ssl_connect(mytcp_t* tcp, const char* host, int port) {
  if (!tcp->use_ssl) return 0;

  int err;
  char host_port_buf[64];
  snprintf(host_port_buf, sizeof(host_port_buf), "%s:%d", host, port);

  mytcp__init_openssl();

  tcp->sslctx = SSL_CTX_new(TLS_client_method());
  if (tcp->sslctx == NULL) {
    printf("Failed to create SSL context\n");
    ERR_print_errors_fp(stderr);
    return -1;
  }

  tcp->ssl = SSL_new(tcp->sslctx);
  if (tcp->ssl == NULL) {
    printf("Failed to create SSL object\n");
    ERR_print_errors_fp(stderr);
    return 1;
  }

  BIO *bio = BIO_new_connect(host_port_buf);
  if (BIO_do_connect(bio) <= 0) {
    printf("Failed to connect to server\n");
    ERR_print_errors_fp(stderr);
    return 1;
  }

  SSL_set_bio(tcp->ssl, bio, bio);

  err = SSL_connect(tcp->ssl);
  if (err != 1) {
    printf("Failed to establish TLS connection\n");
    ERR_print_errors_fp(stderr);
    return 1;
  }

  return 0;
}
static int mytcp__ssl_disconnect(mytcp_t* tcp) {
  SSL_shutdown(tcp->ssl);
  SSL_free(tcp->ssl);
  SSL_CTX_free(tcp->sslctx);
  return 0;
}
static int mytcp__ssl_write(mytcp_t* tcp, const char* data, int len) {
  int err;

  err = SSL_write(tcp->ssl, data, len);
  if (err <= 0) {
    printf("Failed to send data\n");
    ERR_print_errors_fp(stderr);
    return 1;
  }

  return len;
}
static int mytcp__ssl_read(mytcp_t* tcp, char* data, int len) {
  int err = 0;
  int roffset = 0;
  
  while (roffset < len) {
    err = SSL_read(tcp->ssl, data + roffset, len - roffset);
    if (err <= 0) {
      printf("Failed to receive data\n");
      ERR_print_errors_fp(stderr);
      return 1;
    } else {
      roffset += err;
      if (roffset >= len) break;

      // work like read timeout: 1s
      for (int i = 0; i < 10; i++) {
        if (SSL_pending(tcp->ssl) == 0) {
          Sleep(100);
        } else {
          break;
        }
      }
      if (SSL_pending(tcp->ssl) == 0) {
        break;
      }
    }
  }

  return len;
}

static int mytcp__connect_tcp_ssl(mytcp_t* tcp, const char* host, int port) {
  if (tcp->use_ssl) {
    return mytcp__ssl_connect(tcp, host, port);
  } else {
    return mytcp__tcp_connect(tcp, host, port);
  }
}
static int mytcp__write_tcp_ssl(mytcp_t* tcp, const char* data, int len) {
  if (tcp->use_ssl) {
    return mytcp__ssl_write(tcp, data, len);
  } else {
    return mytcp__tcp_write(tcp, data, len);
  }
}
static int mytcp__read_tcp_ssl(mytcp_t* tcp, char* data, int len) {
  if (tcp->use_ssl) {
    return mytcp__ssl_read(tcp, data, len);
  } else {
    return mytcp__tcp_read(tcp, data, len);
  }
}
static int mytcp__disconnect_tcp_ssl(mytcp_t* tcp) {
  if (tcp->use_ssl) {
    return mytcp__ssl_disconnect(tcp);
  } else {
    return mytcp__tcp_disconnect(tcp);
  }
}

static int mytcp__ws_connect(mytcp_t* tcp, const char* host, int port) {
  int err = 0;
  char host_port_buf[64];
  char buf[1024];
  int buf_len = 0;
  
  const char* req =
    "GET /mqtt HTTP/1.1\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "Sec-WebSocket-Key: fp/NuhTTdfYLAo4N2GB1cg==\r\n"
    "Connection: Upgrade\r\n"
    "Upgrade: websocket\r\n"
    "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n"
    "Sec-WebSocket-Protocol: mqtt\r\n"
    "Host: %s\r\n"
    "\r\n";
  
  snprintf(host_port_buf, sizeof(host_port_buf), "%s:%d", host, port);
  buf_len = sprintf(buf, req, host_port_buf);
  
  err = mytcp__write_tcp_ssl(tcp, buf, buf_len);
  if (err < 0) {
    return err;
  }
  
  buf_len = sizeof(buf);
  
  err = mytcp__read_tcp_ssl(tcp, buf, buf_len);
  if (err < 0) {
    return err;
  }
  
  // expected response
  /*
   * HTTP/1.1 101 Switching Protocols
   * connection: Upgrade
   * date: Wed, 07 Aug 2024 14:38:48 GMT
   * sec-websocket-accept: Yoh0hDNDSW1Me7uuyJ8XrujK7Qw=
   * sec-websocket-protocol: mqtt
   * server: Cowboy
   * upgrade: websocket
   */
  if (strstr(buf, "HTTP/1.1 101 Switching Protocols") == NULL) {
    return -1;
  }
  if (strstr(buf, "Yoh0hDNDSW1Me7uuyJ8XrujK7Qw=") == NULL) {
    return -1;
  }
  if (strstr(buf, "websocket") == NULL) {
    return -1;
  }
  if (strstr(buf, "Upgrade") == NULL) {
    return -1;
  }
  
  return 0;
}
static int mytcp__ws_disconnect(mytcp_t* tcp) {
  int err;
  
  char buf[] = { 0x88, 0x80, 0x00, 0x00, 0x00, 0x00 };
  err = mytcp__write_tcp_ssl(tcp, buf, sizeof(buf));
  if (err < 0) {
    return err;
  }
  return 0;
}
static int mytcp__ws_write(mytcp_t* tcp, const char* data, int len) {
  char maskingKey[4] = { 0xa5, 0x23, 0xcf, 0x0c }; // randomly choose
  char* buf = (char*) malloc(len + 16);
  int offset = 0;

  buf[0] = 0x82; // Fin, Binary
  buf[1] = 0x80; // Mask

  if (len <= 125) {
    buf[1] |= len;
    offset = 2;
  } else if (len <= 0xFFFF) {
    buf[1] |= 126;
    buf[2] = (char)((len & 0xFF00) >> 8);
    buf[3] = (char)(len & 0x00FF);
    offset = 4;
  } else {
    buf[1] |= 127;
    buf[2] = 0x00;
    buf[3] = 0x00;
    buf[4] = 0x00;
    buf[5] = 0x00;
    buf[6] = (char)((len & 0xFF000000) >> 24);
    buf[7] = (char)((len & 0x00FF0000) >> 16);
    buf[8] = (char)((len & 0x0000FF00) >>  8);
    buf[9] = (char)((len & 0x000000FF)      );
    offset = 10;
  }

  memcpy(buf + offset, maskingKey, 4);
  offset += 4;

  memcpy(buf + offset, data, len);
  for (int i = 0; i < len; i++) {
    buf[offset + i] ^= maskingKey[i%4];
  }
  offset += len;

  int err = mytcp__write_tcp_ssl(tcp, buf, offset);
  free(buf);
  return len;
}
static int mytcp__ws_read_from_buf(mytcp_t* tcp, char* data, int len) {
  int len_read = len;
  ts_buf__read(tcp->ws_ws_buf, data, &len_read);
  return len_read;
}
static int mytcp__ws_decode_frame(mytcp_t* tcp, BOOL* ok) {
  int err = 0;
  ts_buf_t* buf = tcp->ws_raw_buf;
  ts_buf_t* ws_buf = tcp->ws_ws_buf;
  int offset = 0; // next byte to read
  *ok = FALSE;

  if (buf->len < 2) return 0;

  unsigned long long payload_len = buf->buf[1] & 0x7F;
  if (payload_len <= 125) {
    // payload_len is current value
    offset = 2;
  } else if (payload_len == 126) {
    if (buf->len < 4) {
      return 0;
    }
    payload_len =
        (buf->buf[2] << 8) |
        buf->buf[3];
    offset = 4;
  } else if (payload_len == 127) {
    if (buf->len < 10) {
      return 0;
    }
    payload_len =
        ((unsigned long long)buf->buf[2] << 56) |
        ((unsigned long long)buf->buf[3] << 48) |
        ((unsigned long long)buf->buf[4] << 40) |
        ((unsigned long long)buf->buf[5] << 32) |
        ((unsigned long long)buf->buf[6] << 24) |
        ((unsigned long long)buf->buf[7] << 16) |
        ((unsigned long long)buf->buf[8] <<  8) |
        buf->buf[9];

    offset = 10;
  }

  if (offset + payload_len > buf->len) return 0;

  ts_buf__write(ws_buf, buf->buf + offset, payload_len);
  offset += payload_len;
  ts_buf__read(buf, NULL, &offset);

  *ok = TRUE;
  return 0;
}
static int mytcp__ws_read_from_socket(mytcp_t* tcp, char* data, int len) {
  int err = 0;
  int offset = 0;
  char* recv_buf = malloc(1024 * 1024);
  ts_buf_t* raw_buf = tcp->ws_raw_buf;
  BOOL decoded = FALSE;

  while (offset < len) {
    err = mytcp__read_tcp_ssl(tcp, recv_buf, 1024 * 1024);
    if (err <= 0) return err;
    ts_buf__write(raw_buf, recv_buf, err);

    err = mytcp__ws_decode_frame(tcp, &decoded);
    if (err) return err;

    if (decoded) {
      err = mytcp__ws_read_from_buf(tcp, data + offset, len - offset);
      if (err) return err;
      offset += err;
    }
  }

done:
  free(recv_buf);

  return offset;
}
static int mytcp__ws_read(mytcp_t* tcp, char* data, int len) {
  int err = 0;
  int offset = 0;
  int retry_count = 0;

  err = mytcp__ws_read_from_buf(tcp, data, len);
  if (err < 0) return err;
  offset += err;

  while (offset < len) {
    err = mytcp__ws_read_from_socket(tcp, data+offset, len-offset);
    if (err < 0) return err;
    offset += err;

    if (err == 0) {
      if (retry_count == 10) break;
      Sleep(100);
      retry_count++;
    }
  }

  return offset;
}

int mytcp__init(mytcp_t* tcp) {
  tcp->use_ssl = 0;
  tcp->use_ws = 0;
  tcp->ws_ws_buf = ts_buf__create(0);
  tcp->ws_raw_buf = ts_buf__create(0);
  return 0;
}
int mytcp__destroy(mytcp_t* tcp) {
  if (tcp->ws_ws_buf) {
    ts_buf__destroy(tcp->ws_ws_buf);
  }
  if (tcp->ws_raw_buf) {
    ts_buf__destroy(tcp->ws_raw_buf);
  }
  return 0;
}


int mytcp__connect(mytcp_t* tcp, const char* host, int port) {
  int err = 0;
  err = mytcp__connect_tcp_ssl(tcp, host, port);
  if (err) {
    return err;
  }
  if (!tcp->use_ws) {
    return 0;
  }
  return mytcp__ws_connect(tcp, host, port);
}
int mytcp__disconnect(mytcp_t* tcp) {
  int err;
  if (tcp->use_ws) {
    err = mytcp__ws_disconnect(tcp);
    if (err) {
      return err;
    }
  }
  return mytcp__disconnect_tcp_ssl(tcp);
}
int mytcp__write(mytcp_t* tcp, const char* data, int len) {
  if (tcp->use_ws) {
    return mytcp__ws_write(tcp, data, len);
  } else {
    return mytcp__write_tcp_ssl(tcp, data, len);
  }
}
int mytcp__read(mytcp_t* tcp, char* data, int len) {
  if (tcp->use_ws) {
    return mytcp__ws_read(tcp, data, len);
  } else {
    return mytcp__read_tcp_ssl(tcp, data, len);
  }
}