
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


int mytcp__init(mytcp_t* tcp) {
  tcp->use_ssl = 0;
  tcp->use_ws = 0;
  return 0;
}
int mytcp__destroy(mytcp_t* tcp) {
  return 0;
}


int mytcp__connect(mytcp_t* tcp, const char* host, int port) {
  int err = 0;
  err = mytcp__connect_tcp_ssl(tcp, host, port);
  if (err) {
    return err;
  }
  return mytcp__ws_connect(tcp, host, port);
}
int mytcp__disconnect(mytcp_t* tcp) {
  int err;
  err = mytcp__ws_disconnect(tcp);
  if (err) {
    return err;
  }
  return mytcp__disconnect_tcp_ssl(tcp);
}
int mytcp__write(mytcp_t* tcp, const char* data, int len) {
  return mytcp__write_tcp_ssl(tcp, data, len);
}
int mytcp__read(mytcp_t* tcp, char* data, int len) {
  return mytcp__read_tcp_ssl(tcp, data, len);
}