
#include "mytcp.h"

static int WSA_START_UP = 0;

static void mytcp__wsa_startup() {
  if (WSA_START_UP) { return ; }

#ifdef _WIN32
  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
    exit(-1);
  }
#endif

  WSA_START_UP = 1;
}

int mytcp__connect(mytcp_t* tcp, const char* host, int port) {
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
int mytcp__disconnect(mytcp_t* tcp) {
  int err;
#ifdef _WIN32
  err = closesocket(tcp->socket);
#else
  err = close(tcp->socket);
#endif
  tcp->socket = 0;
  return err;
}
int mytcp__read(mytcp_t* tcp, const char* data, int len) {
  int err;

  err = send(tcp->socket, data, len, 0);
  if (err < 0) {
    mytcp__disconnect(tcp);
  }
  return err;
}
int mytcp__write(mytcp_t* tcp, char* data, int len) {
  int err;

  memset(data, 0, len);

  err = recv(tcp->socket, data, len, 0);
  if (err < 0) {
    mytcp__disconnect(tcp);
  }

  return err;
}