
#ifndef TINYSERVER_MYTCP_H
#define TINYSERVER_MYTCP_H

#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <uv.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mytcp_s mytcp_t;

struct mytcp_s {
  int socket;
  int use_ssl;
  int use_ws;

  SSL_CTX* sslctx;
  SSL*     ssl;
};

int mytcp__init_mutex();
int mytcp__destroy_mutex();

int mytcp__init(mytcp_t* tcp);
int mytcp__destroy(mytcp_t* tcp);

int mytcp__connect(mytcp_t* tcp, const char* host, int port);
int mytcp__disconnect(mytcp_t* tcp);
int mytcp__read(mytcp_t* tcp, char* data, int len);
int mytcp__write(mytcp_t* tcp, const char* data, int len);

#ifdef __cplusplus
}
#endif


#endif //TINYSERVER_MYTCP_H
