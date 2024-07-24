#include "ts_internal.h"


int ts_server_listener__init_default(ts_server_listener_t* listener) {
  listener->host = "0.0.0.0";
  listener->port = 0;
  listener->use_ipv6 = 0;
  listener->backlog = TS_DEFAULT_BACKLOG;
  listener->protocol = TS_PROTO_TCP;
  listener->cert = "";
  listener->key = "";
  listener->tls_verify_mode = 0;
  return 0;
}

static int ts_server_listener__bind(ts_server_listener_t* listener) {
  int err;

  struct sockaddr addr = { 0 };
  struct sockaddr_in* in4 = (struct sockaddr_in*)&addr;
  struct sockaddr_in6* in6 = (struct sockaddr_in6*)&addr;

  int use_ipv6 = listener->use_ipv6;
  const char* host = listener->host;
  int port = listener->port;

  if (use_ipv6) {
    in6->sin6_family = AF_INET6;
    err = uv_inet_pton(AF_INET6, host, &in6->sin6_addr);
  } else {
    in4->sin_family = AF_INET;
    err = uv_inet_pton(AF_INET, host, &in4->sin_addr);
  }
  if (err) {
    ts_error__set_msg(&(listener->server->err), err, "invalid host");
  }

  if (err) {
    if (ts_tcp__getaddrinfo(host, use_ipv6, &addr) == 0) {
      err = 0;
      ts_error__reset(&(listener->server->err));
    }
  }

  if (err) {
    return err;
  }

  if (use_ipv6) {
    in6->sin6_port = htons(port);
  } else {
    in4->sin_port = htons(port);
  }

  err = uv_tcp_bind(&listener->uvtcp, &addr, 0);
  if (err) {
    ts_error__set_msg(&(listener->server->err), err, uv_strerror(err));
  }
  return err;
}

int ts_server_listener__start(ts_server_listener_t* listener, ts_server_t* server, uv_connection_cb cb) {
  int err;
  
  listener->server = server;
  listener->uvloop = server->uvloop;
  
  err = uv_tcp_init(listener->uvloop, &listener->uvtcp);
  if (err) {
    return err;
  }
  
  err = ts_server_listener__bind(listener);
  if (err) {
    return err;
  }
  
  err = uv_listen((uv_stream_t*)&(listener->uvtcp), listener->backlog, cb);
  return err;
}
int ts_server_listener__stop(ts_server_listener_t* listener, uv_close_cb cb) {
  uv_close((uv_handle_t*)&(listener->uvtcp), cb);
  return 0;
}