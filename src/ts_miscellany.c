
#include "ts_internal.h"

const char* ts_proto__str(int proto) {
  switch (proto) {
    case TS_PROTO_TCP: return "TCP";
    case TS_PROTO_TLS: return "TLS";
  }
  return "";
}

const char* ts_ipv6__str(int use_ipv6) {
  return use_ipv6 ? "IPv6" : "IPv4";
}

void ts_sockaddr__str(struct sockaddr_storage* addr, char* buf, int buflen) {
  if (addr->ss_family == AF_INET) {
    struct sockaddr_in *ipv4 = (struct sockaddr_in *)addr;
    char ipstr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ipv4->sin_addr), ipstr, sizeof(ipstr));
    snprintf(buf, buflen, "%s:%d", ipstr, ntohs(ipv4->sin_port));
  } else if (addr->ss_family == AF_INET6) {
    struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)addr;
    char ipstr[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(ipv6->sin6_addr), ipstr, sizeof(ipstr));
    snprintf(buf, buflen, "%s:%d", ipstr, ntohs(ipv6->sin6_port));
  }
}

int ts_tcp__getaddrinfo(const char* host, int use_ipv6, struct sockaddr_storage* ret) {
  struct addrinfo hints, *result, *rp;
  int status;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = use_ipv6 ? AF_INET : AF_INET6;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  status = getaddrinfo(host, NULL, &hints, &result);
  if (status != 0) {
    return UV_EINVAL;
  }

  for (rp = result; rp != NULL; rp = rp->ai_next) {
    memcpy(ret, rp, sizeof(*rp));
    break;
  }

  freeaddrinfo(result);
  return 0;
}

static BOOL str_contains_char(const char* str, char c) {
  const char* p = str;
  while (*p != 0 && *p != c) p++;
  return *p != 0;
}

char* str_trim_left(char* str, const char* spaces) {
  while (*str != 0 && str_contains_char(spaces, *str)) str++;
  return str; // may be empty string
}
char* str_trim_right(char* str, const char* spaces) {
  char* end = str + strlen(str) - 1;
  while (end > str && str_contains_char(spaces, *end)) end--;
  *(end+1) = '\0';
  return str;
}
char* str_trim(char* str, const char* spaces){
  char* p = str;
  p = str_trim_left(p, spaces);
  p = str_trim_right(p, spaces);
  return p;
}


