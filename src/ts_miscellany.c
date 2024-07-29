
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
