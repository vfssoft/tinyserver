
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
