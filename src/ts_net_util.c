
#include "ts_internal.h"


int ts_tcp__getaddrinfo(const char* host, int use_ipv6, struct addrinfo* ret) {
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
    memcpy(ret, rp, sizeof(*ret));
    break;
  }
  
  freeaddrinfo(result);
  return 0;
}
