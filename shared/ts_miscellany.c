#include <uv.h>
#include <openssl/ssl.h>

#include <tsdefs.h>
#include <internal/ts_miscellany.h>

const char* ts_proto__str(int proto) {
  switch (proto) {
    case TS_PROTO_TCP: return "TCP";
    case TS_PROTO_TLS: return "TLS";
    case TS_PROTO_WS:  return "WS";
    case TS_PROTO_WSS: return "WSS";
  }
  return "";
}

int ts_use_ssl(int proto) {
  return proto == TS_PROTO_TLS || proto == TS_PROTO_WSS;
}
int ts_use_websocket(int proto) {
  return proto == TS_PROTO_WS || proto == TS_PROTO_WSS;
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

static int str_contains_char(const char* str, char c) {
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

int b64_encode(const char* data, int data_len, char* encoded) {
  return EVP_EncodeBlock((unsigned char *)encoded, (unsigned char*)data, data_len);
}
int b64_decode(const char* str, int str_len, char* decoded) {
  return EVP_DecodeBlock((unsigned char*)decoded, (unsigned char*)str, str_len);
}

unsigned long long bytes2uint64_be(const char* bytes) {
  unsigned long long val = 0;
  val |= ((unsigned long long)(bytes[0] & 0xFF)) << 56;
  val |= ((unsigned long long)(bytes[1] & 0xFF)) << 48;
  val |= ((unsigned long long)(bytes[2] & 0xFF)) << 40;
  val |= ((unsigned long long)(bytes[3] & 0xFF)) << 32;
  val |= ((unsigned long long)(bytes[4] & 0xFF)) << 24;
  val |= ((unsigned long long)(bytes[5] & 0xFF)) << 16;
  val |= ((unsigned long long)(bytes[6] & 0xFF)) <<  8;
  val |= (unsigned long long)(bytes[7] & 0xFF);
  return (unsigned long long)val;
}
unsigned int bytes2uint32_be(const char* bytes) {
  return (unsigned int) (
      (unsigned int)(bytes[0] & 0xFF) << 24 |
      (unsigned int)(bytes[1] & 0xFF) << 16 |
      (unsigned int)(bytes[2] & 0xFF) << 8 |
      (unsigned int)(bytes[3] & 0xFF)
  );
}
unsigned short bytes2uint16_be(const char* bytes) {
  return (unsigned short) (
      ((unsigned short)(bytes[0] & 0xFF)) << 8 | ((unsigned short)(bytes[1] & 0xFF))
  );
}
void uint642bytes_be(unsigned long long val, char* bytes) {
  bytes[0] = (char)((val & 0xFF00000000000000) >> 56);
  bytes[1] = (char)((val & 0x00FF000000000000) >> 48);
  bytes[2] = (char)((val & 0x0000FF0000000000) >> 40);
  bytes[3] = (char)((val & 0x000000FF00000000) >> 32);
  bytes[4] = (char)((val & 0x00000000FF000000) >> 24);
  bytes[5] = (char)((val & 0x0000000000FF0000) >> 16);
  bytes[6] = (char)((val & 0x000000000000FF00) >> 8);
  bytes[7] = (char)((val & 0x00000000000000FF));
}
void uint322bytes_be(unsigned int val, char* bytes) {
  bytes[0] = (char)((val & 0xFF000000) >> 24);
  bytes[1] = (char)((val & 0x00FF0000) >> 16);
  bytes[2] = (char)((val & 0x0000FF00) >> 8);
  bytes[3] = (char)((val & 0x000000FF));
}
void uint162bytes_be(unsigned short val, char* bytes) {
  bytes[0] = (char)((val & 0xFF00) >> 8);
  bytes[1] = (char)((val & 0x00FF));
}

