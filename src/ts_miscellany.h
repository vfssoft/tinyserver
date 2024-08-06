
#ifndef TINYSERVER_TS_MISCELLANY_H
#define TINYSERVER_TS_MISCELLANY_H

const char* ts_proto__str(int proto);

const char* ts_ipv6__str(int use_ipv6);

void ts_sockaddr__str(struct sockaddr_storage* addr, char* buf, int buflen);

int ts_tcp__getaddrinfo(const char* host, int use_ipv6, struct sockaddr_storage* ret);

char* str_trim_left(char* str, const char* spaces);
char* str_trim_right(char* str, const char* spaces);
char* str_trim(char* str, const char* spaces);

int b64_encode(const char* data, int data_len, char* encoded);
int b64_decode(const char* str, int str_len, char* decoded);

#endif //TINYSERVER_TS_MISCELLANY_H
