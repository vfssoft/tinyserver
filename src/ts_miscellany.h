
#ifndef TINYSERVER_TS_MISCELLANY_H
#define TINYSERVER_TS_MISCELLANY_H

const char* ts_proto__str(int proto);

BOOL ts_use_ssl(int proto);
BOOL ts_use_websocket(int proto);

const char* ts_ipv6__str(int use_ipv6);

void ts_sockaddr__str(struct sockaddr_storage* addr, char* buf, int buflen);

int ts_tcp__getaddrinfo(const char* host, int use_ipv6, struct sockaddr_storage* ret);

char* str_trim_left(char* str, const char* spaces);
char* str_trim_right(char* str, const char* spaces);
char* str_trim(char* str, const char* spaces);

int b64_encode(const char* data, int data_len, char* encoded);
int b64_decode(const char* str, int str_len, char* decoded);

unsigned long long bytes2uint64_be(const char* bytes);
unsigned int bytes2uint32_be(const char* bytes);
unsigned short bytes2uint16_be(const char* bytes);

void uint642bytes_be(unsigned long long val, char* bytes);
void uint322bytes_be(unsigned int val, char* bytes);
void uint162bytes_be(unsigned short val, char* bytes);

#endif //TINYSERVER_TS_MISCELLANY_H
