
#ifndef TINYSERVER_TS_MISCELLANY_H
#define TINYSERVER_TS_MISCELLANY_H

const char* ts_proto__str(int proto);

const char* ts_ipv6__str(int use_ipv6);

void ts_sockaddr__str(struct sockaddr_storage* addr, char* buf, int buflen);

int ts_tcp__getaddrinfo(const char* host, int use_ipv6, struct sockaddr_storage* ret);

#endif //TINYSERVER_TS_MISCELLANY_H
