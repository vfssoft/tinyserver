
#ifndef TINYSERVER_TS_CRYPTO_H
#define TINYSERVER_TS_CRYPTO_H

void crypto__sha1(char* data, int data_len, char* hash/*20*/);
void crypto__random_bytes(char* buf, int len);
unsigned long long crypto__random_int64();

#endif //TINYSERVER_TS_CRYPTO_H
