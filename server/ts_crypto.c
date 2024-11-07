#include "internal/ts_crypto.h"

#include "ts_internal.h"

void crypto__sha1(char* data, int data_len, char* hash) {
  SHA1((unsigned char*)data, data_len, (unsigned char*)hash);
}
void crypto__random_bytes(char* buf, int len) {
  RAND_bytes((unsigned char*)buf, len);
}
unsigned long long crypto__random_int64() {
  unsigned long long val;
  char buf[8];
  
  crypto__random_bytes(buf, 8);
  memcpy(&val, buf, 8);

  return val;
}