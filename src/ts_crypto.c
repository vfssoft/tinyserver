#include "internal/ts_crypto.h"

#include "ts_internal.h"

void crypto__sha1(char* data, int data_len, char* hash) {
  SHA1((unsigned char*)data, data_len, (unsigned char*)hash);
}