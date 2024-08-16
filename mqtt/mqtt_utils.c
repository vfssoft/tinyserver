
#include "mqtt_utils.h"

int tm__encode_variable_length(unsigned long long val, char* bytes, int* used_len) {
  char b = 0;
  int offset = 0;
  
  do {
    b = val % 128;
    val = val / 128;
  
    // if there are more data to encode, set the top bit of this byte
    if (val > 0) {
      b |= 128;
    }
    
    bytes[offset] = b;
    offset++;
  } while (val > 0);

  *used_len = offset;
  return 0;
}

int tm__decode_variable_length(const char* bytes, int* used_len, unsigned long long* val) {
  char b = 0;
  unsigned long long multiplier = 1;
  int offset = 0;
  *val = 0;
  
  do {
    b = bytes[offset];
    offset++;
    
    val += (b & 127) * multiplier;
    multiplier *= 128;
    
    if (multiplier > 128*128*128) {
      return -1;
    }
  } while ((b & 128) != 0);
  
  *used_len = offset;
  return 0;
}
