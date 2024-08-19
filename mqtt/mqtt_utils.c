
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


