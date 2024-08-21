
#include "mqtt_utils.h"

#include <internal/ts_mem.h>

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


ts_buf_t* tm__string(const char* ptr, int len) {
  ts_buf_t* str;
  
  str = ts_buf__create(0);
  if (str == NULL) {
    return NULL;
  }
  
  if (ts_buf__set_str(str, ptr, len)) {
    ts_buf__destroy(str);
    return NULL;
  }
  
  return str;
}

int tm__is_valid_qos(int qos) {
  return qos == 0 || qos == 1 || qos == 2;
}
