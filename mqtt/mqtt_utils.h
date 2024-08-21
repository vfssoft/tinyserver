
#ifndef TINYSERVER_MQTT_UTILS_H
#define TINYSERVER_MQTT_UTILS_H

#include <internal/ts_data_buf.h>

int tm__encode_variable_length(unsigned long long val, char* bytes, int* used_len);

ts_buf_t* tm__string(const char* ptr, int len);

int tm__is_valid_qos(int qos);

#endif //TINYSERVER_MQTT_UTILS_H
