
#ifndef TINYSERVER_MQTT_UTILS_H
#define TINYSERVER_MQTT_UTILS_H

int tm__encode_variable_length(unsigned long long val, char* bytes, int* used_len);

#endif //TINYSERVER_MQTT_UTILS_H
