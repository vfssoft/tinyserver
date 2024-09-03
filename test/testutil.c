
#include "testutil.h"
#include "tinyunit.h"


const char* cur_dir() {
  char* file = strdup(__FILE__);
  int idx = strlen(file) - 1;
  while (file[idx] != '\\') idx--;
  file[idx] = 0;
  return file;
}


ts_t* start_server(int proto) {
  ts_t* server = ts_server__create();
  ts_server__set_listener_count(server, 1);
  ts_server__set_listener_host_port(server, 0, "127.0.0.1", 12345);
  ts_server__set_listener_protocol(server, 0, proto);

  if (ts_use_ssl(proto)) {
    const char* dir_path = cur_dir();
    char crtpath[1024];
    char keypath[1024];

    sprintf(crtpath, "%s/certs/rsa_tinyserver.crt", dir_path);
    sprintf(keypath, "%s/certs/rsa_tinyserver.key", dir_path);

    ts_server__set_listener_certs(server, 0, crtpath, keypath);
  }

  return server;
}

tm_t* start_mqtt_server(int proto, tm_callbacks_t* cbs) {
  return start_mqtt_server_custom_port(proto, -1, cbs);
}
tm_t* start_mqtt_server_custom_port(int proto, int listen_port, tm_callbacks_t* cbs) {
  const char* dir_path = cur_dir();
  char crtpath[1024];
  char keypath[1024];
  
  sprintf(crtpath, "%s/certs/rsa_tinyserver.crt", dir_path);
  sprintf(keypath, "%s/certs/rsa_tinyserver.key", dir_path);
  
  tm_t* tm = tm__create();
  tm__set_listener_count(tm, 1);
  tm__set_listener_protocol(tm, 0, proto);
  
  switch (proto) {
    case TS_PROTO_TCP:
      tm__set_listener_host_port(tm, 0, "127.0.0.1", listen_port < 0 ? MQTT_PLAIN_PORT: listen_port);
      break;
    case TS_PROTO_TLS:
      tm__set_listener_host_port(tm, 0, "127.0.0.1", listen_port < 0 ? MQTT_TLS_PORT: listen_port);
      tm__set_listener_certs(tm, 0, crtpath, keypath);
      break;
    case TS_PROTO_WS:
      tm__set_listener_host_port(tm, 0, "127.0.0.1", listen_port < 0 ? MQTT_WS_PORT: listen_port);
      break;
    case TS_PROTO_WSS:
      tm__set_listener_host_port(tm, 0, "127.0.0.1", listen_port < 0 ? MQTT_WSS_PORT: listen_port);
      tm__set_listener_certs(tm, 0, crtpath, keypath);
      break;
    default:
      assert(0);
  }
  
  tm__set_callbacks(tm, cbs);
  
  return tm;
}


void assert_bytes_equals(const char* d1, int d1len, const char* d2, int d2len) {
  ASSERT_EQ(d1len, d2len);

  for (int i = 0; i < d1len; i++) {
    ASSERT_EQ(d1[i], d2[i]);
  }
}


static unsigned char hex_char_to_byte(char high, char low) {
  unsigned char byte = 0;
  
  // Convert high nibble
  if (high >= '0' && high <= '9') {
    byte |= (high - '0') << 4;
  } else if (high >= 'a' && high <= 'f') {
    byte |= (high - 'a' + 10) << 4;
  } else if (high >= 'A' && high <= 'F') {
    byte |= (high - 'A' + 10) << 4;
  }
  
  // Convert low nibble
  if (low >= '0' && low <= '9') {
    byte |= (low - '0');
  } else if (low >= 'a' && low <= 'f') {
    byte |= (low - 'a' + 10);
  } else if (low >= 'A' && low <= 'F') {
    byte |= (low - 'A' + 10);
  }
  
  return byte;
}
void decode_hex(const char* hex, unsigned char* bytes) {
  int len = strlen(hex);
  int out_len = len / 2;
  for (size_t i = 0; i < out_len; i++) {
    bytes[i] = hex_char_to_byte(hex[2 * i], hex[2 * i + 1]);
  }
}
