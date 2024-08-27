
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
      tm__set_listener_host_port(tm, 0, "127.0.0.1", MQTT_PLAIN_PORT);
      break;
    case TS_PROTO_TLS:
      tm__set_listener_host_port(tm, 0, "127.0.0.1", MQTT_TLS_PORT);
      tm__set_listener_certs(tm, 0, crtpath, keypath);
      break;
    case TS_PROTO_WS:
      tm__set_listener_host_port(tm, 0, "127.0.0.1", MQTT_WS_PORT);
      break;
    case TS_PROTO_WSS:
      tm__set_listener_host_port(tm, 0, "127.0.0.1", MQTT_WSS_PORT);
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
