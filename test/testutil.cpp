
#include "testutil.h"


const char* cur_dir() {
  char* file = strdup(__FILE__);
  int idx = strlen(file) - 1;
  while (file[idx] != '\\') idx--;
  file[idx] = 0;
  return file;
}


void start_server(ts_server_t* server, int proto) {
  ts_server__init(server);
  ts_server__set_listener_count(server, 1);
  ts_server__set_listener_host_port(server, 0, "127.0.0.1", 12345);
  ts_server__set_listener_protocol(server, 0, proto);
  
  if (proto == TS_PROTO_TLS) {
    const char* dir_path = cur_dir();
    char crtpath[1024];
    char keypath[1024];
    
    sprintf(crtpath, "%s/certs/rsa_tinyserver.crt", dir_path);
    sprintf(keypath, "%s/certs/rsa_tinyserver.key", dir_path);
    
    ts_server__set_listener_certs(server, 0, crtpath, keypath);
  }
  
}
