
#include "ts_mqtt.h"

#include <internal/ts_mem.h>

tm_t* tm__create() {
  tm_server_t* server = (tm_server_t*) ts__malloc(sizeof(tm_server_t));
  memset(server, 0, sizeof(tm_server_t));
  
  server->server = ts_server__create();
  if (server->server) {
    return NULL;
  }
  
  return server;
}
int tm_destroy(tm_t* mq) {
  tm_server_t* server = (tm_server_t*) mq;
  
  if (server->server) {
    ts_server__destroy(server->server);
  }
  server->server = NULL;

  ts__free(server);
  return 0;
}
