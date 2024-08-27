#include <tm.h>
#include "tinyunit.h"
#include "testutil.h"


static int mqtt_connect_imp(int proto) {
  tm_t* server;
  tm_callbacks_t cbs;
  memset(&cbs, 0, sizeof(tm_callbacks_t));
  
  server = start_mqtt_server(TS_PROTO_TCP, &cbs);
  tm__start(server);
  
  return 0;
}

TEST_IMPL(mqtt_connect_tcp) {
  return mqtt_connect_imp(TS_PROTO_TCP);
}