#include <tm.h>
#include "tinyunit.h"
#include "testutil.h"
#include "mymqtt.h"
#include "mytcp.h"

typedef struct {
    char pkt_buf[1024];
    int pkt_buf_len;
    
    int recv_done;
    char recv_buf[1024];
    int recv_buf_len;
} test_invalid_first_pkt_info_t;

static void mqtt_client_send_invalid_pkt_cb(void *arg) {
  int err;
  test_invalid_first_pkt_info_t* info = (test_invalid_first_pkt_info_t*)arg;
  mytcp_t client;
  mytcp__init_mutex();
  mytcp__init(&client);
  
  err = mytcp__connect(&client, "127.0.0.1", MQTT_PLAIN_PORT);
  ASSERT_EQ(err, 0);
  
  err = mytcp__write(&client, info->pkt_buf, info->pkt_buf_len);
  ASSERT_EQ(err, info->pkt_buf_len);
  
  err = mytcp__read(&client, info->recv_buf, 1024);
  info->recv_buf_len = err;
  info->recv_done = 1;
  
  err = mymqtt__disconnect(&client);
  ASSERT_EQ(err, 0);
}
static int mqtt_invalid_first_packet_imp(const char* pkt, int len) {
  test_invalid_first_pkt_info_t info;
  memset(&info, 0, sizeof(info));
  memcpy(info.pkt_buf, pkt, len);
  info.pkt_buf_len = len;
  
  tm_t* server;
  tm_callbacks_t cbs;
  memset(&cbs, 0, sizeof(tm_callbacks_t));

  server = start_mqtt_server(TS_PROTO_TCP, &cbs);
  int r = tm__start(server);
  ASSERT_EQ(r, 0);
  
  uv_thread_t client_thread;
  uv_thread_create(&client_thread, mqtt_client_send_invalid_pkt_cb, (void*)&info);
  
  while (info.recv_done == 0) {
    tm__run(server);
  }
  ASSERT_EQ(info.recv_buf_len, 0);
  
  tm__stop(server);
  uv_thread_join(&client_thread);
  
  return 0;
}

// [MQTT-2.2.2-1], [MQTT-2.2.2-2]
TEST_IMPL(mqtt_connect_invalid_reserved_flag_test) {
  const char* hex = "111a00044d5154540402000a000e746573745f636c69656e745f6964";
  int len = strlen(hex) / 2;
  char buf[63];
  decode_hex(hex, buf);
  return mqtt_invalid_first_packet_imp(buf, len);
}