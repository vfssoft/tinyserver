#include <ts.h>
#include "mytcp.h"
#include "testutil.h"
#include "tinyunit.h"


typedef struct {
  char* record;
  int len;
  
  int client_err;
} tls_invalid_handshake_record_info_t;

static void tls_invalid_handshake_record_connect_cb(void *arg) {
  int err;
  char read_buf[1024];
  tls_invalid_handshake_record_info_t* info = (tls_invalid_handshake_record_info_t*) arg;
  mytcp_t client;
  mytcp__init_mutex();
  mytcp__init(&client);
  client.use_ssl = 0;
  
  err = mytcp__connect(&client, "127.0.0.1", 12345);
  ASSERT_EQ(err, 0);
  
  err = mytcp__write(&client, info->record, info->len);
  ASSERT_EQ(err, info->len);
  
  err = mytcp__read(&client, read_buf, 1024);
  ASSERT_EQ(err, 0); // no data is read
  info->client_err = -1;
  
  err = mytcp__disconnect(&client);
  ASSERT_EQ(err, 0);
}

static int tls_invalid_handshake_record_impl(const char* record, int len) {
  tls_invalid_handshake_record_info_t info;
  memset(&info, 0, sizeof(tls_invalid_handshake_record_info_t));
  info.record = malloc(len);
  memcpy(info.record, record, len);
  info.len = len;
  
  ts_t* server = start_server(TS_PROTO_TLS);
  
  uv_thread_t client_thread;
  uv_thread_create(&client_thread, tls_invalid_handshake_record_connect_cb, (void*)&info);
  
  int r = ts_server__start(server);
  ASSERT_EQ(r, 0);
  
  while (info.client_err == 0) {
    ts_server__run(server);
  }
  
  ts_server__stop(server);
  uv_thread_join(&client_thread);
  
  return 0;
}

TEST_IMPL(tls_invalid_handshake_record_test) {
  const char* record = "abcdefghijklmnopqrst";
  int len = strlen(record);
  return tls_invalid_handshake_record_impl(record, len);
}
TEST_IMPL(tls_invalid_handshake_record_1kzero_test) {
  char record[1024];
  memset(record, 0, 1024);
  return tls_invalid_handshake_record_impl(record, 1024);
}