
#include "tinyunit.h"
#include "test-list.h"

int main(int argc, char **argv) {
  //run_tests();
  run_test_invalid_local_host();
  run_test_invalid_local_host_2();
  run_test_tcp_connect();
  //run_test_tls_connect();
  run_test_tcp_server_disconnect();
}