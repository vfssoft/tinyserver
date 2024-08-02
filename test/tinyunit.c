#include "tinyunit.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define STDOUT(format,...) \
  fprintf(stdout, format, __VA_ARGS__); \
  fflush(stdout);

static void run_test(test_entry_t* t) {
  t->entry();
}

int run_tests() {
  int actual;
  int total;
  int current;
  int test_result;
  int skip;
  test_entry_t* test;

  for (test = TESTS; test->entry; test++) {
    STDOUT("[%s]\n", test->name);
    run_test(test);
  }

}

