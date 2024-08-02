#include "tinyunit.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef WIN32
#include <windows.h>
#endif

#define STDOUT(format,...) \
  fprintf(stdout, format, __VA_ARGS__); \
  fflush(stdout);


static int win_enable_virtual_terminal_processing() {
#ifdef WIN32
  // Set output mode to handle virtual terminal sequences
  HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
  if (hOut == INVALID_HANDLE_VALUE) {
    return GetLastError();
  }
  
  DWORD dwMode = 0;
  if (!GetConsoleMode(hOut, &dwMode)) {
    return GetLastError();
  }
  
  dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
  if (!SetConsoleMode(hOut, dwMode)) {
    return GetLastError();
  }
#endif
}

static void run_test(test_entry_t* t) {
  t->entry();
}

int run_tests() {
  win_enable_virtual_terminal_processing();
  
  int index = 1;
  test_entry_t* test;

  for (test = TESTS; test->entry; test++) {
    STDOUT("\x1b[34m##### [%d][%s]\x1b[m\n", index, test->name);
    
    run_test(test);
    index++;
  }

}

