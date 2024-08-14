#include "tinyunit.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef WIN32
#include <windows.h>
#include <Psapi.h>
#else
#include <sys/time.h>
#include <sys/resource.h>
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
  return 0;
}

static long long get_current_time_millis() {
#ifdef _WIN32
  FILETIME ft;
  LARGE_INTEGER li;
  
  GetSystemTimePreciseAsFileTime(&ft);
  
  li.LowPart = ft.dwLowDateTime;
  li.HighPart = ft.dwHighDateTime;
  
  return (long long)(li.QuadPart / 10000LL - 11644473600000LL);
#else
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
#endif
}

long get_current_process_memory_usage() {
#ifdef _WIN32
  PROCESS_MEMORY_COUNTERS_EX pmc;
  if (GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
    return pmc.PrivateUsage;
  } else {
    return -1;
  }
#else
  struct rusage ru;
  if (getrusage(RUSAGE_SELF, &ru) == 0) {
      return ru.ru_maxrss * 1024; // Convert kilobytes to bytes
  } else {
      return -1;
  }
#endif
}

static void run_test(test_entry_t* t) {
  long long start_time = get_current_time_millis();
  t->entry();
  long long time_used = get_current_time_millis() - start_time;
  STDOUT("\x1b[34m##### Time used: %lld ms\x1b[m\n", time_used);
}

int run_tests() {
  win_enable_virtual_terminal_processing();
  
  long long start_time = get_current_time_millis();
  int total_tests_count = sizeof(TESTS) / sizeof(TESTS[0]);
  int index = 1;
  test_entry_t* test;

  for (test = TESTS; test->entry; test++) {
    STDOUT("\x1b[34m##### [%d/%d][%s]\x1b[m\n", index, total_tests_count, test->name);
    
    run_test(test);
    index++;
  }

  long long time_used = get_current_time_millis() - start_time;
  STDOUT("\x1b[34m##### Total Time Used: %lld ms\x1b[m\n", time_used);
}

