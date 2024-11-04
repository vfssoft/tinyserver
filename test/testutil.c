
#include "testutil.h"
#include "tinyunit.h"

#ifdef WIN32
#include <windows.h>
#include <Psapi.h>
#include <sysinfoapi.h>
#else
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#endif


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

void assert_bytes_equals(const char* d1, int d1len, const char* d2, int d2len) {
  ASSERT_EQ(d1len, d2len);

  for (int i = 0; i < d1len; i++) {
    ASSERT_EQ(d1[i], d2[i]);
  }
}


static unsigned char hex_char_to_byte(char high, char low) {
  unsigned char byte = 0;
  
  // Convert high nibble
  if (high >= '0' && high <= '9') {
    byte |= (high - '0') << 4;
  } else if (high >= 'a' && high <= 'f') {
    byte |= (high - 'a' + 10) << 4;
  } else if (high >= 'A' && high <= 'F') {
    byte |= (high - 'A' + 10) << 4;
  }
  
  // Convert low nibble
  if (low >= '0' && low <= '9') {
    byte |= (low - '0');
  } else if (low >= 'a' && low <= 'f') {
    byte |= (low - 'a' + 10);
  } else if (low >= 'A' && low <= 'F') {
    byte |= (low - 'A' + 10);
  }
  
  return byte;
}
void decode_hex(const char* hex, unsigned char* bytes) {
  int len = strlen(hex);
  int out_len = len / 2;
  for (size_t i = 0; i < out_len; i++) {
    bytes[i] = hex_char_to_byte(hex[2 * i], hex[2 * i + 1]);
  }
}

long long get_current_time_millis() {
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

void wait(int milliseconds) {
  unsigned long long end_time_marker = get_current_time_millis() + milliseconds;
  while (get_current_time_millis() < end_time_marker) {
    mysleep(20);
  }
}
void mysleep(int milliseconds) {
#ifdef _WIN32
  Sleep(milliseconds);
#else
  usleep(milliseconds);
#endif
}

