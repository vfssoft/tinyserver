
#include "ts_internal.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/time.h>
#endif

static const char* log_level_strs[] = {
  "NONE ",
  "ERROR",
  "INFO ",
  "VERB ",
  "DEBUG",
  "DBGex"
};

int ts_log__init(ts_log_t* log, void* server) {
#if _DEBUG
  log->log_level = TS_LOG_LEVEL_DEBUG;
  log->log_timestamp_milliseconds = 1;
#else
  log->log_level = TS_LOG_LEVEL_INFO;
  log->log_timestamp_milliseconds = 0;
#endif
  log->log_dest = TS_LOG_DEST_EVENT;
  log->log_dir = NULL;
  log->server = server;

  log->log_timestamp = 1;

  ts_mutex__init(&(log->mutex));
  return 0;
}

int ts_log__destroy(ts_log_t* log) {
  ts_mutex__destroy(&(log->mutex));
  
  if (log->log_dir) {
    ts__free(log->log_dir);
  }
  return 0;
}

static int ts_log__output(ts_log_t* log, const char* line) {
  ts_mutex__lock(&(log->mutex));
  if (log->log_dest & TS_LOG_DEST_EVENT) {
    ts_server__internal_log_cb(log->server, line);
  }
  if (log->log_dest & TS_LOG_DEST_FILE) {
    // TODO:
  }
  ts_mutex__unlock(&(log->mutex));
  return 0;
}

static long long ts_log__milliseconds_since_1970() {
#ifdef _WIN32
  FILETIME ft;
  GetSystemTimeAsFileTime(&ft);
  ULARGE_INTEGER ui;
  ui.LowPart = ft.dwLowDateTime;
  ui.HighPart = ft.dwHighDateTime;
  return (ui.QuadPart / 10000LL  - 11644473600000LL); // Convert from 100-nanosecond intervals to milliseconds
#else
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (tv.tv_sec * 1000LL) + (tv.tv_usec / 1000);
#endif
}

// TODO: add modules: tcp, tls, websocket, and so on
static int ts_log__vprintf(ts_log_t* log, int level, const char* func, int lineno, const char* data, int data_len, const char *fmt, va_list va) {
  int len = 0;
  char line[1024];
  const char* level_str = log_level_strs[level];

  if (log->log_timestamp) {
    char timestamp_buf[64];
    long long now;
    if (log->log_timestamp_milliseconds) {
      now = ts_log__milliseconds_since_1970();
    } else {
      now = (long long)time(NULL);
    }
    snprintf(timestamp_buf, sizeof(timestamp_buf),"%" PRIu64, (uint64_t)now);
    len += snprintf(line, sizeof(line), "[%s]", timestamp_buf);
  }

  len += snprintf(&line[len], sizeof(line) - len, "[%s]", level_str);

  //len += snprintf(&line[len], sizeof(line) - len, "[%s(%d)]", func, lineno);

  vsnprintf(&line[len], sizeof(line) - len, fmt, va);
  line[sizeof(line)-1] = 0; // ensure string is null terminated.
  
  ts_log__output(log, line);
  
  if (data_len > 0) {
    ts_buf_t* buf = ts_buf__create(0);
    ts_buf__write_hex_dump(buf, data, data_len);
    ts_log__output(log, buf->buf);
    ts_buf__destroy(buf);
  }

  return 0;
}

int ts_log__log(ts_log_t* log, int level, const char* func, int lineno, const char* fmt, ...) {
  if (level > log->log_level) {
    return 0;
  }

  va_list va;
  int err;

  va_start(va, fmt);
  err = ts_log__vprintf(log, level, func, lineno, NULL, 0, fmt, va);
  va_end(va);

  return err;
}

int ts_log__log_hexdump(ts_log_t* log, int level, const char* func, int lineno, const char* data, int data_len, const char* fmt, ...) {
  if (level > log->log_level) {
    return 0;
  }
  
  va_list va;
  int err;
  
  va_start(va, fmt);
  err = ts_log__vprintf(log, level, func, lineno, data, data_len, fmt, va);
  va_end(va);
  
  return err;
}