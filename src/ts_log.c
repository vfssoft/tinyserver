
#include "ts_internal.h"

static const char* log_level_strs[] = {
  "NONE ",
  "ERROR",
  "INFO ",
  "VERB ",
  "DEBUG",
  "DBGex"
};


static int ts_log__default_log_cb(void* ctx, int level, const char* msg) {
  printf("%s\n", msg);
  return 0;
}



int ts_log__init(ts_log_t* log) {
  log->log_level = TS_LOG_LEVEL_INFO;
  log->log_dest = TS_LOG_DEST_EVENT;
  log->log_dir = NULL;
  log->log_ctx = NULL;
  log->log_cb = ts_log__default_log_cb;

  log->log_timestamp = 1;
  log->log_timestamp_format = NULL;
  
  uv_mutex_init_recursive(&log->mutex);
  return 0;
}

int ts_log__destroy(ts_log_t* log) {
  uv_mutex_destroy(&log->mutex);
  
  if (log->log_dir) {
    ts__free(log->log_dir);
  }
  if (log->log_timestamp_format) {
    ts__free(log->log_timestamp_format);
  }
  return 0;
}

// TODO: add modules: tcp, tls, websocket, and so on
static int ts_log__vprintf(ts_log_t* log, int level, const char* func, int lineno, const char *fmt, va_list va) {
  int len = 0;
  char line[1024];
  const char* level_str = log_level_strs[level];

  if (log->log_timestamp) {
    char timestamp_buf[64];
    time_t now = time(NULL);
    if (log->log_timestamp_format != NULL) {
      struct tm* local_time = localtime(&now);
      strftime(timestamp_buf, sizeof(timestamp_buf), log->log_timestamp_format, local_time);
    } else {
      snprintf(timestamp_buf, sizeof(timestamp_buf),"%" PRIu64, (uint64_t)now);
    }
    len += snprintf(line, sizeof(line), "[%s]", timestamp_buf);
  }

  len += snprintf(&line[len], sizeof(line) - len, "[%s]", level_str);

  len += snprintf(&line[len], sizeof(line) - len, "[%s(%d)]", func, lineno);

  vsnprintf(&line[len], sizeof(line) - len, fmt, va);
  line[sizeof(line)-1] = 0; // ensure string is null terminated.

  uv_mutex_lock(&log->mutex);
  if (log->log_dest & TS_LOG_DEST_EVENT) {
    log->log_cb(log->log_ctx, level, line);
  }
  if (log->log_dest & TS_LOG_DEST_FILE) {
    // TODO:
  }
  uv_mutex_unlock(&log->mutex);

  return 0;
}

int ts_log__log(ts_log_t* log, int level, const char* func, int lineno, const char* fmt, ...) {
  if (level > log->log_level) {
    return 0;
  }

  va_list va;
  int err;

  va_start(va, fmt);
  err = ts_log__vprintf(log, level, func, lineno, fmt, va);
  va_end(va);

  return err;
}