
#include "ts_internal.h"


int ts_log__init(ts_log_t* log) {
  log->log_level = TS_LOG_LEVEL_INFO;
  log->log_dest = TS_LOG_DEST_STDOUT;
  log->log_dir = NULL;
  log->log_ctx = NULL;
  log->log_cb = NULL;
  return 0;
}

int ts_log__destroy(ts_log_t* log) {
  if(log->log_dir) {
    ts__free(log->log_dir);
  }
  return 0;
}