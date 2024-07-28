
#ifndef TINYSERVER_TS_LOG_H
#define TINYSERVER_TS_LOG_H

#include "ts_internal.h"

int ts_log__init(ts_log_t* log);
int ts_log__destroy(ts_log_t* log);

int ts_log__log(ts_log_t* log, int level, const char* func, int lineno, const char* fmt, ...);

#endif //TINYSERVER_TS_LOG_H
