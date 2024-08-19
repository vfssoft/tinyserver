
#ifndef TINYSERVER_TS_LOG_H
#define TINYSERVER_TS_LOG_H

#include "ts_mutex.h"
#include "ts.h"

typedef struct ts_log_s ts_log_t;

struct ts_log_s {
    int log_level;
    int log_dest;
    char* log_dir;
    void* log_ctx;
    ts_log_cb log_cb;
    
    int log_timestamp;
    char* log_timestamp_format;
    
    // internal states
    FILE* cur_log_file;
    
    ts_mutex_t mutex;
};

#define LOG(level, fmt, ...)   ts_log__log(ts_server__get_log(server), level,                __FUNCTION__, __LINE__, fmt, __VA_ARGS__)
#define LOG_ERROR(fmt, ...)    ts_log__log(ts_server__get_log(server), TS_LOG_LEVEL_ERROR,   __FUNCTION__, __LINE__, fmt, __VA_ARGS__)
#define LOG_INFO(fmt, ...)     ts_log__log(ts_server__get_log(server), TS_LOG_LEVEL_INFO,    __FUNCTION__, __LINE__, fmt, __VA_ARGS__)
#define LOG_VERB(fmt, ...)     ts_log__log(ts_server__get_log(server), TS_LOG_LEVEL_VERB,    __FUNCTION__, __LINE__, fmt, __VA_ARGS__)
#define LOG_DEBUG(fmt, ...)    ts_log__log(ts_server__get_log(server), TS_LOG_LEVEL_DEBUG,   __FUNCTION__, __LINE__, fmt, __VA_ARGS__)
#define LOG_DEBUG_EX(fmt, ...) ts_log__log(ts_server__get_log(server), TS_LOG_LEVEL_DEBUGEX, __FUNCTION__, __LINE__, fmt, __VA_ARGS__)

int ts_log__init(ts_log_t* log);
int ts_log__destroy(ts_log_t* log);

int ts_log__log(ts_log_t* log, int level, const char* func, int lineno, const char* fmt, ...);

ts_log_t* ts_server__get_log(ts_t* server);

#endif //TINYSERVER_TS_LOG_H
