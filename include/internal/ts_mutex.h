#ifndef TINYSERVER_TS_MUTEX_H
#define TINYSERVER_TS_MUTEX_H

#include <uv.h>

typedef uv_mutex_t ts_mutex_t;

void ts_mutex__init(ts_mutex_t* mu);
void ts_mutex__destroy(ts_mutex_t* mu);
void ts_mutex__lock(ts_mutex_t* mu);
void ts_mutex__unlock(ts_mutex_t* mu);

#endif //TINYSERVER_TS_MUTEX_H

