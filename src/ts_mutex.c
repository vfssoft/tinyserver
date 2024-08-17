#include "internal/ts_mutex.h"


void ts_mutex__init(ts_mutex_t* mu) {
  uv_mutex_init_recursive(mu);
}
void ts_mutex__destroy(ts_mutex_t* mu) {
  uv_mutex_destroy(mu);
}
void ts_mutex__lock(ts_mutex_t* mu) {
  uv_mutex_lock(mu);
}
void ts_mutex__unlock(ts_mutex_t* mu) {
  uv_mutex_unlock(mu);
}

