#include "internal/ts_mutex.h"
#include "internal/ts_mem.h"

#include <uv.h>

ts_mutex_t* ts_mutex__create() {
  uv_mutex_t* mu = (uv_mutex_t*) ts__malloc(sizeof(uv_mutex_t));
  if (mu == NULL) return NULL;
  memset(mu, 0, sizeof(uv_mutex_t));
  uv_mutex_init_recursive(mu);
  return mu;
}
void ts_mutex__destroy(ts_mutex_t* mu) {
  uv_mutex_destroy((uv_mutex_t*)mu);
  ts__free(mu);
}
void ts_mutex__lock(ts_mutex_t* mu) {
  uv_mutex_lock((uv_mutex_t*)mu);
}
void ts_mutex__unlock(ts_mutex_t* mu) {
  uv_mutex_unlock((uv_mutex_t*)mu);
}

