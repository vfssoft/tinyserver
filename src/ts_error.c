
#include "ts_internal.h"

static ts_error_t pre_def_errs[] = {
    { TS_ERR_OUT_OF_MEMORY, (char*)"out of memory" }
};

static int ts_error_is_pre_defined_err(int err) {
  int pre_def_errs_len = sizeof(pre_def_errs) / sizeof(ts_error_t);
  return err < pre_def_errs_len;
}

ts_error_t* ts_error_create(int err) {
  if (ts_error_is_pre_defined_err(err)) {
    return &pre_def_errs[err];
  }
  
  ts_error_t* e = (ts_error_t*) ts__malloc(sizeof(ts_error_t));
  if (e == NULL) {
    return NULL;
  }
  
  e->err = err;
  e->msg = (char*)"";
  return e;
}

ts_error_t* ts_error_create_msg(int err, const char* msg) {
  ts_error_t* e = ts_error_create(err);
  if (e == NULL) {
    return NULL;
  }
  
  e->msg = ts__strdup(msg);
  return 0;
}

void ts_error_destroy(ts_error_t* e) {
  if (e == NULL) {
    return;
  }
  
  if (ts_error_is_pre_defined_err(e->err)) {
    return; // no need to free
  }
  
  if (e->msg != NULL && strlen(e->msg) > 0) {
    ts__free(e->msg);
  }
  ts__free(e);
}