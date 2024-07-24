
#include "ts_internal.h"

static ts_error_t pre_def_errs[] = {
    { TS_ERR_OUT_OF_MEMORY, (char*)"out of memory" }
};

static int ts_error__is_pre_defined_err(int err) {
  int pre_def_errs_len = sizeof(pre_def_errs) / sizeof(ts_error_t);
  return err < pre_def_errs_len;
}

void ts_error__init(ts_error_t* errt) {
  errt->err = 0;
  errt->msg = NULL;
}

void ts_error__reset(ts_error_t* errt) {
  if (ts_error__is_pre_defined_err(errt->err)) {
    errt->err = 0;
    errt->msg = NULL;
  } else {
    errt->err = 0;
    if (errt->msg) {
      ts__free(errt->msg);
    }
    errt->msg = NULL;
  }
}

// For predefined errors
void ts_error__set(ts_error_t* errt, int err) {
  assert(ts_error__is_pre_defined_err(err));
  ts_error__reset(errt);

  errt->err = err;
  errt->msg = pre_def_errs[err].msg;
}

// For customer errors
void ts_error__set_msg(ts_error_t* errt, int err, const char* msg) {
  assert(!ts_error__is_pre_defined_err(err));
  ts_error__reset(errt);

  errt->err = err;
  errt->msg = ts__strdup(msg);
}

// For customer errors
void ts_error__set_msgf(ts_error_t* errt, int err, const char* format, ...) {
  assert(!ts_error__is_pre_defined_err(err));
  ts_error__reset(errt);



  char buf[1024];
  va_list args;
  va_start(args, format);
  snprintf(buf, sizeof(buf), format, args);
  va_end(args);

  errt->err = err;
  errt->msg = ts__strdup(buf);
}