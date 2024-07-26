
#include "ts_internal.h"


static const char* ts_error_pre_def_err_msg(int err) {
  switch (err) {
    case TS_ERR_OUT_OF_MEMORY: return "out of memory";
    default: return "unknown error";
  }
}

void ts_error__init(ts_error_t* errt) {
  errt->err = 0;
  errt->msg = NULL;
}

void ts_error__reset(ts_error_t* errt) {
  errt->err = 0;
  if (errt->msg) {
    ts__free(errt->msg);
  }
  errt->msg = NULL;
}

// For predefined errors
void ts_error__set(ts_error_t* errt, int err) {
  ts_error__set_msg(errt, err, ts_error_pre_def_err_msg(err));
}

// For customer errors
void ts_error__set_msg(ts_error_t* errt, int err, const char* msg) {
  ts_error__reset(errt);
  errt->err = err;
  errt->msg = ts__strdup(msg);
}

// For customer errors
void ts_error__set_msgf(ts_error_t* errt, int err, const char* format, ...) {
  ts_error__reset(errt);
  
  char buf[1024];
  va_list args;
  va_start(args, format);
  snprintf(buf, sizeof(buf), format, args);
  va_end(args);

  errt->err = err;
  errt->msg = ts__strdup(buf);
}

void ts_error__copy(ts_error_t* dst, ts_error_t* src) {
  ts_error__set_msg(dst, src->err, src->msg);
}