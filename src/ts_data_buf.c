
#include "ts_internal.h"


static int ts_buf__const_ref_off(ts_buf_t* buf) {
  if (buf->const_ref == 1) {
    char* const_buf = buf->buf;
    buf->buf = (char*) ts__malloc(buf->len);
    if (buf->buf == NULL) {
      return TS_ERR_OUT_OF_MEMORY;
    }
    memcpy(buf->buf, const_buf, buf->len);

    buf->const_ref = 0;
  }
  return 0;
}

static int ts_buf__ensure_cap(ts_buf_t* buf, int cap) {
  int err;

  err = ts_buf__const_ref_off(buf);
  if (err) {
    return err;
  }

  if (buf->cap >= cap) {
    return 0;
  }

  char* newbuf = (char*) ts__malloc(cap);
  if (newbuf == NULL) {
    return UV__EAI_MEMORY;
  }

  if (buf->len > 0) {
    memcpy(newbuf, buf->buf, buf->len);
  }
  if (buf->cap > 0) {
    ts__free(buf->buf);
  }

  buf->buf = newbuf;
  buf->cap = cap;
  // len is kept unchanged
  return 0;
}

ts_buf_t* ts_buf__create(int cap) {
  ts_buf_t* buf = (ts_buf_t*) ts__malloc(sizeof(ts_buf_t));
  if (buf == NULL) {
    return NULL;
  }
  buf->buf = NULL;
  buf->cap = 0;
  buf->len = 0;
  buf->const_ref = 0;
  
  if (ts_buf__ensure_cap(buf, cap)) {
    return NULL;
  }
  
  return buf;
}
void ts_buf__destroy(ts_buf_t* buf) {
  if (buf) {
    if (buf->buf && buf->const_ref == 0) {
      ts__free(buf->buf);
    }
  
    ts__free(buf);
  }
}

int ts_buf__set_length(ts_buf_t* buf, int len) {
  int err = 0;
  
  err = ts_buf__ensure_cap(buf, len);
  if (err) {
    return err;
  }
  
  buf->len = len;
  return 0;
}
int ts_buf__get_length(ts_buf_t* buf) {
  return buf->len;
}

int ts_buf__write(ts_buf_t* buf, const char* data, int len) {
  int err;
  
  err = ts_buf__ensure_cap(buf, buf->len + len);
  if (err) {
    return err;
  }
  
  memcpy(buf->buf + buf->len, data, len);
  buf->len += len;
  return 0;
}
int ts_buf__read(ts_buf_t* buf, char* data, int* len) {
  int len_read = *len > buf->len ? buf->len : *len;
  // If data == NULL, we just drop the data
  if (data) {
    memcpy(data, buf->buf, len_read);
  }
  *len = len_read;

  buf->len -= len_read;
  if (buf->len > 0) {
    if (buf->const_ref == 1) {
      buf->buf += len_read;
    } else {
      memmove(buf->buf, buf->buf + len_read, buf->len);
    }
  }

  return 0;
}

int ts_buf__set(ts_buf_t* buf, const char* data, int len) {
  int err;
  
  err = ts_buf__ensure_cap(buf, len);
  if (err) {
    return err;
  }
  
  memcpy(buf->buf, data, len);
  buf->len = len;
  return 0;
}

int ts_buf__set_str(ts_buf_t* buf, const char* str, int len) {
  int err;
  
  err = ts_buf__ensure_cap(buf, len + 1); // extra one byte
  if (err) {
    return err;
  }
  
  err = ts_buf__set(buf, str, len);
  if (err) {
    return err;
  }
  
  buf->buf[buf->len] = 0; // ensure string terminates with '\0'
  return 0;
}

int ts_buf__set_const(ts_buf_t* buf, const char* data, int len) {
  buf->buf = (char*) data;
  buf->len = len;
  buf->cap = len;
  buf->const_ref = 1;
  return 0;
}