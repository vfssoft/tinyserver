
#include "ts_internal.h"

static const char DECIMAL_TO_HEX_MAP[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
static const char ASCII_VISIABLE_CHAR_MAP[] = {
    '.', '.', '.', '.', '.', '.', '.', '.',   /* 0-7    :non visible */
    '.', '.', '.', '.', '.', '.', '.', '.',   /* 7-15   :non visible */
    '.', '.', '.', '.', '.', '.', '.', '.',   /* 16-23  :non visible */
    '.', '.', '.', '.', '.', '.', '.', '.',   /* 24-31  :non visible */
    '.', '!', '\"', '#', '$', '%', '&', '\'', /* 32-39  :            */ /* map whitespace as . */
    '(', ')', '*', '+', ',', '-', '.', '/',   /* 40-47  :            */
    '0', '1', '2', '3', '4', '5', '6', '7',   /* 48-55  :            */
    '8', '9', ':', ';', '<', '=', '>', '?',   /* 56-63  :            */
    '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G',   /* 64-71  :            */
    'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',   /* 72-79  :            */
    'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',   /* 80-87  :            */
    'X', 'Y', 'Z', '[', '\\', ']', '^', '_',  /* 88-95  :            */
    '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g',   /* 96-103 :            */
    'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',   /* 104-111:            */
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w',   /* 112-119:            */
    'x', 'y', 'z', '{', '|', '}', '~', '.',   /* 120-127:            */
};


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
ts_buf_t* ts_buf__create_with_data(const char* data, int len) {
  ts_buf_t* buf = ts_buf__create(len);
  if (buf == NULL) {
    return NULL;
  }
  
  if (ts_buf__write(buf, data, len)) {
    ts_buf__destroy(buf);
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
int ts_buf__get_cap(ts_buf_t* buf) {
  return buf->cap;
}
int ts_buf__set_cap(ts_buf_t* buf, int cap) {
  return ts_buf__ensure_cap(buf, cap);
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
int ts_buf__write_str(ts_buf_t* buf, const char* str, int len) {
  int err;
  
  err = ts_buf__ensure_cap(buf, buf->len + len + 1); // extra one byte for the NULL terminated char
  if (err) {
    return err;
  }
  
  memcpy(buf->buf + buf->len, str, len);
  buf->len += len;
  
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

int ts_buf__write_hex_dump(ts_buf_t* buf, const char* data, int len) {
  // "xxxxxxxx xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx    xxxxxxxx xxxxxxxx"
  char line[96] = { 0 };
  for (int i = 0; i < len; i += 16) {
    sprintf(line, "%08x", i);
    
    memset(line + 8, ' ', 79);
    if (i + 16 < len) {
      line[80] = '\n';
      line[81] = 0;
    } else {
      line[80] = 0;
    }
    
    int leftBytes = i + 16 > len ? len - i : 16;
    for (int j = 0; j < leftBytes; j++) {
      int index = 9 + (j < 8 ? j * 3 : j * 3 + 1);
      int c = data[i + j] & 0x0FF;
      
      line[index]   = DECIMAL_TO_HEX_MAP[(int)((c / 16) & 0x0FF)];
      line[index+1] = DECIMAL_TO_HEX_MAP[(int)((c % 16) & 0x0FF)];
      
      int index2 = 62 + (j < 8 ? j : j + 1);
      line[index2] = c >= 128 ? '.' : ASCII_VISIABLE_CHAR_MAP[c];
    }
    
    ts_buf__write_str(buf, line, i + 16 < len ? 81 : 80);
  }
  return 0;
}