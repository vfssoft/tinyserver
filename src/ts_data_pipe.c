
#include "ts_internal.h"

static ts_stream_block_t* ts_stream_block__create() {
  ts_stream_block_t* sb = (ts_stream_block_t*) ts__malloc(sizeof(ts_stream_block_t));
  if (sb == NULL) {
    return NULL;
  }
  
  sb->buf = NULL;
  sb->offset = 0;
  sb->len = 0;
  
  sb->prev = NULL;
  sb->next = NULL;
  
  return sb;
}
static void ts_stream_block__destroy(ts_stream_block_t* sb) {
  if (sb) {
    if (sb->len) {
      ts__free(sb->buf);
    }
  
    ts__free(sb);
  }
}
static int ts_stream_block__set(ts_stream_block_t* sb, const char* data, int len) {
  sb->buf = (char*) ts__malloc(len);
  if (sb->buf == NULL) {
    return UV__EAI_MEMORY;
  }
  
  memcpy(sb->buf, data, len);
  sb->offset = 0;
  sb->len = len;
  return 0;
}

static ts_data_queue_t* ts_data_queue__create() {
  ts_data_queue_t* dq = (ts_data_queue_t*) ts__malloc(sizeof(ts_data_queue_t));
  if (dq == NULL) {
    return NULL;
  }
  
  dq->in = NULL;
  dq->out = NULL;
  return dq;
}
static void ts_data_queue__destroy(ts_data_queue_t* dq) {
  if (dq) {
  
    ts_stream_block_t* cur = NULL;
    ts_stream_block_t* tmp = NULL;
    
    if (dq->in) {
      DL_FOREACH_SAFE(dq->in, cur, tmp) {
        DL_DELETE(dq->in, cur);
        ts_stream_block__destroy(cur);
      }
    }
    
    if (dq->out) {
      DL_FOREACH_SAFE(dq->out, cur, tmp) {
        DL_DELETE(dq->out, cur);
        ts_stream_block__destroy(cur);
      }
    }
  
    ts__free(dq);
  }
}

static int ts_data_queue__write(ts_data_queue_t* dq, int inout, const char* data, int len) {
  ts_stream_block_t* block;
  
  block = ts_stream_block__create();
  if (block == NULL) {
    return UV__EAI_MEMORY;
  }
  
  if (inout) {
    DL_APPEND(dq->in, block);
  } else {
    DL_APPEND(dq->out, block);
  }
  
  return 0;
}
static int ts_data_queue__has_more(ts_data_queue_t* dq, int inout) {
  ts_stream_block_t* block = NULL;
  int counter = 0;
  if (inout) {
    DL_COUNT(dq->in, block, counter);
  } else {
    DL_COUNT(dq->out, block, counter);
  }
  return counter > 0;
}
static int ts_data_queue__read(ts_data_queue_t* dq, int inout, const char* data, int* len) {
  int read_offset = 0;
  ts_stream_block_t* cur = NULL;
  ts_stream_block_t* tmp = NULL;
  ts_stream_block_t* header = inout ? dq->in : dq->out;
  
  DL_FOREACH_SAFE(header, cur, tmp) {
    int cur_len = cur->len - cur->offset;
    int len_to_read = *len - read_offset > cur_len ? cur_len : *len - read_offset;
    
    if (data) {
      memcpy(data + read_offset, cur->buf + cur->offset, len_to_read);
    }
    
    read_offset += len_to_read;
    cur->offset += len_to_read;
    
    if (cur->offset == cur->len) {
      // all bytes are consumed, remove the current block from list
      DL_DELETE(header, cur);
    }
    
    if (read_offset == *len) {
      break;
    }
  }
  
  *len = read_offset;
  return 0;
}
static int ts_data_queue__peek(ts_data_queue_t* dq, int inout, char** data, int *out_len) {
  ts_stream_block_t* cur = NULL;
  ts_stream_block_t* tmp = NULL;
  ts_stream_block_t* header = inout ? dq->in : dq->out;
  
  *data = NULL;
  *out_len = 0;
  
  DL_FOREACH_SAFE(header, cur, tmp) {
    *data = cur->buf + cur->offset;
    *out_len = cur->len - cur->offset;
    break;
  }
  return 0;
}

ts_data_pipe_t* ts_data_pipe__create() {
  ts_data_pipe_t* dp = (ts_data_pipe_t*) ts__malloc(sizeof(ts_data_pipe_t));
  if (dp == NULL) {
    return NULL;
  }
  
  dp->filters = NULL; // no filter at the start
  dp->queue = ts_data_queue__create();
  if (dp->queue == NULL) {
    return NULL;
  }
  
  return dp;
}
void ts_data_pipe__destroy(ts_data_pipe_t* dp) {
  if (dp) {
    ts_data_queue__destroy(dp->queue);
    
    if (dp->filters) {
      ts_filter_cb_t* cur = NULL;
      ts_filter_cb_t* tmp = NULL;
  
      DL_FOREACH_SAFE(dp->filters, cur, tmp) {
        DL_DELETE(dp->filters, cur);
        ts__free(cur);
      }
    }
  
    ts__free(dp);
  }
}

int ts_data_pipe__write(ts_data_pipe_t* dp, int inout, const char* data, int len) {
  return ts_data_queue__write(dp->queue, inout, data, len);
}
int ts_data_pipe__read(ts_data_pipe_t* dp, int inout, const char* data, int* len) {
  return ts_data_queue__read(dp->queue, inout, data, len);
}
int ts_data_pipe__peek(ts_data_pipe_t* dp, int inout, char** data, int *out_len) {
  return ts_data_queue__peek(dp->queue, inout, data, out_len);
}

