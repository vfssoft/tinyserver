#include "internal/ts_int_array.h"


ts_int_arr_t* ts_int_arr__create(int initial_count) {
  ts_int_arr_t* arr;
  
  arr = (ts_int_arr_t*) ts__malloc(sizeof(ts_int_arr_t));
  if (arr == NULL) {
    return NULL;
  }
  
  arr->ptrs = ts_buf__create(initial_count * 8);
  if (arr->ptrs == NULL) {
    return NULL;
  }
  
  return arr;
}
int ts_int_arr__destroy(ts_int_arr_t* arr) {
  if (arr->ptrs) {
    ts_buf__destroy(arr->ptrs);
  }
  arr->ptrs = NULL;
  
  ts__free(arr);
  
  return 0;
}

int ts_int_arr__set_count(ts_int_arr_t* arr, int len) {
  return ts_buf__set_length(arr->ptrs, len * 8);
}
int ts_int_arr__get_count(ts_int_arr_t* arr) {
  return ts_buf__get_length(arr->ptrs) / 8;
}

long long ts_int_arr__at(ts_int_arr_t* arr, int idx) {
  long long val;
  memcpy(&val, (void*)(arr->ptrs + (idx * 8)), 8);
  return val;
}
void ts_int_arr__set(ts_int_arr_t* arr, int idx, long long ptr) {
  void* p = (void*)(arr->ptrs + (idx * 8));
  memcpy(p, &ptr, 8);
}

int ts_int_arr__append(ts_int_arr_t* arr, long long ptr) {
  int err;
  int cur_count = ts_int_arr__get_count(arr);
  int cap_count = ts_buf__get_cap(arr->ptrs) / 8;
  if (cur_count >= cap_count) {
    if (cur_count < 128) {
      err = ts_buf__set_cap(arr->ptrs, 2 * cur_count); // double the cap
      if (err) {
        return err;
      }
    } else {
      err = ts_buf__set_cap(arr->ptrs, 128 + cur_count); // increase by 128
      if (err) {
        return err;
      }
    }
  }
  
  ts_int_arr__set(arr, cur_count, ptr);
  ts_int_arr__set_count(arr, cur_count+1);
  
  return 0;
}
