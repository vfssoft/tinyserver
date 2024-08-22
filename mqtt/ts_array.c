#include "ts_array.h"

#define SIZE_OF_PTR (int)(sizeof(void*))

ts_ptr_arr_t* ts_ptr_arr__create(int initial_count) {
  ts_ptr_arr_t* arr;
  
  arr = (ts_ptr_arr_t*) ts__malloc(sizeof(ts_ptr_arr_t));
  if (arr == NULL) {
    return NULL;
  }
  
  arr->ptrs = ts_buf__create(initial_count * SIZE_OF_PTR);
  if (arr->ptrs == NULL) {
    return NULL;
  }
  
  return arr;
}
int ts_ptr_arr__destroy(ts_ptr_arr_t* arr) {
  if (arr->ptrs) {
    ts_buf__destroy(arr->ptrs);
  }
  arr->ptrs;
  
  ts__free(arr);
  
  return 0;
}

int ts_ptr_arr__set_count(ts_ptr_arr_t* arr, int len) {
  return ts_buf__set_length(arr->ptrs, len * SIZE_OF_PTR);
}
int ts_ptr_arr__get_count(ts_ptr_arr_t* arr) {
  return ts_buf__get_length(arr->ptrs) / SIZE_OF_PTR;
}

void* ts_ptr_arr__at(ts_ptr_arr_t* arr, int idx) {
  return (void*)(arr->ptrs + (idx * SIZE_OF_PTR));
}
void ts_ptr_arr__set(ts_ptr_arr_t* arr, int idx, void* ptr) {
  void* p = (void*)(arr->ptrs + (idx * SIZE_OF_PTR));
  memcpy(p, ptr, SIZE_OF_PTR);
}

int ts_ptr_arr__append(ts_ptr_arr_t* arr, void* ptr) {
  int err;
  int cur_count = ts_ptr_arr__get_count(arr);
  int cap_count = ts_buf__get_cap(arr->ptrs) / SIZE_OF_PTR;
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
  
  ts_ptr_arr__set(arr, cur_count, ptr);
  ts_ptr_arr__set_count(arr, cur_count+1);
  
  return 0;
}