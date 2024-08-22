#ifndef TINYSERVER_TS_ARRAY_H
#define TINYSERVER_TS_ARRAY_H

#include <internal/ts_mem.h>
#include <internal/ts_data_buf.h>

typedef struct ts_ptr_arr_s ts_ptr_arr_t;

struct ts_ptr_arr_s {
  ts_buf_t* ptrs;
};

ts_ptr_arr_t* ts_ptr_arr__create(int initial_count);
int ts_ptr_arr__destroy(ts_ptr_arr_t* arr);

int ts_ptr_arr__set_count(ts_ptr_arr_t* arr, int len);
int ts_ptr_arr__get_count(ts_ptr_arr_t* arr);

void* ts_ptr_arr__at(ts_ptr_arr_t* arr, int idx);
void ts_ptr_arr__set(ts_ptr_arr_t* arr, int idx, void* ptr);

int ts_ptr_arr__append(ts_ptr_arr_t* arr, void* ptr);

#endif //TINYSERVER_TS_ARRAY_H

