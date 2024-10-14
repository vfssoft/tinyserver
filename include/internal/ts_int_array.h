
#ifndef TINYSERVER_TS_INT_ARRAY_H
#define TINYSERVER_TS_INT_ARRAY_H

#include <internal/ts_mem.h>
#include <internal/ts_data_buf.h>

typedef struct ts_int_arr_s ts_int_arr_t;

// Note:
// Don't use this struct if the size of the array will be large
// because each element will take 8 bytes no matter the elem is int8, int16, int32 or int64

struct ts_int_arr_s {
    ts_buf_t* ptrs;
};

ts_int_arr_t* ts_int_arr__create(int initial_count);
int ts_int_arr__destroy(ts_int_arr_t* arr);

int ts_int_arr__set_count(ts_int_arr_t* arr, int len);
int ts_int_arr__get_count(ts_int_arr_t* arr);

long long ts_int_arr__at(ts_int_arr_t* arr, int idx);
void ts_int_arr__set(ts_int_arr_t* arr, int idx, long long val);

int ts_int_arr__append(ts_int_arr_t* arr, long long ptr);

#endif //TINYSERVER_TS_INT_ARRAY_H
