
#ifndef TINYSERVER_TS_DATA_BUF_H
#define TINYSERVER_TS_DATA_BUF_H

typedef struct ts_buf_s ts_buf_t;
typedef struct ts_ro_buf_s ts_ro_buf_t;

struct ts_buf_s {
    char* buf;
    int   len;
    int   cap;
    int   const_ref; // whether the buf is a const ref to another memory
};

// readonly buf
struct ts_ro_buf_s {
    const char* buf;
    int len;
};

ts_buf_t* ts_buf__create(int cap);
ts_buf_t* ts_buf__create_with_data(const char* data, int len);
void ts_buf__destroy(ts_buf_t* buf);
int ts_buf__set_length(ts_buf_t* buf, int len);
int ts_buf__get_length(ts_buf_t* buf);
int ts_buf__get_cap(ts_buf_t* buf);
int ts_buf__set_cap(ts_buf_t* buf, int cap);
int ts_buf__write(ts_buf_t* buf, const char* data, int len);
int ts_buf__read(ts_buf_t* buf, char* data, int* len);
int ts_buf__set(ts_buf_t* buf, const char* data, int len);
int ts_buf__set_str(ts_buf_t* buf, const char* str, int len);
int ts_buf__write_str(ts_buf_t* buf, const char* str, int len);
int ts_buf__set_const(ts_buf_t* buf, const char* data, int len);

int ts_buf__write_hex_dump(ts_buf_t* buf, const char* data, int len);

#endif //TINYSERVER_TS_DATA_BUF_H
