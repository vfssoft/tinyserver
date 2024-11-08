#ifndef TINYSERVER_TESTUTIL_H
#define TINYSERVER_TESTUTIL_H

#include <ts.h>


#define RESET_STRUCT(s) memset(&s, 0, sizeof(s))

const char* cur_dir();

ts_t* start_server(int proto);

void assert_bytes_equals(const char* d1, int d1len, const char* d2, int d2len);

void decode_hex(const char* hex, unsigned char* bytes);


#endif //TINYSERVER_TESTUTIL_H
