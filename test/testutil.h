#ifndef TINYSERVER_TESTUTIL_H
#define TINYSERVER_TESTUTIL_H

#include <ts_tcp.h>

const char* cur_dir();

void start_server(ts_server_t* server, int proto);

#endif //TINYSERVER_TESTUTIL_H
