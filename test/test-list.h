
#ifndef TINYSERVER_TEST_LIST_H
#define TINYSERVER_TEST_LIST_H


#include "tinyunit.h"


TEST_DECLARE(invalid_local_host)
TEST_DECLARE(invalid_local_host_2)
TEST_DECLARE(invalid_ssl_cert)

TEST_LIST_START
        TEST_ENTRY(invalid_local_host, {"Error"})
        TEST_ENTRY(invalid_local_host_2, {"Error"})
        TEST_ENTRY(invalid_ssl_cert, {"Error"})
TEST_LIST_END

#endif //TINYSERVER_TEST_LIST_H
