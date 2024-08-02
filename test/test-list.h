
#ifndef TINYSERVER_TEST_LIST_H
#define TINYSERVER_TEST_LIST_H


#include "tinyunit.h"


TEST_DECLARE(invalid_local_host)
TEST_DECLARE(invalid_local_host_2)
TEST_DECLARE(invalid_ssl_cert)

TEST_DECLARE(tcp_connect)
TEST_DECLARE(tls_connect)
TEST_DECLARE(tcp_server_disconnect)
TEST_DECLARE(tls_server_disconnect)

TEST_DECLARE(tcp_connect_disconnect_quick)
TEST_DECLARE(tcp_connect_disconnect_1s)
TEST_DECLARE(tls_connect_disconnect_quick)
TEST_DECLARE(tls_connect_disconnect_1s)

TEST_DECLARE(tcp_10clients_connect)
TEST_DECLARE(tcp_100clients_connect)
TEST_DECLARE(tls_10clients_connect)
TEST_DECLARE(tls_100clients_connect)

TEST_LIST_START
        TEST_ENTRY(invalid_local_host, "Error")
        TEST_ENTRY(invalid_local_host_2, "Error")
        TEST_ENTRY(invalid_ssl_cert, "Error")
        
        TEST_ENTRY(tcp_connect, "TCP,Connect")
        TEST_ENTRY(tls_connect, "TLS,Connect")
        TEST_ENTRY(tcp_server_disconnect, "TCP,Disconnect")
        TEST_ENTRY(tcp_connect_disconnect_quick, "TCP,Connect,Disconnect")
        TEST_ENTRY(tcp_connect_disconnect_1s, "TCP,Connect,Disconnect")
        TEST_ENTRY(tls_connect_disconnect_quick, "TLS,Connect,Disconnect")
        TEST_ENTRY(tls_connect_disconnect_1s, "TLS,Connect,Disconnect")
        TEST_ENTRY(tcp_10clients_connect, "TCP,Connect")
        TEST_ENTRY(tcp_100clients_connect, "TCP,Connect")
        TEST_ENTRY(tls_10clients_connect, "TLS,Connect")
        TEST_ENTRY(tls_100clients_connect, "TLS,Connect")
TEST_LIST_END

#endif //TINYSERVER_TEST_LIST_H
