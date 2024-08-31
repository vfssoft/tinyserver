
#ifndef TINYSERVER_TEST_LIST_H
#define TINYSERVER_TEST_LIST_H


#include "tinyunit.h"


TEST_DECLARE(invalid_local_host)
TEST_DECLARE(invalid_local_host_2)
TEST_DECLARE(invalid_ssl_cert)

TEST_DECLARE(tcp_connect)
TEST_DECLARE(tls_connect)
TEST_DECLARE(ws_connect)
TEST_DECLARE(wss_connect)
TEST_DECLARE(tcp_server_disconnect)
TEST_DECLARE(tls_server_disconnect)
TEST_DECLARE(ws_server_disconnect)
TEST_DECLARE(wss_server_disconnect)

TEST_DECLARE(tcp_connect_disconnect_quick)
TEST_DECLARE(tls_connect_disconnect_quick)
TEST_DECLARE(ws_connect_disconnect_quick)
TEST_DECLARE(wss_connect_disconnect_quick)
TEST_DECLARE(tcp_connect_disconnect_1s)
TEST_DECLARE(tls_connect_disconnect_1s)
TEST_DECLARE(ws_connect_disconnect_1s)
TEST_DECLARE(wss_connect_disconnect_1s)

TEST_DECLARE(tcp_10clients_connect)
TEST_DECLARE(tls_10clients_connect)
TEST_DECLARE(ws_10clients_connect)
TEST_DECLARE(wss_10clients_connect)
TEST_DECLARE(tcp_100clients_connect)
TEST_DECLARE(tls_100clients_connect)
TEST_DECLARE(ws_100clients_connect)
TEST_DECLARE(wss_100clients_connect)

TEST_DECLARE(tcp_echo)
TEST_DECLARE(tls_echo)
TEST_DECLARE(ws_echo)
TEST_DECLARE(wss_echo)
TEST_DECLARE(tcp_echo_1k)
TEST_DECLARE(tls_echo_1k)
TEST_DECLARE(ws_echo_1k)
TEST_DECLARE(wss_echo_1k)
TEST_DECLARE(tcp_echo2)
TEST_DECLARE(tls_echo2)
TEST_DECLARE(ws_echo2)
TEST_DECLARE(wss_echo2)
TEST_DECLARE(tcp_echo_1k_data)
TEST_DECLARE(tls_echo_1k_data)
TEST_DECLARE(ws_echo_1k_data)
TEST_DECLARE(wss_echo_1k_data)
TEST_DECLARE(tcp_echo_10m_data)
TEST_DECLARE(tls_echo_10m_data)
TEST_DECLARE(ws_echo_10m_data)
TEST_DECLARE(wss_echo_10m_data)


TEST_DECLARE(mqtt_connect_tcp)
TEST_DECLARE(mqtt_connect_tls)
TEST_DECLARE(mqtt_connect_ws)
TEST_DECLARE(mqtt_connect_wss)

TEST_DECLARE(mqtt_auth_user)
TEST_DECLARE(mqtt_auth_user_fail)

TEST_LIST_START
        TEST_ENTRY(invalid_local_host, "Error")
        TEST_ENTRY(invalid_local_host_2, "Error")
        TEST_ENTRY(invalid_ssl_cert, "Error")
        
        TEST_ENTRY(tcp_connect, "TCP")
        TEST_ENTRY(tls_connect, "TLS")
        TEST_ENTRY(ws_connect, "Websocket")
        TEST_ENTRY(wss_connect, "Websocket,TLS")
        TEST_ENTRY(tcp_server_disconnect, "TCP")
        TEST_ENTRY(tls_server_disconnect, "TLS")
        TEST_ENTRY(ws_server_disconnect, "Websocket")
        TEST_ENTRY(wss_server_disconnect, "Websocket,TLS")
        TEST_ENTRY(tcp_connect_disconnect_quick, "TCP")
        TEST_ENTRY(tls_connect_disconnect_quick, "TLS")
        TEST_ENTRY(ws_connect_disconnect_quick, "Websocket")
        TEST_ENTRY(wss_connect_disconnect_quick, "Websocket,TLS")
        
        TEST_ENTRY(tcp_connect_disconnect_1s, "TCP")
        TEST_ENTRY(tls_connect_disconnect_1s, "TLS")
        TEST_ENTRY(ws_connect_disconnect_1s, "Websocket")
        TEST_ENTRY(wss_connect_disconnect_1s, "Websocket,TLS")
        
        TEST_ENTRY(tcp_10clients_connect, "TCP")
        TEST_ENTRY(tls_10clients_connect, "TLS")
        TEST_ENTRY(ws_10clients_connect, "Websocket")
        TEST_ENTRY(wss_10clients_connect, "TLS,Websocket")
        TEST_ENTRY(tcp_100clients_connect, "TCP")
        TEST_ENTRY(tls_100clients_connect, "TLS")
        TEST_ENTRY(ws_100clients_connect, "Websocket")
        TEST_ENTRY(wss_100clients_connect, "TLS,Websocket")
        

        TEST_ENTRY(tcp_echo, "TCP")
        TEST_ENTRY(tls_echo, "TLS")
        TEST_ENTRY(ws_echo, "Websocket")
        TEST_ENTRY(wss_echo, "TLS,Websocket")
        TEST_ENTRY(tcp_echo_1k, "TCP")
        TEST_ENTRY(tls_echo_1k, "TLS")
        TEST_ENTRY(ws_echo_1k, "Websocket")
        TEST_ENTRY(wss_echo_1k, "TLS,Websocket")
        TEST_ENTRY(tcp_echo2, "TCP")
        TEST_ENTRY(tls_echo2, "TLS")
        TEST_ENTRY(ws_echo2, "Websocket")
        TEST_ENTRY(tls_echo2, "TLS,Websocket")
        TEST_ENTRY(tcp_echo_1k_data, "TCP")
        TEST_ENTRY(tls_echo_1k_data, "TLS")
        TEST_ENTRY(ws_echo_1k_data, "Websocket")
        TEST_ENTRY(wss_echo_1k_data, "TLS,Websocket")
        TEST_ENTRY(tcp_echo_10m_data, "TCP")
        TEST_ENTRY(tls_echo_10m_data, "TLS")
        TEST_ENTRY(ws_echo_10m_data, "Websocket")
        TEST_ENTRY(wss_echo_10m_data, "TLS,Websocket")


        TEST_ENTRY(mqtt_connect_tcp, "TCP,MQTT")
        TEST_ENTRY(mqtt_connect_tls, "TLS,MQTT")
        TEST_ENTRY(mqtt_connect_ws, "Websocket,MQTT")
        TEST_ENTRY(mqtt_connect_wss, "Websocket,TLS,MQTT")
        
        TEST_ENTRY(mqtt_auth_user, "MQTT")
        TEST_ENTRY(mqtt_auth_user_fail, "MQTT")
        
TEST_LIST_END

#endif //TINYSERVER_TEST_LIST_H
