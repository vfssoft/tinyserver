cmake_minimum_required(VERSION 3.23)
project(tests)

set(OPENSSL_ROOT_DIR "E:/ProgramFiles/OpenSSL")

add_definitions(-DPAHO_WITH_SSL=TRUE -DPAHO_ENABLE_TESTING=FALSE -DTEST_MQTT)

add_subdirectory(paho.mqtt.c)

include_directories(../src ../include ../libuv/include ${OPENSSL_ROOT_DIR}/include paho.mqtt.c)

add_executable(tests
        test.c
        test-list.h
        basic_errors_test.c
        tcp_connect_test.c
        tcp_read_write_test.c
        mqtt_basic_test.c
        testutil.h
        testutil.c
        tinyunit.h
        tinyunit.c
        mytcp.h
        mytcp.c
        mymqtt.h
        mymqtt.c
        )

target_link_libraries(tests server_lib tm_lib paho-mqtt3c)
