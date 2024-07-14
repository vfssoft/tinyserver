cmake_minimum_required(VERSION 3.23)
project(tests)

set(OPENSSL_ROOT_DIR "E:/ProgramFiles/OpenSSL")

include_directories(../src ../include ../libuv/include ${OPENSSL_ROOT_DIR}/include)

add_executable(tests
        test.cpp
        basic_errors_test.cpp
        mytcp.h
        mytcp.cpp
        tcp_connect_test.cpp
        tcp_read_write_test.cpp)

target_link_libraries(tests gtest gtest_main server_lib)
