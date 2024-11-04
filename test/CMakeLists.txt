cmake_minimum_required(VERSION 3.16)
project(tests)

find_package(OpenSSL REQUIRED)

include_directories(
        ../src
        ../include
        ${CMAKE_BINARY_DIR}/libuv/include
)

add_executable(tests
        test.c
        test-list.h
        basic_errors_test.c
        tcp_connect_test.c
        tcp_read_write_test.c
        tls_test.c
        testutil.h
        testutil.c
        tinyunit.h
        tinyunit.c
        mytcp.h
        mytcp.c
)


target_link_directories(tests PRIVATE ${CMAKE_BINARY_DIR}/libuv/lib)
target_link_libraries(tests server_lib libuv OpenSSL::SSL OpenSSL::Crypto Iphlpapi Userenv Dbghelp Psapi)
