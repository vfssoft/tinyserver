cmake_minimum_required(VERSION 3.23)
project(tests)

set(OPENSSL_ROOT_DIR "E:/ProgramFiles/OpenSSL")

include_directories(../src ../include ../libuv/include ${OPENSSL_ROOT_DIR}/include)

add_executable(tests
        test.c
		test-list.h
        basic_errors_test.c
        tcp_connect_test.c
        tcp_read_write_test.c
        testutil.h
        testutil.c
        tinyunit.h
        tinyunit.c
		mytcp.h
        mytcp.c
        )

target_link_libraries(tests server_lib)
