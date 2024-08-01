cmake_minimum_required(VERSION 3.23)
project(tests)

set(OPENSSL_ROOT_DIR "E:/ProgramFiles/OpenSSL")

include_directories(../src ../include ../libuv/include ${OPENSSL_ROOT_DIR}/include)

if (WIN32)
    set(TINY_UNIT_SRC
            tinyunit/task.h
            tinyunit/runner.h
            tinyunit/runner-win.h
            tinyunit/runner-win.c
            tinyunit/runner.c)
else()
    set(TINY_UNIT_SRC
            tinyunit/task.h
            tinyunit/runner.h
            tinyunit/runner-unix.h
            tinyunit/runner-unix.c
            tinyunit/runner.c)
endif()


add_executable(tests
        test.cpp
        basic_errors_test.cpp
        mytcp.h
        mytcp.cpp
        tcp_connect_test.cpp
        tcp_read_write_test.cpp
        testutil.h
        testutil.cpp
        ${TINY_UNIT_SRC}
        )

target_link_libraries(tests gtest gtest_main server_lib)
