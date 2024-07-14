cmake_minimum_required(VERSION 3.23)

add_definitions(-DWITH_MEMORY_TRACKING)

set(SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR})

file(GLOB_RECURSE SRC_FILES ${SRC_DIR}/*.c ${SRC_DIR}/*.h)

add_library(server_lib STATIC ${SRC_FILES})

set(OPENSSL_ROOT_DIR "E:/ProgramFiles/OpenSSL")

include_directories(../libuv/include ${OPENSSL_ROOT_DIR}/include ../include)

target_link_libraries(server_lib PRIVATE uv_a ${OPENSSL_ROOT_DIR}/lib/libssl_static.lib ${OPENSSL_ROOT_DIR}/lib/libcrypto_static.lib)
