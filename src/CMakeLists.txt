cmake_minimum_required(VERSION 3.23)

add_definitions(-DWITH_MEMORY_TRACKING)

set(SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR})

file(GLOB_RECURSE SRC_FILES ${SRC_DIR}/*.c ${SRC_DIR}/*.h)

add_library(server_lib STATIC ${SRC_FILES})

find_package(OpenSSL REQUIRED)
include_directories(../libuv/include ../include)

target_link_libraries(server_lib PRIVATE uv_a OpenSSL::SSL OpenSSL::Crypto)
