cmake_minimum_required(VERSION 3.23)

set(SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR})

file(GLOB_RECURSE SRC_FILES ${SRC_DIR}/*.c ${SRC_DIR}/*.h)

add_library(tm_lib STATIC ${SRC_FILES})

include_directories(../include ../libuv/include ../include/internal  ../tinyserver/include)

target_link_libraries(tm_lib PRIVATE)