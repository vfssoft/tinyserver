cmake_minimum_required(VERSION 3.16)

add_definitions(-DWITH_MEMORY_TRACKING)

set(SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR})

file(GLOB_RECURSE SRC_FILES ${SRC_DIR}/*.c ${SRC_DIR}/*.h)

add_library(server_lib STATIC ${SRC_FILES})

include (ExternalProject)
ExternalProject_Add(
        uv
        GIT_REPOSITORY https://github.com/libuv/libuv.git
        GIT_TAG v1.x
        BUILD_IN_SOURCE 1
        CMAKE_ARGS -DLIBUV_BUILD_SHARED=FALSE -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}/libuv -DBUILD_SHARED_LIBS=OFF
)
add_dependencies(server_lib uv)

link_directories(${CMAKE_BINARY_DIR}/libuv/lib)


find_package(OpenSSL REQUIRED)
include_directories(../include ${CMAKE_BINARY_DIR}/libuv/include)

target_link_libraries(server_lib PRIVATE libuv OpenSSL::SSL OpenSSL::Crypto)

install(
        TARGETS server_lib
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
)

install(
        DIRECTORY ../include/
        DESTINATION include
)
