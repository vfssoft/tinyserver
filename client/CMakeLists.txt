cmake_minimum_required(VERSION 3.16)

file(GLOB_RECURSE SRC_FILES *.c)

add_library(tsc STATIC ${SRC_FILES})

add_dependencies(tsc uv)

include_directories(../include ${CMAKE_BINARY_DIR}/libuv/include)
target_link_libraries(tsc PRIVATE libuv OpenSSL::SSL OpenSSL::Crypto ${SYS_DLL})

install(
        TARGETS tsc
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
)