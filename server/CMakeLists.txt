cmake_minimum_required(VERSION 3.16)

set(SHARED_FILES
        ../shared/ts_data_buf.c
        ../shared/ts_error.c
        ../shared/ts_mem.c
        ../shared/ts_log.c
        ../shared/ts_miscellany.c
        ../shared/ts_crypto.c
)

file(GLOB_RECURSE SRC_FILES *.c)

add_library(ts STATIC ${SRC_FILES} ${SHARED_FILES})

add_dependencies(ts uv)

include_directories(../include ${CMAKE_BINARY_DIR}/libuv/include)
target_link_libraries(ts PRIVATE libuv OpenSSL::SSL OpenSSL::Crypto ${SYS_DLL})

install(
        TARGETS ts
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
)
