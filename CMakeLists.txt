cmake_minimum_required(VERSION 3.16)
project(tinyserver)

# Option to use static or shared OpenSSL libraries
option(USE_STATIC_OPENSSL "Use static OpenSSL libraries" ON)

# Set the OpenSSL usage based on the option
if(USE_STATIC_OPENSSL)
    set(OPENSSL_USE_STATIC_LIBS TRUE)  # Use static libraries
else()
    set(OPENSSL_USE_STATIC_LIBS FALSE) # Use shared libraries
endif()

add_definitions(-DWITH_MEMORY_TRACKING)

if(WIN32)
    set(SYS_DLL Psapi Iphlpapi Userenv Dbghelp)
else()
    set(SYS_DLL)
endif()


include_directories(src)
file(GLOB_RECURSE SRC_FILES src/*.c)

add_library(ts STATIC ${SRC_FILES})

include (ExternalProject)
ExternalProject_Add(
        uv
        GIT_REPOSITORY https://github.com/libuv/libuv.git
        GIT_TAG v1.x
        BUILD_IN_SOURCE 1
        CMAKE_ARGS -DLIBUV_BUILD_SHARED=FALSE -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}/libuv -DBUILD_SHARED_LIBS=OFF
)
add_dependencies(ts uv)

link_directories(${CMAKE_BINARY_DIR}/libuv/lib)

find_package(OpenSSL REQUIRED)
include_directories(include ${CMAKE_BINARY_DIR}/libuv/include)

target_link_libraries(ts PRIVATE libuv OpenSSL::SSL OpenSSL::Crypto ${SYS_DLL})


enable_testing()

file(GLOB TEST_SRC_FILES "test/*.c")
add_executable(tests ${TEST_SRC_FILES})
target_link_libraries(tests PRIVATE ts OpenSSL::SSL OpenSSL::Crypto)

add_test(NAME tests COMMAND tests)

install(
        TARGETS ts
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
)

install(
        DIRECTORY include/
        DESTINATION include
)
