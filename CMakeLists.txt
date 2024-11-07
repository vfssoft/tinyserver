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

add_definitions(-DWITH_MEMORY_TRACKING -DTHREAD_API)

if(WIN32)
    set(SYS_DLL Psapi Iphlpapi Userenv Dbghelp)
else()
    set(SYS_DLL)
endif()

include (ExternalProject)
ExternalProject_Add(
        uv
        GIT_REPOSITORY https://github.com/libuv/libuv.git
        GIT_TAG v1.x
        BUILD_IN_SOURCE 1
        CMAKE_ARGS -DLIBUV_BUILD_SHARED=FALSE -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}/libuv -DBUILD_SHARED_LIBS=OFF
)

find_package(OpenSSL REQUIRED)
include_directories(include ${CMAKE_BINARY_DIR}/libuv/include)

add_subdirectory(server)
add_subdirectory(test)

install(
        DIRECTORY include/
        DESTINATION include
)
