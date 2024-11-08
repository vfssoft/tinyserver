cmake_minimum_required(VERSION 3.16)

include (ExternalProject)
ExternalProject_Add(
        tinyunit
        GIT_REPOSITORY https://github.com/vfssoft/tinyunit.git
        GIT_TAG main
        BUILD_IN_SOURCE 1
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}/tinyunit  -DBUILD_SHARED_LIBS=OFF
        UPDATE_COMMAND ""
)

enable_testing()

file(GLOB TEST_SRC_FILES "*.c")
add_executable(tests ${TEST_SRC_FILES})

add_dependencies(tests tinyunit)
add_dependencies(tests uv)

include_directories(tests PRIVATE ../include ${CMAKE_BINARY_DIR}/tinyunit/include)
target_link_directories(tests PRIVATE ${CMAKE_BINARY_DIR}/tinyunit/lib ${CMAKE_BINARY_DIR}/libuv/lib)
target_link_libraries(tests PRIVATE ts tinyunit_lib OpenSSL::SSL OpenSSL::Crypto)

add_test(NAME tests COMMAND tests)