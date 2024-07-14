cmake_minimum_required(VERSION 3.23)
project(tinyserver)

add_subdirectory(libuv)
add_subdirectory(src)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_subdirectory(test/googletest)
add_subdirectory(test)
