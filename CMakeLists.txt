cmake_minimum_required(VERSION 3.23)
project(tinyserver)

add_subdirectory(libuv)
add_subdirectory(src)

add_subdirectory(test)
