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

add_subdirectory(src)
add_subdirectory(mqtt)

add_subdirectory(test)
