cmake_minimum_required(VERSION 3.23)
project(tests)

set(OPENSSL_ROOT_DIR "E:/ProgramFiles/OpenSSL")
set(PAHO_ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/paho.mqtt.c")

include_directories(
        ../src
        ../include
        ../libuv/include
        ${OPENSSL_ROOT_DIR}/include
        ${PAHO_ROOT_DIR}/build/include
        ../mqtt
)

add_executable(tests
        test.c
        test-list.h
        basic_errors_test.c
        tcp_connect_test.c
        tcp_read_write_test.c
        tls_test.c
        mqtt_basic_test.c
        mqtt_invalid_packet_test.c
        mqtt_sub_unsub_test.c
        mqtt_topic_test.c
        testutil.h
        testutil.c
        tinyunit.h
        tinyunit.c
        mytcp.h
        mytcp.c
        mymqtt.h
        mymqtt.c
)

target_link_directories(tests PRIVATE ${PAHO_ROOT_DIR}/build/lib)
target_link_libraries(tests server_lib tm_lib paho-mqtt3cs-static)

# Automatically build paho.mqtt.c
add_custom_command(
        OUTPUT ${PAHO_ROOT_DIR}/build/lib/paho-mqtt3cs-static.lib
        COMMAND ${CMAKE_COMMAND}  -E make_directory ${PAHO_ROOT_DIR}/build
        COMMAND ${CMAKE_COMMAND}  -E make_directory ${PAHO_ROOT_DIR}/build/include
        COMMAND ${CMAKE_COMMAND}  -E make_directory ${PAHO_ROOT_DIR}/build/lib
        COMMAND cd  ${PAHO_ROOT_DIR}/build
        COMMAND ${CMAKE_COMMAND} -DPAHO_WITH_SSL=TRUE -DPAHO_BUILD_STATIC=TRUE -DPAHO_ENABLE_TESTING=FALSE ..
        COMMAND ${CMAKE_COMMAND} --build .
        COMMAND ${CMAKE_COMMAND} -E copy ${PAHO_ROOT_DIR}/src/MQTTAsync.h ${PAHO_ROOT_DIR}/build/include/MQTTAsync.h
        COMMAND ${CMAKE_COMMAND} -E copy ${PAHO_ROOT_DIR}/src/MQTTClient.h ${PAHO_ROOT_DIR}/build/include/MQTTClient.h
        COMMAND ${CMAKE_COMMAND} -E copy ${PAHO_ROOT_DIR}/src/MQTTClientPersistence.h ${PAHO_ROOT_DIR}/build/include/MQTTClientPersistence.h
        COMMAND ${CMAKE_COMMAND} -E copy ${PAHO_ROOT_DIR}/src/MQTTExportDeclarations.h ${PAHO_ROOT_DIR}/build/include/MQTTExportDeclarations.h
        COMMAND ${CMAKE_COMMAND} -E copy ${PAHO_ROOT_DIR}/src/MQTTProperties.h ${PAHO_ROOT_DIR}/build/include/MQTTProperties.h
        COMMAND ${CMAKE_COMMAND} -E copy ${PAHO_ROOT_DIR}/src/MQTTReasonCodes.h ${PAHO_ROOT_DIR}/build/include/MQTTReasonCodes.h
        COMMAND ${CMAKE_COMMAND} -E copy ${PAHO_ROOT_DIR}/src/MQTTSubscribeOpts.h ${PAHO_ROOT_DIR}/build/include/MQTTSubscribeOpts.h
        COMMAND ${CMAKE_COMMAND} -E copy ${PAHO_ROOT_DIR}/build/src/Debug/paho-mqtt3a-static.lib ${PAHO_ROOT_DIR}/build/lib/paho-mqtt3a-static.lib
        COMMAND ${CMAKE_COMMAND} -E copy ${PAHO_ROOT_DIR}/build/src/Debug/paho-mqtt3as-static.lib ${PAHO_ROOT_DIR}/build/lib/paho-mqtt3as-static.lib
        COMMAND ${CMAKE_COMMAND} -E copy ${PAHO_ROOT_DIR}/build/src/Debug/paho-mqtt3c-static.lib ${PAHO_ROOT_DIR}/build/lib/paho-mqtt3c-static.lib
        COMMAND ${CMAKE_COMMAND} -E copy ${PAHO_ROOT_DIR}/build/src/Debug/paho-mqtt3cs-static.lib ${PAHO_ROOT_DIR}/build/lib/paho-mqtt3cs-static.lib
        COMMENT “Building dependency paho.mqtt.c”
)
add_custom_target(
        PreBuildPaho ALL
        DEPENDS ${PAHO_ROOT_DIR}/build/lib/paho-mqtt3cs-static.lib
)
add_dependencies(tests PreBuildPaho)
