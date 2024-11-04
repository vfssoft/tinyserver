cmake_minimum_required(VERSION 3.16)
project(tests)

find_package(OpenSSL REQUIRED)
set(PAHO_ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/paho.mqtt.c")

include_directories(
        ../src
        ../include
        ${CMAKE_BINARY_DIR}/libuv/include
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
        mqtt_publish_test.c
        mqtt_msg_delivery_test.c
        mqtt_multi_pub_sub_test.c
        mqtt_topic_test.c
        testutil.h
        testutil.c
        tinyunit.h
        tinyunit.c
        mytcp.h
        mytcp.c
        mymqtt.h
        mymqtt.c
        test_mqtt_msgs.h
        test_mqtt_msgs.c
        ../src/ts_int_array.c
)

if (WIN32)
    set(MQTT3CS "paho-mqtt3cs-static.lib")
    set(MQTT_LIB_SUBDIR "Debug/")
else()
    set(MQTT3CS "libpaho-mqtt3cs.a")
    set(MQTT_LIB_SUBDIR "")
endif()

# Automatically build paho.mqtt.c
add_custom_command(
        OUTPUT ${PAHO_ROOT_DIR}/build/lib/${MQTT3CS}
        COMMAND ${CMAKE_COMMAND}  -E remove ${PAHO_ROOT_DIR}/build/CMakeCache.txt || true
        COMMAND ${CMAKE_COMMAND}  -E make_directory ${PAHO_ROOT_DIR}/build
        COMMAND ${CMAKE_COMMAND}  -E make_directory ${PAHO_ROOT_DIR}/build/include
        COMMAND ${CMAKE_COMMAND}  -E make_directory ${PAHO_ROOT_DIR}/build/lib
        COMMAND ${CMAKE_COMMAND} -DPAHO_WITH_SSL=TRUE -DPAHO_BUILD_STATIC=TRUE -DPAHO_ENABLE_TESTING=FALSE -S ${PAHO_ROOT_DIR}/ -B ${PAHO_ROOT_DIR}/build
        COMMAND ${CMAKE_COMMAND} --build ${PAHO_ROOT_DIR}/build
        COMMAND ${CMAKE_COMMAND} -E copy ${PAHO_ROOT_DIR}/src/MQTTAsync.h ${PAHO_ROOT_DIR}/build/include/MQTTAsync.h
        COMMAND ${CMAKE_COMMAND} -E copy ${PAHO_ROOT_DIR}/src/MQTTClient.h ${PAHO_ROOT_DIR}/build/include/MQTTClient.h
        COMMAND ${CMAKE_COMMAND} -E copy ${PAHO_ROOT_DIR}/src/MQTTClientPersistence.h ${PAHO_ROOT_DIR}/build/include/MQTTClientPersistence.h
        COMMAND ${CMAKE_COMMAND} -E copy ${PAHO_ROOT_DIR}/src/MQTTExportDeclarations.h ${PAHO_ROOT_DIR}/build/include/MQTTExportDeclarations.h
        COMMAND ${CMAKE_COMMAND} -E copy ${PAHO_ROOT_DIR}/src/MQTTProperties.h ${PAHO_ROOT_DIR}/build/include/MQTTProperties.h
        COMMAND ${CMAKE_COMMAND} -E copy ${PAHO_ROOT_DIR}/src/MQTTReasonCodes.h ${PAHO_ROOT_DIR}/build/include/MQTTReasonCodes.h
        COMMAND ${CMAKE_COMMAND} -E copy ${PAHO_ROOT_DIR}/src/MQTTSubscribeOpts.h ${PAHO_ROOT_DIR}/build/include/MQTTSubscribeOpts.h
        COMMAND ${CMAKE_COMMAND} -E copy ${PAHO_ROOT_DIR}/build/src/${MQTT_LIB_SUBDIR}${MQTT3CS} ${PAHO_ROOT_DIR}/build/lib/${MQTT3CS}
        COMMENT “Building dependency paho.mqtt.c”
)
add_custom_target(
        PreBuildPaho ALL
        DEPENDS ${PAHO_ROOT_DIR}/build/lib/${MQTT3CS}
)
add_dependencies(tests PreBuildPaho)


target_link_directories(tests PRIVATE ${PAHO_ROOT_DIR}/build/lib ${CMAKE_BINARY_DIR}/libuv/lib)
target_link_libraries(tests server_lib tm_lib libuv ${MQTT3CS} OpenSSL::SSL OpenSSL::Crypto Iphlpapi Userenv Dbghelp Psapi)
