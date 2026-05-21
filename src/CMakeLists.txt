add_library(
    core
    core/byte_utils.cpp
    core/checksum.cpp
)

add_library(
    CPP-ROUTER-SIMULATOR::core
    ALIAS core
)

add_library(
    protocols
    protocols/ethernet.cpp
    protocols/ipv4.cpp
    protocols/arp.cpp
    protocols/icmp.cpp
    protocols/tcp.cpp
    protocols/udp.cpp
)

add_library(
    CPP-ROUTER-SIMULATOR::protocols
    ALIAS protocols
)

add_library(
    demo
    demo/packet_samples.cpp
    demo/print_utils.cpp
)

add_library(
    CPP-ROUTER-SIMULATOR::demo
    ALIAS demo
)

add_library(
    router
    router/routing_table.cpp
    router/arp_cache.cpp
    router/forwarding_engine.cpp
)

add_library(
    CPP-ROUTER-SIMULATOR::router
    ALIAS router
)

target_compile_features(
    core
    PUBLIC cxx_std_17
)

target_compile_features(
    protocols
    PUBLIC cxx_std_17
)

target_compile_features(
    demo
    PUBLIC cxx_std_17
)


target_compile_features(
    router
    PUBLIC cxx_std_17
)

target_include_directories(
    core
    PUBLIC
        "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"   
        "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)

target_include_directories(
    protocols
    PUBLIC
        "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"   
        "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)

target_include_directories(
    demo
    PUBLIC
        "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"   
        "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)

target_include_directories(
    router
    PUBLIC
        "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"   
        "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)

install(
    TARGETS core
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)

install(
    TARGETS protocols
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)

install(
    TARGETS demo
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)

install(
    TARGETS router
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)