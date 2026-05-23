include(FetchContent)

FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
)

FetchContent_MakeAvailable(googletest)

add_executable(
    router_tests
    test_byte_utils.cpp
    test_ethernet.cpp
    test_ipv4.cpp
    test_checksum.cpp
    test_routing_table.cpp
    test_arp_cache.cpp
    test_arp.cpp
    test_icmp.cpp
    test_tcp.cpp
    test_udp.cpp
    test_forwarding_engine.cpp
)

target_link_libraries(
    router_tests
    PRIVATE
        GTest::gtest_main
        CPP-ROUTER-SIMULATOR::core
        CPP-ROUTER-SIMULATOR::protocols
        CPP-ROUTER-SIMULATOR::router
)

include(GoogleTest)

gtest_discover_tests(router_tests)