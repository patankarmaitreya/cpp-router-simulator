add_executable(
    router_sim
    main.cpp
)

target_link_libraries(
    router_sim
    PRIVATE CPP-ROUTER-SIMULATOR::core
)

install(
    TARGETS router_sim
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)
