cmake_minimum_required(VERSION 3.25)

project(
    cpp-router-simulator
    VERSION 1.0.0
    DESCRIPTION "A project to simulate basic router packet processing behaviour in c++17"
    LANGUAGES CXX
)


include(GNUInstallDirs)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_subdirectory(src)
add_subdirectory(app)

target_compile_options(
    router_sim
    PRIVATE
        -Wall
        -Wextra
        -Wpedantic
)

install(
    DIRECTORY "${PROJECT_SOURCE_DIR}/include/"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)