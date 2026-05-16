cmake_minimum_required(VERSION 3.25)

project(
    cpp-router-simulator
    VERSION 1.0.0
    DESCRIPTION "A project to simulate basic router packet processing behaviour in c++17"
    LANGUAGES CXX
)

add_executable(
    router_sim
    src/main.cpp
)

target_compile_options(
    router_sim
    PRIVATE
        -Wall
        -Wextra
        -Wpedantic
)

target_compile_features(
    router_sim
    PRIVATE cxx_std_17
)

