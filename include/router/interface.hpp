#pragma once

#include "protocols/ethernet.hpp"
#include <string>

#include <protocols/ethernet.hpp>
#include <protocols/ipv4.hpp>

struct RouterInterface{
    std::string name;
    MacAddress mac;
    IPv4Address ip;
};