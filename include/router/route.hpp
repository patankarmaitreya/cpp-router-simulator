#pragma once


#include "protocols/ipv4.hpp"
#include <optional>
#include <string>

struct Route{
    IPv4Address network_ip;
    size_t prefix_length;
    std::string interface_name;
    std::optional<IPv4Address> next_hop_ip;
};