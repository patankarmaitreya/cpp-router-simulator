#pragma once

#include "protocols/ipv4.hpp"
#include "router/route.hpp"
#include <vector>

class RoutingTable{
    public:
        void add_route(const Route& route);
        std::optional<Route> lookup_linear(const IPv4Address& destination_ip) const;

    private:
        std::vector<Route> routes;
};

uint32_t generate_mask(size_t prefix_length);

bool matches_prefix(const IPv4Address& destination_ip, const IPv4Address& network_ip, size_t prefix_length);