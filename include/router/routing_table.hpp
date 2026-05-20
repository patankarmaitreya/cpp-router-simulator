#pragma once

#include "protocols/ipv4.hpp"
#include "router/route.hpp"
#include <memory>
#include <optional>
#include <vector>

struct TrieNode{
    std::unique_ptr<TrieNode> zero_node;
    std::unique_ptr<TrieNode> one_node;
    std::optional<Route> route;
};

class RoutingTable{
    public:
        void add_route_linear(const Route& route);
        void add_route_trie(const Route& route);
        std::optional<Route> lookup_linear(const IPv4Address& destination_ip) const;
        std::optional<Route> lookup_trie(const IPv4Address& destination_ip) const;

    private:
        std::vector<Route> routes;
        TrieNode root;
};

uint32_t generate_mask(size_t prefix_length);

bool matches_prefix(const IPv4Address& destination_ip, const IPv4Address& network_ip, size_t prefix_length);