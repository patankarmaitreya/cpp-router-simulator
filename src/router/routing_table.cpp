#include "router/routing_table.hpp"
#include "protocols/ipv4.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <iostream>

void RoutingTable::add_route_linear(const Route& route) {
    routes.push_back(route);
}

void RoutingTable::add_route_trie(const Route& route) {
    if(route.prefix_length > 32){
        return;
    }
    
    TrieNode* curr = &root;

    if(route.prefix_length == 0){
        root.route = route;
        return;
    }

    int prefix_len = static_cast<int>(route.prefix_length);
    uint32_t network_num = ipv4_to_uint32(route.network_ip); 

    for(int i=31; i >= (32 - prefix_len); --i){
        uint32_t bit = (network_num >> i) & 1;

        if(bit == 1){
            if(curr->one_node == nullptr){
                curr->one_node = std::make_unique<TrieNode>();
            }
            curr = curr->one_node.get();
        }
        else{
            if(curr->zero_node == nullptr){
                curr->zero_node = std::make_unique<TrieNode>();
            }
            curr = curr->zero_node.get();
        }
    }
    curr->route = route;
}

std::optional<Route> RoutingTable::lookup_linear(const IPv4Address& destination_ip) const{
    std::optional<Route> best_match = std::nullopt;

    for(size_t i=0; i < routes.size(); i++){
        if(matches_prefix(destination_ip, routes[i].network_ip, routes[i].prefix_length)){
            if(!best_match.has_value() || routes[i].prefix_length > best_match->prefix_length){
                best_match = routes[i];
            }
        }
    }
    
    return best_match;
}

std::optional<Route> RoutingTable::lookup_trie(const IPv4Address& destination_ip) const{
    const TrieNode* curr = &root;

    uint32_t destination_num = ipv4_to_uint32(destination_ip); 
    std::optional<Route> best_match = root.route;
    for(int i=31; i>= 0; --i){
        uint32_t bit = (destination_num >> i) & 1;

        const TrieNode* nxt = (bit == 0) ? curr->zero_node.get() : curr->one_node.get();

        if(nxt == nullptr) break;
        curr = nxt;

        if(curr->route.has_value()) best_match  = curr->route;
    }

    return best_match;
}


uint32_t generate_mask(size_t prefix_length){
    if(prefix_length > 32){
        throw std::invalid_argument("Prefix length must be between 0 and 32");
    }

    if(prefix_length ==0) return 0x00000000u;

    return 0xffffffffu << (32 - prefix_length);
}

bool matches_prefix(const IPv4Address& destination_ip, const IPv4Address& network_ip, size_t prefix_length){
    if(prefix_length > 32) return false;

    uint32_t destination_ip_num = ipv4_to_uint32(destination_ip);
    uint32_t network_ip_num = ipv4_to_uint32(network_ip);
    
    uint32_t mask = generate_mask(prefix_length);

    return (destination_ip_num & mask) == (network_ip_num & mask);
}