#include "router/routing_table.hpp"
#include "protocols/ipv4.hpp"

#include <optional>

void RoutingTable::add_route(const Route& route) {
    routes.push_back(route);
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