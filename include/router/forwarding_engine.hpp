#pragma once 

#include "router/arp_cache.hpp"
#include "router/interface.hpp"
#include "router/routing_table.hpp"
#include <cstdint>
#include <optional>
#include<string>
#include <vector>

enum class ForwardAction{
    Forwarded,
    Dropped,
    ArpReplyGenerated,
    IcmpEchoReplyGenerated,
    IcmpTimeExceededGenerated,
    IcmpDestinationUnreachableGenerated,
    QueuedPendingArp
};

struct PacketResult{
    ForwardAction action;
    std::string reason;
    std::optional<RouterInterface> output_interface;
    std::optional<std::vector<uint8_t>> output_bytes;
};

class ForwardingEngine{
    public:
        ForwardingEngine(std::vector<RouterInterface> interface, RoutingTable table, ARPCache cache) : 
        router_interface(std::move(interface)), routing_table(std::move(table)), arp_cache(std::move(cache)){}
        PacketResult process_packet(std::vector<std::uint8_t> frame, RouterInterface in_interface);
        std::optional<RouterInterface> find_interface_by_name( const std::string& name) const;

    private:
        std::vector<RouterInterface> router_interface;
        RoutingTable routing_table;
        ARPCache arp_cache;
};