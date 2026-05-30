#include <demo/router_samples.hpp>

namespace demo::samples {
    RoutingTable demo_routing_table()
    {
        RoutingTable table;

        table.add_route_trie(Route{
            make_ipv4(192, 168, 1, 0),
            24,
            "eth0",
            std::nullopt
        });

        table.add_route_trie(Route{
            make_ipv4(10, 0, 1, 0),
            24,
            "eth1",
            std::nullopt
        });

        return table;
    }
}