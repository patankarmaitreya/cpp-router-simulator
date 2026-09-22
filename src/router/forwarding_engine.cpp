#include "core/checksum.hpp"
#include "protocols/arp.hpp"
#include "protocols/ethernet.hpp"
#include "protocols/icmp.hpp"
#include "protocols/ipv4.hpp"
#include "router/arp_cache.hpp"
#include "router/interface.hpp"
#include "router/routing_table.hpp"
#include <cstddef>
#include <optional>
#include <router/forwarding_engine.hpp>
#include <router/packet_builder.hpp>

std::optional<RouterInterface> ForwardingEngine::find_interface_by_name( const std::string& name) const{
    for(size_t i=0; i<router_interface.size(); i++){
        if(router_interface[i].name == name) return router_interface[i];
    }

    return std::nullopt;
}

PacketResult ForwardingEngine::process_packet(std::vector<std::uint8_t> frame, RouterInterface in_interface){
    //short ethernet frame
    if(frame.size() < kEthernetHeaderLength){
        return PacketResult{
            ForwardAction::Dropped,
            "Malformed Ethernet frame",
            std::nullopt,
            std::nullopt
        };
    };

    auto ethernet_frame = parse_ethernet(frame);

    if(ethernet_frame.has_value())
    {
        if(ethernet_frame->ethernet_type != kEtherTypeARP && ethernet_frame->ethernet_type != kEtherTypeIPv4){
            return PacketResult{
                ForwardAction::Dropped,
                "Unsupported Ethertype",
                std::nullopt,
                std::nullopt
            };
        }
        else{
            if(ethernet_frame->ethernet_type ==kEtherTypeARP){
                auto arp_frame = parse_arp(frame.data() + ethernet_frame->payload_offset, ethernet_frame->payload_length);

                if(!arp_frame.has_value()){
                    return PacketResult{
                        ForwardAction::Dropped,
                        "Malformed ARP frame",
                        std::nullopt,
                        std::nullopt
                    };
                }

                if(arp_frame->opcode == ArpOpcode::reply)
                {
                    arp_cache.insert(arp_frame->sender_ip, arp_frame->sender_mac);
                    return PacketResult{
                        ForwardAction::Dropped,
                        "ARP reply processed and cache updated",
                        std::nullopt,
                        std::nullopt
                    };
                }

                if(arp_frame->opcode == ArpOpcode::request)
                {
 
                    std::optional<RouterInterface> match_interface;

                    for(size_t i=0; i < router_interface.size(); i++){
                        if(ipv4_to_uint32(arp_frame->target_ip) == ipv4_to_uint32(router_interface[i].ip)){
                            match_interface = router_interface[i];
                            break;
                        }
                    }

                    if(match_interface.has_value())
                    {   
                        //destination ip not requried for arp reply hecnce passing placeholder
                        ArpReplyBuilderInfo info(frame, match_interface->mac, ethernet_frame->source, match_interface->ip, make_ipv4(0, 0, 0,0 ), *arp_frame);
                        
                        return PacketResult{
                            ForwardAction::ArpReplyGenerated,
                            "Return ARP reply",
                            match_interface,
                            build_packet(info)
                        };  
                    }
                    else {
                        return PacketResult{
                            ForwardAction::Dropped,
                            "Not targetting any router interface",
                            std::nullopt,
                            std::nullopt
                        };
                    }
                }
                
                return PacketResult{
                    ForwardAction::Dropped,
                    "Unhandled ARP packet",
                    std::nullopt,
                    std::nullopt
                };
            }

            if(ethernet_frame->ethernet_type ==kEtherTypeIPv4){

                if(ethernet_frame->payload_length < 20){
                    return PacketResult{
                        ForwardAction::Dropped,
                        "Malformed IPv4 packet",
                        std::nullopt,
                        std::nullopt
                    };
                }

                auto ipv4_frame = parse_ipv4(frame.data() + ethernet_frame->payload_offset, ethernet_frame->payload_length);
                
                if(!ipv4_frame.has_value()){
                    return PacketResult{
                        ForwardAction::Dropped,
                        "Malformed IPv4 packet",
                        std::nullopt,
                        std::nullopt
                    };
                }

                if(!validate_ones_complement_checksum(frame.data() + ethernet_frame->payload_offset, ipv4_frame->header_length))
                {
                    return PacketResult{
                        ForwardAction::Dropped,
                        "Invalid IPv4 checksum",
                        std::nullopt,
                        std::nullopt
                    };
                }

                std::optional<RouterInterface> match_interface;
                for(size_t i=0; i < router_interface.size(); i++){
                    if(ipv4_to_uint32(ipv4_frame->destination_ip) == ipv4_to_uint32(router_interface[i].ip)){
                        match_interface = router_interface[i];
                        break;
                    }
                }


                if(match_interface.has_value())
                {
                    if(ipv4_frame->protocol == kIpProtocolICMP)
                    {
                        auto icmp_frame = parse_icmp(frame.data() + ethernet_frame->payload_offset + ipv4_frame->payload_offset, ipv4_frame->payload_length);   
                        
                        if(!icmp_frame.has_value())
                        {
                            return PacketResult{
                                ForwardAction::Dropped,
                                "Malformed ICMP frame",
                                std::nullopt,
                                std::nullopt
                            };
                        }
                        
                        if(icmp_frame->type == 0x08){

                            if(!validate_icmp_echo_request(icmp_frame))
                            {
                                return PacketResult{
                                    ForwardAction::Dropped,
                                    "Malformed ICMP frame",
                                    std::nullopt,
                                    std::nullopt
                                };
                            }
                            
                            IcmpEchoReplyBuilderInfo info(frame, ethernet_frame->destination, ethernet_frame-> source, ipv4_frame->destination_ip, ipv4_frame->source_ip, *icmp_frame, *ipv4_frame, *ethernet_frame);
                            return PacketResult{
                                ForwardAction::IcmpEchoReplyGenerated,
                                "ICMP echo request to router interface",
                                match_interface,
                                build_packet(info)
                            };
                        }
                        else{
                            return PacketResult{
                                ForwardAction::Dropped,
                                "Unsupported local ICMP type",
                                std::nullopt,
                                std::nullopt
                            };
                        }
                    }
                    else {
                        return PacketResult{
                            ForwardAction::Dropped,
                            "unsupported local protocol",
                            std::nullopt,
                            std::nullopt
                        };
                    }
                }
                

                if(ipv4_frame->ttl <= 1){

                    auto source_route = routing_table.lookup_trie(ipv4_frame->source_ip);

                    if(!source_route.has_value())
                    {
                        return PacketResult{
                            ForwardAction::Dropped,
                            "Route not present in routing table",
                            std::nullopt,
                            std::nullopt
                        }; 
                    }
                    
                    auto interface = find_interface_by_name(source_route->interface_name);
                    if(!interface.has_value())
                    {
                        return PacketResult{
                            ForwardAction::Dropped,
                            "source route interface not matching any of router interface",
                            std::nullopt,
                            std::nullopt
                        }; 
                    }

                    IPv4Address arp_target =
                        source_route->next_hop_ip.has_value()
                            ? *source_route->next_hop_ip
                            : ipv4_frame->source_ip;

                    auto arp_entry = arp_cache.lookup(arp_target);
                    
                    if(arp_entry.has_value())
                    {
                        IcmpTimeExceededBuilderInfo info(frame, interface->mac, arp_entry->mac, interface->ip, arp_entry->ip, *ipv4_frame, *ethernet_frame);

                        return PacketResult{
                            ForwardAction::IcmpTimeExceededGenerated,
                            "TTL expired",
                            interface,
                            build_packet(info)
                        };
                    }
                    else{
                        return PacketResult{
                            ForwardAction::Dropped,
                            "Arp target not present in cache",
                            std::nullopt,
                            std::nullopt
                        };  
                    }
                }

                auto route = routing_table.lookup_trie(ipv4_frame->destination_ip);

                if(!route.has_value())
                {
                    auto source_route = routing_table.lookup_trie(ipv4_frame->source_ip);
                    
                    if(!source_route.has_value())
                    {
                        return PacketResult{
                            ForwardAction::Dropped,
                            "Route not present in routing table",
                            std::nullopt,
                            std::nullopt
                        }; 
                    }
                    
                    auto interface = find_interface_by_name(source_route->interface_name);
                    if(!interface.has_value())
                    {
                        return PacketResult{
                            ForwardAction::Dropped,
                            "source route interface not matching any of router interface",
                            std::nullopt,
                            std::nullopt
                        }; 
                    }


                    IPv4Address arp_target =
                        source_route->next_hop_ip.has_value()
                            ? *source_route->next_hop_ip
                            : ipv4_frame->source_ip;

                    auto arp_entry = arp_cache.lookup(arp_target);
                    
                    if(arp_entry.has_value())
                    {
                        IcmpDestinationUnreachableBuilderInfo info(frame, interface->mac, arp_entry->mac, interface->ip, arp_entry->ip, *ipv4_frame, *ethernet_frame);

                        return PacketResult{
                            ForwardAction::IcmpDestinationUnreachableGenerated,
                            "Unreachable destination",
                            in_interface,
                            build_packet(info)
                        };
                    }
                    else{
                        return PacketResult{
                            ForwardAction::Dropped,
                            "Arp target not present in cache",
                            std::nullopt,
                            std::nullopt
                        }; 
                    }
                }
                auto out_interface = find_interface_by_name(route->interface_name);

                if (!out_interface.has_value()) {
                    return PacketResult{
                        ForwardAction::Dropped,
                        "Route refers to unknown interface",
                        std::nullopt,
                        std::nullopt
                    };
                }

                IPv4Address arp_target =
                route->next_hop_ip.has_value()
                    ? *route->next_hop_ip
                    : ipv4_frame->destination_ip;

                auto arp_entry = arp_cache.lookup(arp_target);

                if(!arp_entry.has_value())
                {
                    return PacketResult{
                        ForwardAction::QueuedPendingArp,
                        "Missing ARP entry",
                        out_interface,
                        std::nullopt
                    };
                }

                auto out_frame = frame;

                for(int i=0; i<6; i++){
                    out_frame[i] = arp_entry->mac.bytes[i];
                }

                for(int i=0; i<6; i++){
                    out_frame[i+6] = out_interface->mac.bytes[i];
                }

                size_t ip_start = ethernet_frame->payload_offset;
                
                out_frame[ip_start + 8] -= 1;

                out_frame[ip_start + 10] = 0;
                out_frame[ip_start + 11] = 0;

                auto new_checksum = compute_ones_complement_checksum(out_frame.data() + ip_start, ipv4_frame->header_length);
                
                out_frame[ip_start + 10] = (new_checksum >> 8) & 0xff;
                out_frame[ip_start + 11] = new_checksum & 0xff;
                
                return PacketResult{
                    ForwardAction::Forwarded,
                    "Packet forwarded",
                    out_interface,
                    out_frame
                };
            }
        }
    }

    return PacketResult{
        ForwardAction::Dropped,
        "Malformed Ethernet frame",
        std::nullopt,
        std::nullopt
    };
}