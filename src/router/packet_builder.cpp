#include "protocols/ethernet.hpp"
#include "protocols/icmp.hpp"
#include "protocols/ipv4.hpp"
#include "protocols/arp.hpp"
#include "router/interface.hpp"
#include <cstdint>
#include <router/packet_builder.hpp>
#include <vector>

std::vector<uint8_t> build_packet(const ArpReplyBuilderInfo& info){
    std::vector<uint8_t> final_frame;

    std::vector<uint8_t> arp_reply = build_arp_reply_payload(info.arp_packet, info.source_mac, info.source_ip);
    std::vector<uint8_t> ethernet_header = generate_ethernet_header(info.destination_mac, info.source_mac, kEtherTypeARP);
    
    final_frame.insert(final_frame.end(), ethernet_header.begin(), ethernet_header.end());
    final_frame.insert(final_frame.end(), arp_reply.begin(), arp_reply.end());

    return final_frame; 
}

std::vector<uint8_t> build_packet(const IcmpEchoReplyBuilderInfo& info){
     std::vector<uint8_t> final_frame;

    std::vector<uint8_t> icmp_reply = generate_icmp_reply_frame(info.input_frame.data() + info.ethernet_packet.payload_offset + info.ipv4_packet.payload_offset, info.ipv4_packet.payload_length, info.icmp_packet);
    std::vector<uint8_t> ipv4_header = generate_ipv4_header(info.destination_ip, info.source_ip, kIpProtocolICMP, icmp_reply);    
    std::vector<uint8_t> ethernet_header = generate_ethernet_header(info.destination_mac, info.source_mac, kEtherTypeIPv4);


    final_frame.insert(final_frame.end(), ethernet_header.begin(), ethernet_header.end());
    final_frame.insert(final_frame.end(), ipv4_header.begin(), ipv4_header.end());
    final_frame.insert(final_frame.end(), icmp_reply.begin(), icmp_reply.end());

    return final_frame; 
}

std::vector<uint8_t> build_packet(const IcmpTimeExceededBuilderInfo& info){
    std::vector<uint8_t> final_frame;
    
    std::vector<uint8_t> icmp_reply = build_icmp_time_exceeded(info.input_frame.data() + info.ethernet_packet.payload_offset,  info.ipv4_packet.total_length);
    
    std::vector<uint8_t> ipv4_header = generate_ipv4_header(info.destination_ip, info.source_ip, kIpProtocolICMP, icmp_reply);    
    std::vector<uint8_t> ethernet_header = generate_ethernet_header(info.destination_mac, info.source_mac, kEtherTypeIPv4);

    final_frame.insert(final_frame.end(), ethernet_header.begin(), ethernet_header.end());
    final_frame.insert(final_frame.end(), ipv4_header.begin(), ipv4_header.end());
    final_frame.insert(final_frame.end(), icmp_reply.begin(), icmp_reply.end());

    return final_frame;
}

std::vector<uint8_t> build_packet(const IcmpDestinationUnreachableBuilderInfo& info){
    std::vector<uint8_t> final_frame;
    
    std::vector<uint8_t> icmp_reply = build_icmp_destination_unreachable(info.input_frame.data() + info.ethernet_packet.payload_offset,  info.ipv4_packet.total_length);
    
    std::vector<uint8_t> ipv4_header = generate_ipv4_header(info.destination_ip, info.source_ip, kIpProtocolICMP, icmp_reply);    
    std::vector<uint8_t> ethernet_header = generate_ethernet_header(info.destination_mac, info.source_mac, kEtherTypeIPv4);

    final_frame.insert(final_frame.end(), ethernet_header.begin(), ethernet_header.end());
    final_frame.insert(final_frame.end(), ipv4_header.begin(), ipv4_header.end());
    final_frame.insert(final_frame.end(), icmp_reply.begin(), icmp_reply.end());

    return final_frame;
}

std::vector<uint8_t> build_icmp_error_frame(const std::vector<uint8_t>& inputFrame, const EthernetFrame& ethernetFrame, const IPv4Packet& ipv4Packet, uint8_t type, const RouterInterface& interface){
    std::vector<uint8_t> final_frame;

    std::vector<uint8_t> icmp_reply;
    if(type == kIcmpTypeTimeExcedded) icmp_reply = build_icmp_time_exceeded(inputFrame.data() + ethernetFrame.payload_offset,  ipv4Packet.total_length);
    if (type == kIcmpTypeDestUnreachable) icmp_reply = build_icmp_destination_unreachable(inputFrame.data() + ethernetFrame.payload_offset,  ipv4Packet.total_length);


    std::vector<uint8_t> ipv4_header = generate_ipv4_header(ipv4Packet.source_ip, interface.ip, kIpProtocolICMP, icmp_reply);    
    std::vector<uint8_t> ethernet_header = generate_ethernet_header(ethernetFrame.source, interface.mac, kEtherTypeIPv4);


    final_frame.insert(final_frame.end(), ethernet_header.begin(), ethernet_header.end());
    final_frame.insert(final_frame.end(), ipv4_header.begin(), ipv4_header.end());
    final_frame.insert(final_frame.end(), icmp_reply.begin(), icmp_reply.end());

    return final_frame;
}