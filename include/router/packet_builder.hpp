#pragma once

#include "protocols/ethernet.hpp"
#include "protocols/icmp.hpp"
#include "protocols/ipv4.hpp"
#include "protocols/arp.hpp"
#include "router/interface.hpp"
#include <vector>
#include <cstdint>

struct BuilderInfo{
    const std::vector<uint8_t>& input_frame;

    MacAddress source_mac;
    MacAddress destination_mac;

    IPv4Address source_ip;
    IPv4Address destination_ip;

    virtual ~BuilderInfo() = default;

    BuilderInfo(const std::vector<uint8_t>& frame, MacAddress src_mac, MacAddress dst_mac, IPv4Address src_ip, IPv4Address dst_ip) : 
        input_frame(frame), source_mac(src_mac), destination_mac(dst_mac), source_ip(src_ip), destination_ip(dst_ip){};

};

struct ArpReplyBuilderInfo : BuilderInfo{
    ArpPacket arp_packet;
     
    ArpReplyBuilderInfo(const std::vector<uint8_t>& frame, MacAddress src_mac, MacAddress dst_mac, IPv4Address src_ip, IPv4Address dst_ip, ArpPacket packet) : 
        BuilderInfo(frame, src_mac, dst_mac, src_ip, dst_ip), arp_packet(packet){};
};

struct IcmpEchoReplyBuilderInfo : BuilderInfo{
    IcmpPacket icmp_packet;
    IPv4Packet ipv4_packet;
    EthernetFrame ethernet_packet;

    IcmpEchoReplyBuilderInfo(const std::vector<uint8_t>& frame, MacAddress src_mac, MacAddress dst_mac, IPv4Address src_ip, IPv4Address dst_ip, IcmpPacket icmp_pac, IPv4Packet ipv4_pac, EthernetFrame ethernet_pac) : 
        BuilderInfo(frame, src_mac, dst_mac, src_ip, dst_ip), icmp_packet(icmp_pac), ipv4_packet(ipv4_pac), ethernet_packet(ethernet_pac){};
};

struct IcmpTimeExceededBuilderInfo : BuilderInfo{
    IPv4Packet ipv4_packet;
    EthernetFrame ethernet_packet;
    
    IcmpTimeExceededBuilderInfo(const std::vector<uint8_t>& frame, MacAddress src_mac, MacAddress dst_mac, IPv4Address src_ip, IPv4Address dst_ip, IPv4Packet ipv4_pac, EthernetFrame ehternet_pac) : 
        BuilderInfo(frame, src_mac, dst_mac, src_ip, dst_ip), ipv4_packet(ipv4_pac), ethernet_packet(ehternet_pac){};
};

struct IcmpDestinationUnreachableBuilderInfo : BuilderInfo{
    IPv4Packet ipv4_packet;
    EthernetFrame ethernet_packet;
    
    IcmpDestinationUnreachableBuilderInfo(const std::vector<uint8_t>& frame, MacAddress src_mac, MacAddress dst_mac, IPv4Address src_ip, IPv4Address dst_ip, IPv4Packet ipv4_pac, EthernetFrame ehternet_pac) : 
        BuilderInfo(frame, src_mac, dst_mac, src_ip, dst_ip), ipv4_packet(ipv4_pac), ethernet_packet(ehternet_pac){};
};

std::vector<uint8_t> build_packet(const ArpReplyBuilderInfo& info);

std::vector<uint8_t> build_packet(const IcmpEchoReplyBuilderInfo& info);

std::vector<uint8_t> build_packet(const IcmpTimeExceededBuilderInfo& info);

std::vector<uint8_t> build_packet(const IcmpDestinationUnreachableBuilderInfo& info);