#pragma once

#include "protocols/ethernet.hpp"
#include <optional>
#include <protocols/ipv4.hpp>

enum class ArpOpcode: uint16_t{
    request = 1,
    reply = 2
};

struct ArpPacket{
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_add_len;
    uint8_t protocol_add_len;
    ArpOpcode opcode;
    MacAddress sender_mac;
    IPv4Address sender_ip;
    MacAddress target_mac;
    IPv4Address target_ip;
};

std::optional<ArpPacket> parse_arp(const uint8_t* data, size_t length);

std::vector<uint8_t> build_arp_reply_payload(const ArpPacket& arp_header, MacAddress router_mac, IPv4Address router_ip);