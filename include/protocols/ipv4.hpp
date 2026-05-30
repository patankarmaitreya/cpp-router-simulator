#pragma once

#include <array>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <optional>

constexpr uint8_t kIpProtocolICMP = 1;
constexpr uint8_t kIpProtocolTCP = 6;
constexpr uint8_t kIpProtocolUDP = 17;

struct IPv4Address{
    std::array<uint8_t, 4> bytes;
};

struct IPv4Packet{
    uint8_t version;
    uint8_t ihl;
    size_t header_length;
    uint8_t dscp_ecn;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;
    IPv4Address source_ip;
    IPv4Address destination_ip;
    size_t payload_offset;
    size_t payload_length;
};


std::optional<IPv4Packet> parse_ipv4(const uint8_t* data, size_t length);

std::optional<IPv4Address> extract_ip(const uint8_t* packet, size_t length, size_t start_index);

IPv4Address make_ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d);

uint32_t ipv4_to_uint32(const IPv4Address& ip);

std::vector<uint8_t> generate_ipv4_header(const IPv4Address& destinationIP, const IPv4Address& sourceIP, const uint8_t protocol, const std::vector<uint8_t>& payload);