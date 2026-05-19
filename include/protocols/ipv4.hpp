#pragma once

#include <array>
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

IPv4Address make_ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d);

uint32_t ipv4_to_uint32(const IPv4Address& ip);