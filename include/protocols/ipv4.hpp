#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>


struct IPAddress{
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
    IPAddress source_ip;
    IPAddress destination_ip;
    size_t payload_offset;
    size_t payload_length;
};


std::optional<IPv4Packet> parse_ipv4(const uint8_t* data, size_t length);