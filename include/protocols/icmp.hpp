#pragma once

#include <cstdint>
#include <optional>
#include <vector> 

struct IcmpPacket{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    std::optional<uint16_t> identifier;
    std::optional<uint16_t> sequence_number;
    size_t payload_offset;
    size_t payload_length;
};

std::optional<IcmpPacket> parse_icmp(const uint8_t* data, size_t length);

std::vector<uint8_t> generate_icmp_reply_frame(const uint8_t* request_data, size_t request_length, const IcmpPacket& request);

std::vector<uint8_t> build_icmp_error_message(uint8_t type, uint8_t code, const uint8_t* ipv4_data, size_t ipv4_length);

std::vector<uint8_t> build_icmp_time_exceeded( const uint8_t* ipv4_data, size_t ipv4_length); 

std::vector<uint8_t> build_icmp_destination_unreachable( const uint8_t* ipv4_data, size_t ipv4_length); 