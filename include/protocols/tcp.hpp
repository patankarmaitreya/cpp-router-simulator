#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>

struct TcpSegment{
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t sequence_number;
    uint32_t acknowledgment_number;
    uint8_t data_offset;
    size_t header_length;
    uint8_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
    size_t payload_offset;
    size_t payload_length;
};

std::optional<TcpSegment> parse_tcp(const uint8_t* data, size_t length);