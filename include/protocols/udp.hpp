#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>

struct UdpDatagram{
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t length;
    uint16_t checksum;
    size_t payload_offset;
    size_t payload_length;
};

std::optional<UdpDatagram> parse_udp(const uint8_t* data, size_t length);