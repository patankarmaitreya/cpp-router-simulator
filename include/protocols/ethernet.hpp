#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

struct MacAddress{
    std::array<uint8_t, 6> bytes;
};

struct EthernetFrame{
    MacAddress destination;
    MacAddress source;
    uint16_t ethernet_type;
    size_t payload_offset;
    size_t payload_length;
};

std::optional<EthernetFrame> parse_ethernet(const std::vector<uint8_t>& packet);

std::string ethernettype_to_string(uint16_t value);
