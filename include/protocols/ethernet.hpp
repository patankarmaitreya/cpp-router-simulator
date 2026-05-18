#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

constexpr std::size_t kMacAddressLength = 6;

constexpr uint16_t kEtherTypeIPv4 = 0x0800;
constexpr uint16_t kEtherTypeARP  = 0x0806;

struct MacAddress{
    std::array<uint8_t, kMacAddressLength> bytes;
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

bool extract_mac(const std::vector<uint8_t>& packet, size_t start_index, MacAddress& out_mac);
