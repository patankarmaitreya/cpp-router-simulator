#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

constexpr std::size_t kMacAddressLength = 6;
constexpr size_t kEthernetHeaderLength = 14;

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

std::optional<MacAddress> extract_mac(const uint8_t* packet, size_t length, size_t start_index);

bool extract_mac(const std::vector<uint8_t>& packet, size_t start_index, MacAddress& out_mac);

MacAddress make_mac(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e, uint8_t f);

std::vector<uint8_t> generate_ethernet_header(const MacAddress& destinationMAC, const MacAddress& sourceMAC, uint16_t type);