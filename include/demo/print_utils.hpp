#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "protocols/ethernet.hpp"
#include "protocols/ipv4.hpp"

namespace demo::print {

    void print_banner();

    std::string format_hex_u8(uint8_t val);
    std::string format_hex_u16(uint16_t val);
    std::string format_hex_u32(uint32_t val);

    std::string format_mac(const MacAddress& mac);
    std::string format_ipv4(const IPv4Address& mac);

    std::string ethernet_type_name(uint16_t ether_type);
    std::string ip_protocol_name(uint8_t protocol);

    void print_bytes(const std::vector<uint8_t>& data, size_t start, size_t count);
}