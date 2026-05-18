#include <cstddef>
#include <optional>
#include <protocols/ethernet.hpp>
#include <core/byte_utils.hpp>

constexpr size_t kEthernetHeaderLength = 14;
constexpr size_t kDestinationMacOffset = 0;
constexpr size_t kSourceMacOffset = 6;
constexpr size_t kEtherTypeOffset = 12;

std::optional<EthernetFrame> parse_ethernet(const std::vector<uint8_t>& packet){
    if(packet.size() < kEthernetHeaderLength) return std::nullopt;

    EthernetFrame frame;

    for(size_t i = 0; i< kMacAddressLength; i++){
        frame.destination.bytes[i] = packet[i + kDestinationMacOffset];
    }

    for(size_t i = 0; i< kMacAddressLength; i++){
        frame.destination.bytes[i] = packet[i + kSourceMacOffset];
    }

    auto value = read_u16_be(packet, kEtherTypeOffset);
    if(!value) return std::nullopt;

    frame.ethernet_type = *value;
    frame.payload_offset = kEthernetHeaderLength;
    frame.payload_length = packet.size() - kEthernetHeaderLength;

    return frame;
}

bool extract_mac(const std::vector<uint8_t>& packet, size_t start_index, MacAddress& out_mac){
    if(start_index > packet.size() || packet.size() - start_index < kMacAddressLength) return false;

    for(size_t i=0; i<kMacAddressLength; i++){
        out_mac.bytes[i] = packet[i + start_index];
    }

    return true;
}