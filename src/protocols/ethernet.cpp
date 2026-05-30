#include <cstddef>
#include <cstdint>
#include <optional>
#include <protocols/ethernet.hpp>
#include <core/byte_utils.hpp>

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
        frame.source.bytes[i] = packet[i + kSourceMacOffset];
    }

    auto value = read_u16_be(packet, kEtherTypeOffset);
    if(!value) return std::nullopt;

    frame.ethernet_type = *value;
    frame.payload_offset = kEthernetHeaderLength;
    frame.payload_length = packet.size() - kEthernetHeaderLength;

    return frame;
}

std::optional<MacAddress> extract_mac(const uint8_t*packet, size_t length, size_t start_index){
    if(start_index > length || length - start_index < kMacAddressLength) return std::nullopt;

    MacAddress mac;
    for(size_t i=0; i<kMacAddressLength; i++){
        mac.bytes[i] = packet[i + start_index];
    }

    return mac;
}

bool extract_mac(const std::vector<uint8_t>& packet, size_t start_index, MacAddress& out_mac){
    if(start_index > packet.size() || packet.size() - start_index < kMacAddressLength) return false;

    for(size_t i=0; i<kMacAddressLength; i++){
        out_mac.bytes[i] = packet[i + start_index];
    }

    return true;
}


MacAddress make_mac(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e, uint8_t f){
    MacAddress mac{
        {a, b, c, d, e, f}
    };
    return mac;
}

std::vector<uint8_t> generate_ethernet_header(const MacAddress& destinationMAC, const MacAddress& sourceMAC, uint16_t type){
    std::vector<uint8_t> header(kEthernetHeaderLength);

    for(size_t i = 0; i< kMacAddressLength; i++){
        header[i] = destinationMAC.bytes[i];
    }

    for(size_t i = 0; i< kMacAddressLength; i++){
        header[6+i] = sourceMAC.bytes[i];
    }

    write_u16_be(header, 12, type);

    return header;
}