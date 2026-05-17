#include <cstddef>
#include <optional>
#include <protocols/ethernet.hpp>
#include <core/byte_utils.hpp>

std::optional<EthernetFrame> parse_ethernet(const std::vector<uint8_t>& packet){
    if(packet.size() < 14) return std::nullopt;

    size_t offset = 0;
    EthernetFrame frame;

    for(size_t i = 0; i< 6; i++){
        frame.destination.bytes[i] = packet[i];
    }

    for(size_t i = 0; i< 6; i++){
        frame.destination.bytes[i] = packet[6 + i];
    }

    auto value = read_u16_be(packet, 12);
    if(!value) return std::nullopt;

    frame.ethernet_type = *value;
    frame.payload_offset = 14;
    frame.payload_length = packet.size()-14;

    return frame;
}

std::string ethernettype_to_string(uint16_t value){
    if(value == 0x0800){
        return "IPv4";
    }
    else if(value == 0x0806){
        return "ARP"; 
    }
    else{
        return "Unknown";
    }
}