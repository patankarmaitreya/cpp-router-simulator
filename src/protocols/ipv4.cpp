#include "protocols/ipv4.hpp"
#include "core/byte_utils.hpp"
#include <cstdint>
#include <iostream>
#include <optional>

std::optional<IPv4Packet> parse_ipv4(const uint8_t* data, size_t length){
    if(length < 20){
        std::cout << "lenghth less than minimum ipv4 packet legth of 20" << std::endl;
        return std::nullopt;
    }
    IPv4Packet frame;

    frame.version = data[0] >> 4;
    frame.ihl = data[0] & 0x0F;
    frame.header_length = frame.ihl * 4; // IHL is the number of 32-bit (4 byte) words.
    
    //if version no 4 this is not ipv4
    if(frame.version != 4) return std::nullopt;
    //if IHL < 5 then headr lenght becomes < 20 which is incorrect
    if(frame.ihl < 5) return std::nullopt;

    if(frame.header_length > length) return std::nullopt;

    auto total_length = read_u16_be(data, length, 2);
    if(!total_length.has_value()) return std::nullopt;

    frame.total_length = *total_length;

    if(frame.total_length > length) return std::nullopt;

    if(frame.header_length > frame.total_length) return std::nullopt;

    auto id = read_u16_be(data, length,4);
    if(!id.has_value()) return std::nullopt;
    frame.id = *id;


    auto flags = read_u16_be(data, length,6);
    if(!flags.has_value()) return std::nullopt;

    frame.flags = *flags;
    
    frame.ttl = data[8];
    frame.protocol = data[9];

    auto header_checksum = read_u16_be(data, length,10);
    if(!header_checksum.has_value()) return std::nullopt;

    frame.header_checksum = *header_checksum;

    for(size_t i = 0; i< 4; i++){
        frame.source_ip.bytes[i] = data[i + 12];
    }


    for(size_t i = 0; i< 4; i++){
        frame.destination_ip.bytes[i] = data[i + 16];
    }

    frame.payload_offset = frame.header_length;
    frame.payload_length = frame.total_length - frame.header_length;

    return frame;
}

IPv4Address make_ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d){
    IPv4Address ip{
        {a, b, c, d}
    };
    return ip;
}

uint32_t ipv4_to_uint32(const IPv4Address &ip){
    return (static_cast<uint32_t>(ip.bytes[0] << 24) |
            static_cast<uint32_t>(ip.bytes[1] << 16) |
            static_cast<uint32_t>(ip.bytes[2] << 8) |
            static_cast<uint32_t>(ip.bytes[3]) 
        );
}