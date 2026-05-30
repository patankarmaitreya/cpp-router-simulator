#include "protocols/ipv4.hpp"
#include "core/checksum.hpp"
#include "protocols/ethernet.hpp"
#include "core/byte_utils.hpp"
#include <cstdint>
#include <optional>
#include <vector>

std::optional<IPv4Packet> parse_ipv4(const uint8_t* data, size_t length){
    if(length < 20) return std::nullopt;
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

std::optional<IPv4Address> extract_ip(const uint8_t* packet, size_t length, size_t start_index){
    if(start_index > length || length - start_index < 4) return std::nullopt;

    IPv4Address ip;
    for(size_t i=0; i<4; i++){
        ip.bytes[i] = packet[i + start_index];
    }

    return ip;    
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

std::vector<uint8_t> generate_ipv4_header(const IPv4Address& destinationIP, const IPv4Address& sourceIP, const uint8_t protocol, const std::vector<uint8_t>& payload)
{
    std::vector<uint8_t> header(20);

    header[0] = 0x45;//version + ihl
     
    header[1] = 0x00;//dcp/ecn
    
    size_t total_length = 20 + payload.size();
    write_u16_be(header, 2, total_length);//total length

    write_u16_be(header, 4, 0);//id
    write_u16_be(header, 6, 0);//flags

    header[8] = 0x40;//ttl
    header[9] = protocol;//protocol

    write_u16_be(header, 10, 0);

    for(int i=0; i<sourceIP.bytes.size(); i++){
        header[12+i] = sourceIP.bytes[i];
    }

    for(int i=0; i<destinationIP.bytes.size(); i++){
        header[16+i] = destinationIP.bytes[i];
    }

    write_u16_be(header, 10, compute_ones_complement_checksum(header.data(), header.size()));

    return header;
}