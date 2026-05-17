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
    if(frame.version != 4){
        std::cout << "frame version not for ipv4" << std::endl;
        return std::nullopt;
    } 
    //if IHL < 5 then headr lenght becomes < 20 which is incorrect
    if(frame.ihl < 5){
        std::cout << "frame IHL less than 5" << std::endl; 
        return std::nullopt;
    } 
        

    if(frame.header_length > length){
        std::cout << "frame header length more that total frame length" << std::endl;
        return std::nullopt;
    }

    auto total_length = read_u16_be(data, length, 2);
    if(!total_length.has_value()){
        std::cout << "failed conversion of total length bytes to uint16" << std::endl;
        return std::nullopt;
    }
    frame.total_length = *total_length;

    if(frame.total_length > length){
        std::cout << "frame total length more than frame length" << std::endl;  
        return std::nullopt;
    }

    if(frame.header_length > frame.total_length){ 
        std::cout << "frame header length more than frame total lenght" << std::endl;  
        return std::nullopt;
    }

    auto id = read_u16_be(data, length,4);
    if(!id.has_value()){
        std::cout << "failed conversion of id bytes to uint16" << std::endl;
        return std::nullopt;
    }
    frame.id = *id;


    auto flags = read_u16_be(data, length,6);
    if(!flags.has_value()){
        std::cout << "failed conversion of flags bytes to uint16" << std::endl;
        return std::nullopt;
    }
    frame.flags = *flags;
    
    frame.ttl = data[8];
    frame.protocol = data[9];

    auto header_checksum = read_u16_be(data, length,10);
    if(!header_checksum.has_value()){
        std::cout << "failed conversion of header checksum bytes to uint16" << std::endl;
        return std::nullopt;
    }
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