#include "core/checksum.hpp"
#include "core/byte_utils.hpp"
#include <cstdint>

uint16_t compute_ones_complement_checksum(const uint8_t* header, size_t header_length){

    uint32_t sum = 0;
    for(size_t i=0; i<header_length; i+=2){    
        if(i==header_length -1) {
            uint16_t end_byte = static_cast<uint16_t>(header[i]) << 8;
            sum += static_cast<uint32_t>(end_byte);
        }
        else{
            auto pair = read_u16_be(header, header_length, i);
            if(pair.has_value()) sum += static_cast<uint32_t>(*pair);
            else return 0;
        }
    }

    while(sum > 0xffff){
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return static_cast<uint16_t>((~sum) & 0xffff);
}



bool validate_oes_complement_checksum(const uint8_t* header, size_t header_length)
{
    uint32_t sum = 0;
    for(size_t i=0; i<header_length; i+=2){    
        if(i==header_length -1) {
            uint16_t end_byte = static_cast<uint16_t>(header[i]) << 8;
            sum += static_cast<uint32_t>(end_byte);
        }
        else{
            auto pair = read_u16_be(header, header_length, i);
            if(pair.has_value()) sum += static_cast<uint32_t>(*pair);
            else return 0;
        }
    }
    
    while(sum > 0xffff){
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return static_cast<uint16_t>((~sum) & 0xffff) == 0x0000;
}

bool decrement_ttl_and_update_checksum(std::vector<uint8_t>&  packet, size_t ipv4_header_offset, size_t header_length){
    if(ipv4_header_offset + header_length > packet.size()) return false;

    if(header_length < 20) return false;

    if(header_length % 4 != 0) return false;

    const size_t ttl_offset = ipv4_header_offset + 8;
    const size_t checksum_offset = ipv4_header_offset + 10;
    
    if(packet[ttl_offset] == 1 || packet[ttl_offset] == 0) return false;

    packet[ttl_offset] -= 1;
    write_u16_be(packet, checksum_offset, 0x0000);
    uint16_t new_checksum = compute_ones_complement_checksum(packet.data() + ipv4_header_offset,header_length);
    write_u16_be(packet, checksum_offset, new_checksum);

    return true;
}