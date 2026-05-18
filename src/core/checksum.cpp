#include "core/checksum.hpp"
#include "core/byte_utils.hpp"

uint16_t compute_ipv4_checksum(const uint8_t* header, size_t header_length){

    uint32_t sum = 0;
    for(size_t i=0; i<header_length; i+=2){    
        auto pair = read_u16_be(header, header_length, i);
        if(pair.has_value()) sum += static_cast<uint32_t>(*pair);
        else return 0;
    }

    while(sum > 0xffff){
        uint16_t high = static_cast<uint16_t>(sum >> 16);
        uint16_t low = static_cast<uint16_t>(sum & 0xffff);

        sum = static_cast<uint32_t>(high+low);
    }

    return static_cast<uint16_t>((~sum) & 0xffff);
}

bool validate_ipv4_checksum(const uint8_t* header, size_t header_length)
{
    uint32_t sum = 0;
    for(size_t i=0; i<header_length; ){    
        auto pair = read_u16_be(header, header_length, i);
        if(pair.has_value()) sum += static_cast<uint32_t>(*pair);
        else return 0;

        i += 2;
    }
    
    while(sum > 0xffff){
        uint16_t high = static_cast<uint16_t>(sum >> 16);
        uint16_t low = static_cast<uint16_t>(sum & 0xffff);

        sum = static_cast<uint32_t>(high+low);
    }

    if(static_cast<uint16_t>((~sum) & 0xffff) == 0x0000) return true;
    else return false; 
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
    uint16_t new_checksum = compute_ipv4_checksum(packet.data() + ipv4_header_offset,header_length);
    write_u16_be(packet, checksum_offset, new_checksum);

    return true;
}