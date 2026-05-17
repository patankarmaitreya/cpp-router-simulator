#include <iostream>
#include <optional>
#include <string>
#include <vector>
#include <cstdint>
#include <iomanip>

#include<core/byte_utils.hpp>

void print_banner(){
    std::cout << "C++ Router Simulator" << std::endl;
}

void print_bytes(const std::vector<uint8_t>& packet, size_t start, size_t count){
    if(start > packet.size() || count > packet.size() - start){
        std::cout << "Invalid range" << std::endl;
        return;
    }
    
    for(size_t i=start; i - start < count; i++){
        std::cout << std::hex
        << std::setw(2)
        << std::setfill('0') 
        << static_cast<int>(packet[i])
        << " "; 
    }
    std::cout << std::dec << std::endl;
}

void print_packet_info(const std::vector<uint8_t>& packet){
    if(packet.size() < 14){
        std::cout << "Invalid Ethernet Frame" << std::endl;
        return;
    }

    std::cout << "Destination MAC: ";
    print_bytes(packet, 0, 6);

    std::cout << "Source MAC: ";
    print_bytes(packet, 6, 6);

    std::cout << "EtherType: ";
    print_bytes(packet, 12, 2);

    std::cout << "Payload: ";
    print_bytes(packet, 14, packet.size()-14);

    std::cout << "\n";
}

void print_optional_u16(std::optional<uint16_t>& value){
    if(value.has_value())
    {
        std::cout << "0x"
        << std::hex
        << std::setw(4)
        << std::setfill('0')
        << *value
        << std::dec
        << std::setfill(' ')
        << std::endl; 
    }
    else{
        std::cout << "No value returned" << std::endl;
    }
}

void print_optional_u32(std::optional<uint32_t>& value){
    if(value.has_value())
    {
        std::cout << "0x"
        << std::hex
        << std::setw(8)
        << std::setfill('0')
        << *value
        << std::dec
        << std::setfill(' ')
        << std::endl; 
    }
    else{
        std::cout << "No value returned" << std::endl;
    }
}

int main(){
    print_banner();
    std::cout << "\n";

    //int packet_count = 0;

    std::vector<uint8_t> packet {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x08, 0x06,
        0x45, 0x00, 0x00, 0x14
    };
    std::vector<uint8_t> short_packet {
        0x00, 0x11, 0x22
    };
    std::vector<uint8_t> header_only_packet {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x08, 0x00
    };
    std::vector<uint8_t> ip_bytes {
        0xc0, 0xa8, 0x01, 0x0a
    };
    std::vector<uint8_t> zero_bytes {
        0x00, 0x00
    };
    std::vector<uint8_t> zero_bytes4 {
        0x00, 0x00, 0x00, 0x00
    };

    std::optional<uint16_t> value = read_u16_be(packet, 12);
    std::cout << "Ethernet Type: ";
    print_optional_u16(value);

    if(value.has_value() && *value == 0x0800){
        std::cout << "Payload type: " << "Ipv4" << std::endl;
    }
    else if(value.has_value() && *value == 0x0806){
        std::cout << "Payload type: " << "ARP" << std::endl; 
    }
    else{
        std::cout << "Payload type: " << "Unknown" << std::endl;
    }

    std::optional<uint32_t> value32 = read_u32_be(short_packet, 0);
    print_optional_u32(value32);

    std::optional<uint32_t> ipValue = read_u32_be(ip_bytes, 0);
    uint32_t b1  = (*ipValue >> 24) & 0xFF;
    uint32_t b2  = (*ipValue >> 16) & 0xFF;
    uint32_t b3  = (*ipValue >> 8) & 0xFF;
    uint32_t b4  = *ipValue & 0xFF;

    std::cout << static_cast<int>(b1) << "."
              << static_cast<int>(b2) << "."
              << static_cast<int>(b3) << "."
              << static_cast<int>(b4) << std::endl;

    write_u16_be(zero_bytes, 0, 0x0800);
    print_bytes(zero_bytes, 0, zero_bytes.size());
    
    write_u16_be(zero_bytes, 0, 0x0806); 
    print_bytes(zero_bytes, 0, zero_bytes.size());
   
    write_u32_be(zero_bytes4, 0, 0xc0a8010a);
    print_bytes(zero_bytes4, 0, zero_bytes4.size());

    /*
    std::cout << "Packet 1 Info:" << std::endl;
    print_packet_info(packet);

    std::cout << "Packet 2 Info:" << std::endl;
    print_packet_info(short_packet);

    std::cout << "Packet 3 Info:" << std::endl;
    print_packet_info(header_only_packet);

    std::cout << "Frame size: " << packet.size() << std::endl;
    print_bytes(packet, 0, packet.size());

    print_bytes(packet, 20, 5);

    std::cout << "Packets Processed: " << packet_count << std::endl;
    */


    return 0;
}