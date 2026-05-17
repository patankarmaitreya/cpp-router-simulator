#include "protocols/ethernet.hpp"
#include "protocols/ipv4.hpp"
#include <iostream>
#include <optional>
#include <ostream>
#include <system_error>
#include <vector>
#include <cstdint>
#include <iomanip>

#include<core/byte_utils.hpp>

void print_banner(){
    std::cout << "C++ Router Simulator" << std::endl;
}

void print_hex8(uint8_t val){
    std::cout << std::hex
    << std::setw(2)
    << std::setfill('0') 
    << static_cast<int>(val)
    << std::dec
    << std::setfill(' ');
}

void print_hex16(uint16_t val){
    std::cout << std::hex
    << std::setw(4)
    << std::setfill('0') 
    << static_cast<int>(val)
    << std::dec
    << std::setfill(' ');
}

void print_bytes(const std::vector<uint8_t>& packet, size_t start, size_t count){
    if(start > packet.size() || count > packet.size() - start){
        std::cout << "Invalid range" << std::endl;
        return;
    }
    
    for(size_t i=start; i - start < count; i++){
       print_hex8(packet[i]);
       std::cout << " ";
    }
    
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

void print_optional_u16(const std::optional<uint16_t>& value){
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

void print_optional_u32(const std::optional<uint32_t>& value){
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

void print_mac(const std::vector<uint8_t>& packet, size_t start_index){
    if(start_index > packet.size() || packet.size() - start_index < 6){
        std::cout << "Invalid start for mac" << std::endl;
        return;
    }

    for(size_t i = 0; i < 6; i++){
        print_hex8(packet[i + start_index]);
        if(i !=  5) std::cout << ":";
    }
}

void print_mac(const MacAddress& mac){
    for(size_t i = 0; i < 6; i++){
        print_hex8(mac.bytes[i]);
        if(i !=  5) std::cout << ":";
    } 
}

bool extract_mac(const std::vector<uint8_t>& packet, size_t start_index, MacAddress& out_mac){
    if(start_index > packet.size() || packet.size() - start_index < 6) return false;

    for(size_t i=0; i<6; i++){
        out_mac.bytes[i] = packet[i + start_index];
    }

    return true;
}

void print_ip(const IPAddress& ip){
    for(size_t i = 0; i < 4; i++){
        std::cout << static_cast<int>(ip.bytes[i]);
        if(i !=  3) std::cout << ".";
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
    /*
    uint8_t first_byte = 0x65;

    int version = static_cast<int>(first_byte >> 4);
    int IHL = static_cast<int>(first_byte & 0x0F);
    int header_length = version * IHL;

    std::cout << "Version: " << version << std::endl;
    std::cout << "IHL: " << IHL << std::endl;
    std::cout << "Header length: " << header_length << std::endl;
    */

    std::vector<uint8_t> ethernet_packet = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x08, 0x00,
        0x45, 0x00, 0x00, 0x18,
        0x12, 0x34, 0x00, 0x00,
        0x40, 0x01, 0x00, 0x00,
        0x0a, 0x00, 0x00, 0x02,
        0x0a, 0x00, 0x01, 0x02,
        0xde, 0xad, 0xbe, 0xef
    };

    std::optional<EthernetFrame> ethernet_frame = parse_ethernet(ethernet_packet);
    
    std::cout << "Ethernet: " << std::endl;
    if(ethernet_frame.has_value()){
        print_mac(ethernet_frame->destination);
        std::cout << std::endl;
        print_mac(ethernet_frame->source);
        std::cout << std::endl;
        print_hex16(ethernet_frame->ethernet_type);
        std::cout << std::endl;
        std::cout << ethernettype_to_string(ethernet_frame->ethernet_type) << std::endl;
        std::cout << std::endl;

        if(ethernet_frame->ethernet_type == 0x0800){
            std::cout << "IPv4: " << std::endl; 
            std::optional<IPv4Packet> frame = parse_ipv4(ethernet_packet.data() + ethernet_frame->payload_offset, ethernet_frame->payload_length);
            if(frame.has_value()){
                std::cout << "Version: " << static_cast<int>(frame->version) << std:: endl;
                std::cout << "IHL: " << static_cast<int>(frame->ihl) << std:: endl;
                std::cout << "Header Lenght: " << static_cast<int>(frame->header_length) << std:: endl;
                std::cout << "Total Length: " << static_cast<int>(frame->total_length) << std:: endl;
                std::cout << "TTL: " << static_cast<int>(frame->ttl) << std:: endl;
                std::cout << "Protocol: " << static_cast<int>(frame->protocol) << std:: endl;

                std::cout << "Ptotocol name: ";
                if(static_cast<int>(frame->protocol) == 1) std::cout << "ICMP";
                else if(static_cast<int>(frame->protocol) == 6) std::cout << "TCP";
                else if(static_cast<int>(frame->protocol) == 17) std::cout << "UDP";
                else std::cout << "Unknown"; 
                std::cout << std::endl;

                std::cout << "Header Checksum: ";
                print_hex16(frame->header_checksum);
                std::cout << std:: endl;

                std::cout << "Soure IP: ";
                print_ip(frame->source_ip);
                std::cout << std:: endl;

                std::cout << "Destination IP: ";
                print_ip(frame->destination_ip);
                std::cout << std:: endl;

                std::cout << "Payload offset: " << frame->payload_offset << std::endl;
                std::cout << "Payload lenght: " << frame->payload_length << std::endl;
            }
            else{
                std::cout << "Invalid IPv4 packet" << std::endl;
            }
        }
        else{
            std::cout << "Payload not a IPv4 packet" << std::endl;
        }
    }
    else{
        std::cout << "Invalid Ethernet frame" << std::endl;
    }


    #pragma region chunk2 tests
    /*
    MacAddress destination;
    MacAddress source;

    extract_mac(packet, 0, destination);
    extract_mac(packet, 6, source);

    std::cout << "Destination Mac: ";
    print_mac(destination);
    std::cout << std::endl;

    std::cout << "Source Mac: ";
    print_mac(source);
    std::cout << std::endl;

    std::optional<EthernetFrame> frame = parse_ethernet(packet);
    if(frame.has_value()){
        print_mac(frame->destination);
        std::cout << std::endl;
        print_mac(frame->source);
        std::cout << std::endl;
        print_hex16(frame->ethernet_type);
        std::cout << ethernettype_to_string(frame->ethernet_type) << std::endl;
    }
    else{
        std::cout << "Invalid Ethernet frame" << std::endl;
    }
        */
    #pragma endregion

    #pragma region chunk1 tests
    /*
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

    */
    #pragma endregion

    #pragma region chunk0 tests
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
    #pragma endregion

    return 0;
}