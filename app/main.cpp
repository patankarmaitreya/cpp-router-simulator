#include "core/checksum.hpp"
#include "protocols/ethernet.hpp"
#include "protocols/ipv4.hpp"
#include <iostream>
#include <optional>
#include <ostream>
#include <vector>
#include <cstdint>

#include<core/byte_utils.hpp>
#include "demo/packet_samples.hpp"
#include "demo/print_utils.hpp"

namespace samples = demo::samples;
namespace print = demo::print;

void run_ethernet_demo(){
    std::vector<uint8_t> packet = samples::valid_ethernet_frame();
    std::vector<uint8_t> short_packet = samples::invalid_ethernet_frame_short();

    std::optional<EthernetFrame> ethernet_frame = parse_ethernet(packet);
    std::cout << "Valid Ethernet Frame Test: " << std::endl;
    if(ethernet_frame.has_value()){
        std::cout << "Destination Mac: " << print::format_mac(ethernet_frame->destination) << std::endl;
        std::cout << "Source Mac: " << print::format_mac(ethernet_frame->source) << std::endl;
        std::cout << "Ethernet type hex: " << print::format_hex_u16(ethernet_frame->ethernet_type) << std::endl;
        std::cout << "Ethernet type: " << print::ethernet_type_name(ethernet_frame->ethernet_type) << std::endl;
    }
    else{
        std::cout << "Invalid Ethernet frame" << std::endl; 
    }

    std::cout << std::endl;

    std::cout << "Short Ethernet Frame Test: " << std::endl;
    std::optional<EthernetFrame> short_frame = parse_ethernet(short_packet);
    std::cout << "Packet size: " << short_packet.size() << std::endl;
    if(short_frame.has_value()){
        std::cout << "Valid Ethernet Frame" << std::endl;
    }
    else{
        std::cout << "Invalid Ethernet Frame" << std::endl ;
    }
}

void run_ipv4_demo(){
    std::vector<uint8_t> packet = samples::valid_ipv4_frame();
    std::vector<uint8_t> arp_packet = samples::valid_arp_frame();

    std::optional<EthernetFrame> ethernet_frame = parse_ethernet(packet);

    if(ethernet_frame.has_value())
    {
        if(ethernet_frame->ethernet_type == kEtherTypeIPv4){
            std::optional<IPv4Packet> frame = parse_ipv4(packet.data() + ethernet_frame->payload_offset, ethernet_frame->payload_length);
            
            if(frame.has_value()){
                std::cout << "Version: " << static_cast<int>(frame->version) << std:: endl;
                std::cout << "IHL: " << static_cast<int>(frame->ihl) << std:: endl;
                std::cout << "Header Length: " << static_cast<int>(frame->header_length) << std:: endl;
                std::cout << "Total Length: " << static_cast<int>(frame->total_length) << std:: endl;
                std::cout << "TTL: " << static_cast<int>(frame->ttl) << std:: endl;
                std::cout << "Protocol number: " << static_cast<int>(frame->protocol) << std:: endl;
                std::cout << "Protocol name: " << print::ip_protocol_name(frame->protocol) << std:: endl;
                std::cout << "Header Checksum: " << print::format_hex_u16(frame->header_checksum) << std::endl;
                std::cout << "Source IP: " << print::format_ipv4(frame->source_ip) << std::endl;
                std::cout << "Destination IP: " << print::format_ipv4(frame->destination_ip) << std::endl;
                std::cout << "Payload offset: " << frame->payload_offset << std::endl;
                std::cout << "Payload length: " << frame->payload_length << std::endl;
            }
            else{
                std::cout << "Invalid IPv4 packet" << std::endl;
            }
        }
        else{
            std::cout << "Ethernet frame is not IPv4 frame" << std::endl;
        }
    }
    else{
        std::cout << "Invalid ethernet frame" << std::endl;
    }

    std::cout << "ARP Frame Test: " << std::endl;
    std::optional<EthernetFrame> arp_frame = parse_ethernet(arp_packet);

    if (arp_frame.has_value()) {
        std::cout << "Packet ethernet type bytes: "
                  << print::format_hex_u16(arp_frame->ethernet_type) << std::endl;
    
        std::cout << "Packet ethernet type: "
                  << print::ethernet_type_name(arp_frame->ethernet_type) << std::endl;
    
        if (arp_frame->ethernet_type == kEtherTypeIPv4) {
            std::cout << "Valid IPv4 frame" << std::endl;
        } else {
            std::cout << "Not IPv4 frame hence not parsed" << std::endl;
        }
    } else {
        std::cout << "Invalid Ethernet frame" << std::endl;
    }
}

void run_checksum_demo(){
    std::vector<uint8_t> ipv4_packet = samples::valid_ipv4_frame_no_ethernet_header();

    std::vector<uint8_t> output = ipv4_packet;
    write_u16_be(output, 10, 0x0000);
    
    std::cout << print::format_hex_u16(compute_ipv4_checksum(output.data(), 20)) << std::endl;
    if(validate_ipv4_checksum(ipv4_packet.data(), 20)) std::cout << "Valid checksum" << std::endl;
    else std::cout << "Invalid checksum" << std::endl;

    std::cout << "Original TTL: " << print::format_hex_u8(ipv4_packet[8]) << std::endl;

    bool updated = decrement_ttl_and_update_checksum(ipv4_packet, 0, 20);

    std::cout << "Updated: " << updated << std::endl;

    std::cout << "Updated TTL: " << print::format_hex_u8(ipv4_packet[8]) << std::endl;

    auto checksum = read_u16_be(ipv4_packet, 10);

    if (checksum.has_value()) {
        std::cout << "Checksum: " << print::format_hex_u16(*checksum) << std::endl;
    }
    else{
        std::cout << "Invalid checksum bytes" << std::endl;
    }

    if (validate_ipv4_checksum(ipv4_packet.data(), 20)) {
        std::cout << "Valid checksum" << std::endl;
    } else {
        std::cout << "Invalid checksum" << std::endl;
    }
}

int main(){
    print::print_banner();
    std::cout << "\n";

    run_ethernet_demo();
    std::cout <<std::endl;
    run_ipv4_demo();
    std::cout <<std::endl;
    run_checksum_demo();

    return 0;
}