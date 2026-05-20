#include "core/checksum.hpp"
#include "protocols/arp.hpp"
#include "protocols/ethernet.hpp"
#include "protocols/ipv4.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <iostream>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include<core/byte_utils.hpp>
#include "demo/packet_samples.hpp"
#include "demo/print_utils.hpp"
#include "router/arp_cache.hpp"
#include "router/route.hpp"
#include "router/routing_table.hpp"
#include <cstdint>

namespace samples = demo::samples;
namespace print = demo::print;

struct RouterInterface{
    std::string name = "eth0";
    IPv4Address ip = make_ipv4(10, 0, 0, 1);
    MacAddress mac{
        std::array<uint8_t, 6>{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
    };
};



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
    std::vector<uint8_t> packet = samples::valid_ethernet_frame_ipv4();
    std::vector<uint8_t> arp_packet = samples::valid_arp_request_frame();

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
    std::vector<uint8_t> ipv4_packet = samples::valid_ipv4_frame();

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

void run_router_demo(){
    Route r1{
        make_ipv4(10, 0, 0, 0),
        8,
        "eth0",
        std::nullopt
    };

    Route r2{
        make_ipv4(10, 0, 1, 0),
        24,
        "eth1",
        std::nullopt
    };

    Route r3{
        make_ipv4(10, 0, 1, 50),
        32,
        "eth1",
        std::nullopt
    };

    Route r4{
        make_ipv4(0, 0, 0, 0),
        0,
        "eth0",
        make_ipv4(10, 0, 0, 254)
    };

    RoutingTable table;

    table.add_route_linear(r1);
    table.add_route_linear(r2);
    table.add_route_linear(r3);
    table.add_route_linear(r4);

    table.add_route_trie(r1);
    table.add_route_trie(r2);
    table.add_route_trie(r3);
    table.add_route_trie(r4); 

    std::vector<IPv4Address> test_addreses = {
        make_ipv4(10, 0, 1, 50),
        make_ipv4(10, 0, 1, 99),
        make_ipv4(10, 5, 6, 7),
        make_ipv4(8, 8, 8, 8)
    };

    for(size_t i=0; i<test_addreses.size(); i++){
        std::optional<Route> linear_match = table.lookup_linear(test_addreses[i]);
        std::optional<Route> trie_match = table.lookup_trie(test_addreses[i]);
        
        uint32_t linear_match_num = 0x00;
        uint32_t trie_match_num = 0x00;

        std::cout << "Linear match: ";
        if(linear_match.has_value()) {
            std::cout << demo::print::format_ipv4(linear_match->network_ip) << std::endl;
            linear_match_num = ipv4_to_uint32(linear_match->network_ip);
        }
        else std::cout << "None" << std::endl;

        std::cout << "Trie match: ";
        if(trie_match.has_value()) {
            std::cout << demo::print::format_ipv4(trie_match->network_ip) << std::endl;
            trie_match_num = ipv4_to_uint32(trie_match->network_ip);
        }
        else std::cout << "None" << std::endl;

        std::cout << "Match same: ";
        if(linear_match_num == trie_match_num) std::cout << "Yes" << std::endl;
        else std::cout << "No" <<std::endl;

        std::cout << std::endl;
    }
}

//Incomplete demo
void run_arp_demo(){
    MacAddress test_mac{
        std::array<uint8_t, kMacAddressLength>{0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb}
    };
    MacAddress test_mac_new{
        std::array<uint8_t, kMacAddressLength>{0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc}
    };

    IPv4Address test_ip = make_ipv4(10, 0, 1, 2);
    IPv4Address test_ip_new = make_ipv4(10, 0, 1, 3);

    ARPCache data(std::chrono::milliseconds(100));

    data.insert(test_ip, test_mac);
    std::optional<ARPEntry> match1 = data.lookup(test_ip);
    std::optional<ARPEntry> match2 = data.lookup(test_ip_new);

    if(match1.has_value()) std::cout << "Found Mac for ip1: " << demo::print::format_mac(match1->mac) << std::endl;
    else std::cout << "Found Mac for ip1: None" << std::endl;

    if(match2.has_value()) std::cout << "Found Mac for ip2: " << demo::print::format_mac(match2->mac) << std::endl;
    else std::cout << "Found Mac for ip2: None" << std::endl;

    data.insert(test_ip, test_mac_new);
    std::optional<ARPEntry> match1_new = data.lookup(test_ip);
    if(match1_new.has_value()) std::cout << "Found Mac for ip1: " << demo::print::format_mac(match1_new->mac) << std::endl;
    else std::cout << "Found Mac for ip1: None" << std::endl;

    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    std::optional<ARPEntry> match1_new1 = data.lookup(test_ip);
    if(match1_new1.has_value()) std::cout << "Found Mac for ip1: " << demo::print::format_mac(match1_new1->mac) << std::endl;
    else std::cout << "Found Mac for ip1: None" << std::endl;
}

void run_arp_parser_demo(){
    std::vector<uint8_t> packet = samples::valid_ethernet_frame_arp();

    std::optional<EthernetFrame> ethernet_frame = parse_ethernet(packet);

    if(ethernet_frame.has_value())
    {   
        std::cout << "Ethernet: " << std::endl;
        std::cout << "Destination Mac: " << print::format_mac(ethernet_frame->destination) << std::endl;
        std::cout << "Source Mac: " << print::format_mac(ethernet_frame->source) << std::endl;
        std::cout << "Ethernet type hex: " << print::format_hex_u16(ethernet_frame->ethernet_type) << std::endl;
        std::cout << "Ethernet type: " << print::ethernet_type_name(ethernet_frame->ethernet_type) << std::endl;
        std::cout << std::endl;

        if(ethernet_frame->ethernet_type == kEtherTypeARP){
            std::optional<ArpPacket> frame = parse_arp(packet.data() + ethernet_frame->payload_offset, ethernet_frame->payload_length);
            
            std::cout << "ARP: " << std::endl;
            if(frame.has_value()){
                std::cout << "Opcode: " << print::arp_opcode_to_string(frame->opcode) << std::endl;
                std::cout << "Sender mac: " << demo::print::format_mac(frame->sender_mac) << std::endl;
                std::cout << "Sender ip: " << demo::print::format_ipv4(frame->sender_ip) << std::endl;
                std::cout << "target mac: " << demo::print::format_mac(frame->target_mac) << std::endl;
                std::cout << "target ip: " << demo::print::format_ipv4(frame->target_ip) << std::endl;
            }
            else{
                std::cout << "Invalid ARP packet" << std::endl;
            }
        }
        else{
            std::cout << "Ethernet frame is not ARP frame" << std::endl;
        }
    }
    else{
        std::cout << "Invalid ethernet frame" << std::endl;
    }
}

void run_Arp_reply_demo(){
    RouterInterface interface;
    std::vector<uint8_t> packet = samples::valid_ethernet_frame_arp();

    std::vector<uint8_t> reply;
    std::optional<EthernetFrame> ethernet_frame_old = parse_ethernet(packet);

    if(ethernet_frame_old.has_value()){
        if(ethernet_frame_old->ethernet_type == kEtherTypeARP){
            std::optional<ArpPacket> frame = parse_arp(packet.data() + ethernet_frame_old->payload_offset, ethernet_frame_old->payload_length);
        
            if(frame.has_value()) reply = generate_arp_reply_frame(*ethernet_frame_old, *frame, interface.mac, interface.ip);
            else std::cout << "Invalid ARP frame" << std::endl;
        }
        else std::cout << "Not ARP frame" << std::endl;
    }
    else std::cout << "Invalid Ethernet frame" << std::endl;

    std::optional<EthernetFrame> ethernet_frame = parse_ethernet(reply);

    if(ethernet_frame.has_value())
    {   
        std::cout << "Ethernet: " << std::endl;
        std::cout << "Destination Mac: " << print::format_mac(ethernet_frame->destination) << std::endl;
        std::cout << "Source Mac: " << print::format_mac(ethernet_frame->source) << std::endl;
        std::cout << "Ethernet type hex: " << print::format_hex_u16(ethernet_frame->ethernet_type) << std::endl;
        std::cout << "Ethernet type: " << print::ethernet_type_name(ethernet_frame->ethernet_type) << std::endl;
        std::cout << std::endl;

        if(ethernet_frame->ethernet_type == kEtherTypeARP){
            std::optional<ArpPacket> frame = parse_arp(reply.data() + ethernet_frame->payload_offset, ethernet_frame->payload_length);
            
            std::cout << "ARP: " << std::endl;
            if(frame.has_value()){
                std::cout << "Opcode: " << print::arp_opcode_to_string(frame->opcode) << std::endl;
                std::cout << "Sender mac: " << demo::print::format_mac(frame->sender_mac) << std::endl;
                std::cout << "Sender ip: " << demo::print::format_ipv4(frame->sender_ip) << std::endl;
                std::cout << "target mac: " << demo::print::format_mac(frame->target_mac) << std::endl;
                std::cout << "target ip: " << demo::print::format_ipv4(frame->target_ip) << std::endl;
            }
            else{
                std::cout << "Invalid ARP packet" << std::endl;
            }
        }
        else{
            std::cout << "Ethernet frame is not ARP frame" << std::endl;
        }
    }
    else{
        std::cout << "Invalid ethernet frame" << std::endl;
    } 
}



int main(){
    print::print_banner();
    std::cout << "\n";

    RouterInterface interface;

    run_Arp_reply_demo();
    std::cout << std::endl;
    //run_arp_parser_demo();
    //run_router_demo();
    //std::cout << std::endl;
    //run_ethernet_demo();
    //std::cout <<std::endl;
    //run_ipv4_demo();
    //std::cout <<std::endl;
    //run_checksum_demo();

    return 0;
}