#include "demo/print_utils.hpp"
#include "protocols/arp.hpp"
#include "protocols/ethernet.hpp"
#include "router/forwarding_engine.hpp"

#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

namespace demo::print {
    void print_banner(){
        std::cout << "C++ Router Simulator" << std::endl;   
    }

    std::string format_hex_u8(uint8_t val){
        std::ostringstream oss;

        oss << "0x"
            << std::hex
            << std::setw(2)
            << std::setfill('0') 
            << static_cast<int>(val);

        return oss.str();
    }

    std::string format_hex_u16(uint16_t val){
        std::ostringstream oss;

        oss << "0x"
            << std::hex
            << std::setw(4)
            << std::setfill('0') 
            << static_cast<int>(val);

        return oss.str();
    }

    std::string format_hex_u32(uint32_t val){
        std::ostringstream oss;

        oss << "0x"
            << std::hex
            << std::setw(8)
            << std::setfill('0') 
            << static_cast<int>(val);

        return oss.str();
    }

    void print_bytes(const std::vector<uint8_t> &data, size_t start, size_t count){
        if(start > data.size() || count > data.size() - start){
            std::cout << "Invalid range" << std::endl;
            return;
        }
        
        for(size_t i=start; i - start < count; i++){
           std::cout << format_hex_u8(data[i]) << " ";
        }
        std::cout << "\n";
    }

    std::string format_mac(const MacAddress& mac){
        std::ostringstream oss;
        
        for(size_t i = 0; i < 6; i++){
            oss << static_cast<int>((mac.bytes[i]));
            if(i !=  5) oss << ":";
        } 

        return oss.str();
    }

    std::string format_ipv4(const IPv4Address& ip){
        std::ostringstream oss;
        
        for(size_t i = 0; i < 4; i++){
            oss << static_cast<int>(ip.bytes[i]);
            if(i !=  3) oss << ".";
        } 

        return oss.str();
    }

    std::string ethernet_type_name(uint16_t ethernet_type){
        if(ethernet_type == kEtherTypeIPv4) return "IPv4";
        else if(ethernet_type == kEtherTypeARP) return "ARP"; 
        else return "Unknown";
    }

    std::string ip_protocol_name(uint8_t protocol) {
        if (protocol == kIpProtocolICMP) return "ICMP";
        if (protocol == kIpProtocolTCP) return "TCP";
        if (protocol == kIpProtocolUDP) return "UDP";
        return "Unknown";
    }

    std::string icmp_type_name(uint8_t type) {
        if (type == 8) return "Echo request";
        if (type == 0) return "Echo reply";
        if (type == 11) return "Time exceeded";
        if (type == 3) return "Destination unreachable";
        return "Unknown";
    }

    std::string arp_opcode_to_string(ArpOpcode opcode){
        if(opcode == ArpOpcode::request) return "request";
        else if(opcode == ArpOpcode::reply) return "reply";
        else return "invalid";
    }

    void print_interface_info(const RouterInterface& interface){
        std::cout << "Name: " << interface.name <<std::endl;
        std::cout << "ip: " << demo::print::format_ipv4(interface.ip) << std::endl;
        std::cout << "mac: " << demo::print::format_mac(interface.mac) << std::endl;
    }
    
    void print_packet_info(const PacketResult &packet){
        std::cout << "Action: ";

        if(packet.action == ForwardAction::Forwarded) std::cout << "Forwarded" <<std::endl;
        else if(packet.action == ForwardAction::Dropped) std::cout << "Dropped" <<std::endl;
        else if(packet.action == ForwardAction::ArpReplyGenerated) std::cout << "ArpReplyGenerated" <<std::endl;
        else if(packet.action == ForwardAction::IcmpEchoReplyGenerated) std::cout << "IcmpEchoReplyGenerated" <<std::endl;
        else if(packet.action == ForwardAction::IcmpTimeExceededGenerated) std::cout << "IcmpTimeExceededGenerated" <<std::endl;
        else if(packet.action == ForwardAction::IcmpDestinationUnreachableGenerated) std::cout << "IcmpDestinationUnreachableGenerated" <<std::endl;
        else if(packet.action == ForwardAction::QueuedPendingArp) std::cout << "QueuedPendingArp" <<std::endl;
        else std::cout << "Unknown" <<std::endl;

        std::cout << "Reason: " << packet.reason <<std::endl;

        std::cout << "Interface: ";
        if(packet.output_interface.has_value()) print_interface_info(*packet.output_interface);
    }
}
