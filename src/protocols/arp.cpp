#include "core/byte_utils.hpp"
#include "protocols/ethernet.hpp"
#include <optional>
#include <protocols/arp.hpp>

std::optional<ArpPacket> parse_arp(const uint8_t *data, size_t length){
    if(length < 28) return std::nullopt;

    ArpPacket packet;

    auto hardware_type = read_u16_be(data, length, 0);
    if(hardware_type.has_value()) packet.hardware_type = *hardware_type;
    else return std::nullopt;

    auto protocol_type = read_u16_be(data, length, 2);
    if(protocol_type.has_value()) packet.protocol_type = *protocol_type;
    else return std::nullopt;

    packet.hardware_add_len = data[4];
    packet.protocol_add_len = data[5];

    auto opcode = read_u16_be(data, length, 6);
    if(opcode.has_value()){
        if(opcode == 1) packet.opcode = ArpOpcode::request;
        else if(opcode == 2) packet.opcode = ArpOpcode::reply;
        else  return std::nullopt;
    }
    else return std::nullopt;

    if(packet.hardware_type != 1 || packet.protocol_type != 0x0800) return std::nullopt;
    if(packet.hardware_add_len != 6 || packet.protocol_add_len != 4) return std::nullopt;

    auto sender_mac = extract_mac(data, length, 8);
    if(sender_mac.has_value()) packet.sender_mac = *sender_mac;
    else return std::nullopt;

    auto sender_ip = extract_ip(data, length, 14);
    if(sender_ip.has_value()) packet.sender_ip = *sender_ip;
    else return std::nullopt; 

    auto target_mac = extract_mac(data, length, 18);
    if(target_mac.has_value()) packet.target_mac = *target_mac;
    else return std::nullopt;

    auto target_ip = extract_ip(data, length, 24);
    if(target_ip.has_value()) packet.target_ip = *target_ip;
    else return std::nullopt; 

    return packet;
}

std::vector<uint8_t> generate_arp_reply_frame(const EthernetFrame& ethernet_header, const ArpPacket& arp_header, MacAddress router_mac, IPv4Address router_ip){
    if (ethernet_header.ethernet_type != kEtherTypeARP) {
        return {};
    }
    
    if (arp_header.opcode != ArpOpcode::request) {
        return {};
    }
    
    std::vector<uint8_t> reply(42, 0);

    for(size_t i=0; i<kMacAddressLength; i++){
        reply[i] = ethernet_header.source.bytes[i];
    } 

    for(size_t i=0; i<kMacAddressLength; i++){
        reply[i+6] = router_mac.bytes[i];
    }

    write_u16_be(reply, 12, kEtherTypeARP);

    
    write_u16_be(reply, kEthernetHeaderLength+0, arp_header.hardware_type);
    write_u16_be(reply, kEthernetHeaderLength+2, arp_header.protocol_type);
    
    reply[kEthernetHeaderLength+4] = arp_header.hardware_add_len;
    reply[kEthernetHeaderLength+5] = arp_header.protocol_add_len;

    write_u16_be(reply, kEthernetHeaderLength+6, static_cast<uint16_t>(ArpOpcode::reply));

    for(int i=0; i<6; i++){
        reply[i+kEthernetHeaderLength+8] = router_mac.bytes[i];
    }
    write_u32_be(reply, kEthernetHeaderLength+14, ipv4_to_uint32(router_ip));

    for(int i=0; i<6; i++){
        reply[i+kEthernetHeaderLength+18] = arp_header.sender_mac.bytes[i];
    }
    write_u32_be(reply, kEthernetHeaderLength+24, ipv4_to_uint32(arp_header.sender_ip));

    return reply;
}