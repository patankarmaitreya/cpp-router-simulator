#include "core/byte_utils.hpp"
#include "core/checksum.hpp"
#include <cstdint>
#include <optional>
#include <protocols/icmp.hpp>
#include <protocols/ethernet.hpp>
#include <protocols/ipv4.hpp>
#include <vector>

std::optional<IcmpPacket> parse_icmp(const uint8_t *data, size_t length){
    if(length < 4) return std::nullopt;
    
    IcmpPacket packet;

    packet.type = data[0];
    packet.code = data[1];

    auto checksum = read_u16_be(data, length, 2);
    if(checksum.has_value()) packet.checksum = *checksum;
    else return std::nullopt;

    if(packet.type == 0x00 || packet.type == 0x08){
        if( length < 8) return std::nullopt;

        auto identifier = read_u16_be(data, length, 4);
        if(identifier.has_value()) packet.identifier = *identifier;
        else return std::nullopt;

        auto sequence_number = read_u16_be(data, length, 6);
        if(sequence_number.has_value()) packet.sequence_number = *sequence_number;
        else return std::nullopt;

        packet.payload_offset = 8;
        packet.payload_length = length - 8;
    }
    else{
        packet.payload_offset = 4;
        packet.payload_length = length - 4;
    }

    return packet;;
}

std::vector<uint8_t> generate_icmp_reply_frame(const uint8_t* request_data, size_t request_length, const IcmpPacket& request){
    if (!request.identifier.has_value() || !request.sequence_number.has_value()) {
        return {};
    }

    if (request_data == nullptr || request_length < 8) {
        return {};
    }
    
    std::vector<uint8_t> out(8, 0);

    out[0] = 0x00; // Echo Reply
    out[1] = 0x00; // Code

    write_u16_be(out, 2, 0x0000);
    write_u16_be(out, 4, *request.identifier);
    write_u16_be(out, 6, *request.sequence_number);

    // Preserve original echo payload.
    if (request.payload_offset < request_length) {
        out.insert(
            out.end(),
            request_data + request.payload_offset,
            request_data + request_length
        );
    }

    uint16_t checksum = compute_ones_complement_checksum(out.data(), out.size());
    write_u16_be(out, 2, checksum);

    return out;
}

std::vector<uint8_t> build_icmp_error_message(uint8_t type, uint8_t code, const uint8_t* ipv4_data, size_t ipv4_length){
    
    if (ipv4_data == nullptr || ipv4_length < 20) {
        return {};
    }
    
    uint8_t version = ipv4_data[0] >> 4;
    uint8_t ihl = ipv4_data[0] & 0x0f;
    size_t header_length = static_cast<size_t>(ihl) * 4;

    if (version != 4 || ihl < 5 || header_length > ipv4_length) {
        return {};
    }

    std::vector<uint8_t> out(8, 0);

    out[0] = type; // Echo Reply
    out[1] = code; // Code

    write_u16_be(out, 2, 0x0000);
    write_u16_be(out, 4, 0x0000);
    write_u16_be(out, 6, 0x0000);

    size_t bytes_to_quote = std::min(ipv4_length, header_length + static_cast<size_t>(8));
    out.insert(
        out.end(),
        ipv4_data ,
        ipv4_data + bytes_to_quote
    );
    

    uint16_t checksum = compute_ones_complement_checksum(out.data(), out.size());
    write_u16_be(out, 2, checksum);

    return out;
}

std::vector<uint8_t> build_icmp_time_exceeded( const uint8_t* ipv4_data, size_t ipv4_length){
    return build_icmp_error_message(
        0x0b, // Type 11: Time Exceeded
        0x00, // Code 0: TTL exceeded in transit
        ipv4_data,
        ipv4_length
    );
}

std::vector<uint8_t> build_icmp_destination_unreachable( const uint8_t* ipv4_data, size_t ipv4_length){
    return build_icmp_error_message(
        0x03, // Type 3: destination unreachable
        0x00, // Code 0: TTL exceeded in transit
        ipv4_data,
        ipv4_length
    );
}