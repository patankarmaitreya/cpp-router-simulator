#include "core/byte_utils.hpp"
#include <cstddef>
#include <optional>
#include <protocols/udp.hpp>

std::optional<UdpDatagram> parse_udp(const uint8_t *data, size_t length)
{
    if(length < 8) return std::nullopt;

    UdpDatagram diagram;

    auto source_port = read_u16_be(data, length, 0);
    if(source_port.has_value()) diagram.source_port = *source_port;
    else return std::nullopt;

    auto destination_port = read_u16_be(data, length, 2);
    if(destination_port.has_value()) diagram.destination_port = *destination_port;
    else return std::nullopt;

    auto udp_length = read_u16_be(data, length, 4);
    if(udp_length.has_value()) diagram.length = *udp_length;
    else return std::nullopt;

    auto checksum = read_u16_be(data, length, 6);
    if(checksum.has_value()) diagram.checksum = *checksum;
    else return std::nullopt;

    if(diagram.length < 8 || diagram.length > length) return std::nullopt;

    diagram.payload_offset = 8;
    diagram.payload_length = diagram.length - 8;

    return diagram;
}