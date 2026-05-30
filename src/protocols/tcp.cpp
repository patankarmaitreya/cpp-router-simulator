#include "core/byte_utils.hpp"
#include <cstddef>
#include <optional>
#include <protocols/tcp.hpp>

std::optional<TcpSegment> parse_tcp(const uint8_t *data, size_t length)
{
    if(length < 20) return std::nullopt;

    TcpSegment segment;

    auto source_port = read_u16_be(data, length, 0);
    if(source_port.has_value()) segment.source_port = *source_port;
    else return std::nullopt;

    auto destination_port = read_u16_be(data, length, 2);
    if(destination_port.has_value()) segment.destination_port = *destination_port;
    else return std::nullopt;

    auto sequence_number = read_u32_be(data, length, 4);
    if(sequence_number.has_value()) segment.sequence_number = *sequence_number;
    else return std::nullopt;

    auto acknowledgment_number = read_u32_be(data, length, 8);
    if(acknowledgment_number.has_value()) segment.acknowledgment_number = *acknowledgment_number;
    else return std::nullopt;

    segment.data_offset = static_cast<uint8_t>((data[12] >> 4) & 0x0f);
    segment.header_length = static_cast<size_t>(segment.data_offset) * 4;

    if(segment.data_offset < 5 || segment.header_length > length) return std::nullopt;

    segment.flags = data[13];

    auto window_size = read_u16_be(data, length, 14);
    if(window_size.has_value()) segment.window_size = *window_size;
    else return std::nullopt;

    auto checksum = read_u16_be(data, length, 16);
    if(checksum.has_value()) segment.checksum = *checksum;
    else return std::nullopt;

    auto urgent_pointer = read_u16_be(data, length, 18);
    if(urgent_pointer.has_value()) segment.urgent_pointer = *urgent_pointer;
    else return std::nullopt;

    segment.payload_offset = segment.header_length;
    segment.payload_length = length - segment.header_length;

    return segment;
}