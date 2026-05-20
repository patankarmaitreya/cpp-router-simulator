#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>


uint16_t compute_ones_complement_checksum(const uint8_t* header, size_t header_length);

bool validate_oes_complement_checksum(const uint8_t* header, size_t header_length);

bool decrement_ttl_and_update_checksum(std::vector<uint8_t>&  packet, size_t ipv4_header_offset, size_t header_length);