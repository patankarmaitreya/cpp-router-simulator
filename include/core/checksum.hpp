#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>


uint16_t compute_ipv4_checksum(const uint8_t* header, size_t header_length);

bool validate_ipv4_checksum(const uint8_t* header, size_t header_length);

bool update_ipv4_checksum(std::vector<uint8_t>&  packet, size_t ipv4_header_offset, size_t header_length);