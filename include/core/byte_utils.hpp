#pragma once

#include <cstdint>
#include <optional>
#include <vector>
#include <cstddef>

std::optional<uint16_t> read_u16_be(const std::vector<uint8_t>& buffer, size_t offset);

std::optional<uint16_t> read_u16_be(const uint8_t* buffer, size_t length, size_t offset);

std::optional<uint32_t> read_u32_be(const std::vector<uint8_t>& buffer, size_t offset);

std::optional<uint32_t> read_u32_be(const uint8_t* buffer, size_t length, size_t offset);

bool write_u16_be(std::vector<uint8_t>& buffer, size_t offset, uint16_t value);

bool write_u32_be(std::vector<uint8_t>& buffer, size_t offset, uint32_t value);
