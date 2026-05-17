#include<core/byte_utils.hpp>
#include <optional>

std::optional<uint16_t> read_u16_be(const std::vector<uint8_t>& buffer, size_t offset){
    if(offset > buffer.size() || buffer.size() - offset < 2) return std::nullopt;

    uint16_t high = static_cast<uint16_t>(buffer[offset]);
    uint16_t low = static_cast<uint16_t>(buffer[offset+1]);
    
    return ((high << 8) | low);    
}

std::optional<uint32_t> read_u32_be(const std::vector<uint8_t>& buffer, size_t offset){
    if(offset > buffer.size() || buffer.size() - offset < 4) return std::nullopt;

    uint32_t high = static_cast<uint32_t>(buffer[offset]);
    uint32_t midhigh = static_cast<uint32_t>(buffer[offset+1]);
    uint32_t midlow = static_cast<uint32_t>(buffer[offset+2]);
    uint32_t low = static_cast<uint32_t>(buffer[offset+3]);
    
    return ((high << 24) | (midhigh << 16) | (midlow << 8) | low);    
}

bool write_u16_be(std::vector<uint8_t>& buffer, size_t offset, uint16_t value){
    if(offset > buffer.size() || buffer.size() - offset < 2) return false; 
  
    buffer[offset] = static_cast<uint8_t>((value >> 8) & 0xFF);
    buffer[offset+1] = static_cast<uint8_t>(value & 0xFF);

    return true;
}

bool write_u32_be(std::vector<uint8_t>& buffer, size_t offset, uint32_t value){
    if(offset > buffer.size() || buffer.size() - offset < 4) return false; 
  
    buffer[offset] = static_cast<uint8_t>((value >> 24) & 0xFF);
    buffer[offset+1] = static_cast<uint8_t>((value >> 16) & 0xFF);
    buffer[offset+2] = static_cast<uint8_t>((value >> 8) & 0xFF);
    buffer[offset+3] = static_cast<uint8_t>(value & 0xFF);

    return true;
}