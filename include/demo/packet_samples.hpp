#pragma once

#include <vector>

namespace demo::samples {

    std::vector<uint8_t> valid_ipv4_frame();
    std::vector<uint8_t> valid_arp_frame();
    std::vector<uint8_t> valid_ipv4_frame_no_ethernet_header();
    std::vector<uint8_t> invalid_ipv4_frame_invalid_version();

    std::vector<uint8_t> zero_frame_size2(); 
    std::vector<uint8_t> zero_frame_size4(); 

    std::vector<uint8_t> invalid_ethernet_frame_short(); 
    std::vector<uint8_t> valid_ethernet_headeronly_frame(); 
    std::vector<uint8_t> valid_ethernet_frame(); 
}