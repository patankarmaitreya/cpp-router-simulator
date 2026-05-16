#include <iostream>
#include <vector>
#include <cstdint>
#include <iomanip>

void print_banner(){
    std::cout << "C++ Router Simulator" << std::endl;
    std::cout << "Build: Sprint 0" << std::endl;
}

void print_bytes(const std::vector<uint8_t>& packet, size_t start, size_t count){
    if(start > packet.size() || count > packet.size() - start){
        std::cout << "Invalid range" << std::endl;
        return;
    }
    
    for(size_t i=start; i - start < count; i++){
        std::cout << std::hex
        << std::setw(2)
        << std::setfill('0') 
        << static_cast<int>(packet[i])
        << " "; 
    }
    std::cout << std::dec << std::endl;
}

void print_packet_info(const std::vector<uint8_t>& packet){
    if(packet.size() < 14){
        std::cout << "Invalid Ethernet Frame" << std::endl;
        return;
    }

    std::cout << "Destination MAC: ";
    print_bytes(packet, 0, 6);

    std::cout << "Source MAC: ";
    print_bytes(packet, 6, 6);

    std::cout << "EtherType: ";
    print_bytes(packet, 12, 2);

    std::cout << "Payload: ";
    print_bytes(packet, 14, packet.size()-14);

}

int main(){
    print_banner();
    
    int packet_count = 0;

    std::vector<uint8_t> packet {0x00, 0x11, 0x22, 0x33,  0x44, 0x55, 0xaa, 0xbb, 0xcc,  0xdd, 0xee, 0xff, 0x08, 0x00, 0x45, 0x00, 0x00, 0x14};
    std::vector<uint8_t> short_packet {
        0x00, 0x11, 0x22
    };
    std::vector<uint8_t> header_only_packet {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x08, 0x00
    };

    std::cout << "Packet 1 Info" << std::endl;
    print_packet_info(packet);

    std::cout << "Packet 2 Info" << std::endl;
    print_packet_info(short_packet);

    std::cout << "Packet 3 Info" << std::endl;
    print_packet_info(header_only_packet);

    std::cout << "Frame size: " << packet.size() << std::endl;
    print_bytes(packet, 0, packet.size());

    print_bytes(packet, 20, 5);

    std::cout << "Packets Processed: " << packet_count << std::endl;
    return 0;
}