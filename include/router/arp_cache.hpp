#pragma once

#include "protocols/ethernet.hpp"
#include "protocols/ipv4.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <unordered_map>

struct ARPEntry{
    IPv4Address ip;
    MacAddress mac;
    std::chrono::steady_clock::time_point expires_at;
};

class ARPCache{
    public:
        explicit ARPCache( std::chrono::milliseconds ttl_duration = std::chrono::milliseconds(6000));
        std::optional<ARPEntry> lookup(const IPv4Address& ip);
        void insert(const IPv4Address& ip, const MacAddress& mac);
        void remove_expired();

    private:
        std::unordered_map<uint32_t, ARPEntry> cache;
        std::chrono::milliseconds ttl_duration;
};