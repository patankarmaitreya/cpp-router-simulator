#include <router/arp_cache.hpp>

ARPCache::ARPCache(std::chrono::milliseconds timeout){
    ttl_duration = timeout;
}

void ARPCache::insert(const IPv4Address& ip, const MacAddress& mac){
    ARPEntry entry{
        ip,
        mac,
    };
    entry.expires_at = std::chrono::steady_clock::now() + ttl_duration;
    
    cache[ipv4_to_uint32(ip)] = entry;
}

std::optional<ARPEntry> ARPCache::lookup(const IPv4Address& ip){
    if(cache.find(ipv4_to_uint32(ip)) == cache.end()) return std::nullopt;

    if (std::chrono::steady_clock::now() >= cache[ipv4_to_uint32(ip)].expires_at) {
        cache.erase(ipv4_to_uint32(ip));
        return std::nullopt;
    }

    return cache[ipv4_to_uint32(ip)];
}

void ARPCache::remove_expired(){
    const auto now = std::chrono::steady_clock::now();

    for (auto it = cache.begin(); it != cache.end(); ) {
        if (now >= it->second.expires_at) {
            it = cache.erase(it);
        } else {
            ++it;
        }
    }
}