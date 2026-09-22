# C++ Router Simulator

A C++17 simulation of core router packet-processing behavior: parsing real network protocols and making the same forwarding decisions an actual router makes.

## Implemented

**Protocol parsing**
- Ethernet frame parsing (source/destination MAC, EtherType)
- ARP request/reply parsing and reply generation
- IPv4 header parsing, including checksum validation and recalculation
- ICMP: Echo Request/Reply, Time Exceeded, Destination Unreachable — generated as complete Ethernet+IP+ICMP frames
- TCP and UDP header parsing

**Routing & forwarding**
- ARP cache with TTL-based entry expiry
- Routing table with both linear-scan and trie-based Longest Prefix Match lookups
- Full forwarding engine: parses an incoming frame, decides local delivery vs. forward vs. drop, handles TTL expiry and unreachable destinations, resolves the next hop via ARP, rewrites Ethernet addressing, and recomputes checksums

**Tooling**
- CMake build (core / protocols / router / demo libraries)
- GoogleTest scaffold wired into CTest and GitHub Actions CI

## Roadmap

- **Validate against real captured traffic.** Currently tested against hand-built packets; next is feeding in real Wireshark/tcpdump captures to confirm the parser handles actual network traffic, not just synthetic test data.
- **Extend into the kernel with eBPF/XDP.** Reimplementing the packet-processing hot path as an XDP program for hands-on kernel-level packet processing.
- Expanding unit test coverage and adding throughput/latency benchmarks for the routing table and forwarding path.