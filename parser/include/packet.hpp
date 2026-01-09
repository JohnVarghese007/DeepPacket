#pragma once
#include <cstdint>

// LAYER 2 -> Ethernet Header
struct EthernetHeader {
    uint8_t dest_mac[6];  // bytes 0-5
    uint8_t src_mac[6];   // bytes 6-11
    uint16_t ether_type;  // bytes 12-13
};

// LAYER 3 -> IPv4 Header
struct IPv4Header {
    uint8_t  version_ihl;      // Version (4 bits) + IHL (4 bits)
    uint8_t  dscp_ecn;         // DSCP (6 bits) + ECN (2 bits)
    uint16_t total_length;     // Total length of packet (header + payload)
    uint16_t identification;   // Unique ID for fragmentation
    uint16_t flags_fragment;   // Flags (3 bits) + Fragment offset (13 bits)
    uint8_t  ttl;              // Time To Live
    uint8_t  protocol;         // Protocol number (TCP=6, UDP=17, ICMP=1)
    uint16_t header_checksum;  // Header checksum
    uint32_t src_addr;         // Source IP address
    uint32_t dest_addr;         // Destination IP address
};

// LAYER 4 -> TCP Header
struct TCPHeader {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset;
    uint8_t flags; 
    uint16_t window;
    uint16_t checksum;
    uint16_t urgentptr;
};

// LAYER 4 -> UDP Header
struct UDPHeader {
    uint16_t src;
    uint16_t dest;
    uint16_t length;
    uint16_t checksum;
};

// Supported L4 Protocols
enum class L4Type {
    TCP,
    UDP,
    UNKNOWN
};