#pragma once
#include <cstdint>


namespace dp {
namespace parser {

#pragma pack(push, 1)

// LAYER 2 -> Ethernet Header
struct EthernetHeader {
    uint8_t dest_mac[6];  
    uint8_t src_mac[6];   
    uint16_t ether_type;  // (0x0800, 0x0806 etc.)
};


// ARP header (technically both layers 2 and 3)
struct ARPHeader {
    uint16_t hardware_type;       // Hardware type (1 -> Ethernet)
    uint16_t protocol_type;     // (0x0800, 0x0806 etc.)
    uint8_t hardware_len;
    uint8_t protocol_len;
    uint16_t opcode;            // Request -> 1, Reply -> 2
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];

};


// LAYER 3 -> IPv4 Header
struct IPv4Header {
    uint8_t  version_ihl;      // Version (4 bits) + IHL (4 bits)
    uint8_t  dscp_ecn;         // DSCP (6 bits) + ECN (2 bits)
    uint16_t total_length;     // Total length of packet (header + payload)
    uint16_t identification;   // Unique ID for fragmentation
    uint16_t flags_fragment;   // Flags (3 bits) + Fragment offset (13 bits)
    uint8_t  ttl;              // Time To Live
    uint8_t  protocol;         // L4 Protocol number (TCP=6, UDP=17, ICMP=1)
    uint16_t header_checksum;  
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

// LAYER 4 -> ICMP Fixed Header
struct ICMPFixedHeader {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
};

// ICMP variable headers depending on type
// type 0 or 8
struct ICMPEcho {
    uint16_t identifier;
    uint16_t sequence;
};

// type 3
struct ICMPDestUnreach {
    uint32_t data; // unused or mtu depending on code
};

// type 5
struct ICMPRedirect {
    uint32_t gateway_ip;
};

// type 12
struct ICMPParamProblem {
    uint8_t pointer;
    uint8_t unused[3];
};

#pragma pack(pop)


// Supported L4 Protocols
enum class L4Type {
    TCP,
    UDP,
    ICMP,
    UNKNOWN
};

} // namespace parser
} // namespace dp